package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/gin-gonic/gin"

	"github.com/italypaleale/unlocker/pkg/keyvault"
)

// RouteApiConfirmPost is the handler for the POST /api/confirm request
// This receives the results of the confirm/reject action
func (s *Server) RouteApiConfirmPost(c *gin.Context) {
	// Get the fields from the body
	req := &confirmRequest{}
	err := c.Bind(req)
	if err != nil {
		_ = c.Error(err)
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Invalid request body"))
		return
	}
	if req.StateId == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Missing state in request body"))
		return
	}

	// Get the request
	s.lock.Lock()
	state, ok := s.states[req.StateId]
	switch {
	case !ok || state == nil:
		_ = c.Error(errors.New("state object not found or expired"))
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("State not found or expired"))
		s.lock.Unlock()
		return
	case state.Expired():
		_ = c.Error(errors.New("state object is expired"))
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("State not found or expired"))
		s.lock.Unlock()
		return
	case state.Status != StatusPending:
		_ = c.Error(errors.New("request already completed"))
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Request already completed"))
		s.lock.Unlock()
		return
	case state.Processing:
		_ = c.Error(errors.New("request is already being processed"))
		c.AbortWithStatusJSON(http.StatusConflict, ErrorResponse("Request is already being processed"))
		s.lock.Unlock()
		return
	case (req.Confirm && req.Cancel) || (!req.Confirm && !req.Cancel):
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("One and only one of confirm and cancel must be set to true in the body"))
		s.lock.Unlock()
		return
	}

	// Set processing flag
	// It's safe then to release the lock as no other goroutine can alter this request then
	state.Processing = true
	s.lock.Unlock()

	// Because the request is not pending anymore, send a notification that it has been removed
	go s.pubsub.Publish(&requestStatePublic{
		State:  req.StateId,
		Status: StatusRemoved.String(),
	})

	if req.Cancel {
		s.handleCancel(c, req.StateId, state)
	} else if req.Confirm {
		s.handleConfirm(c, req.StateId, state)
	}
}

// Handle confirmation of operations
func (s *Server) handleConfirm(c *gin.Context, stateId string, state *requestState) {
	defer func() {
		// Record the result in a deferred function to automatically catch failures
		if len(c.Errors) > 0 {
			s.metrics.RecordResult("error")
		} else {
			s.metrics.RecordResult("confirmed")
		}
	}()

	// Errors here should never happen
	var (
		at         string
		expiration time.Time
	)
	atAny, ok := c.Get(contextKeySessionAccessToken)
	if ok {
		at, ok = atAny.(string)
		if !ok {
			at = ""
		}
	}
	expirationAny, ok := c.Get(contextKeySessionExpiration)
	if ok {
		expiration, ok = expirationAny.(time.Time)
		if !ok {
			expiration = time.Time{}
		}
	}

	start := time.Now()

	// Init the Key Vault client
	akv := keyvault.NewClient(at, expiration)

	// Make the request
	var (
		output keyvault.KeyVaultResponse
		err    error
	)
	switch state.Operation {
	case OperationEncrypt:
		err = errors.New("unimplemented")
	case OperationDecrypt:
		err = errors.New("unimplemented")
	case OperationSign:
		err = errors.New("unimplemented")
	case OperationVerify:
		err = errors.New("unimplemented")
	case OperationWrapKey:
		output, err = akv.WrapKey(c.Request.Context(), state.Vault, state.KeyId, state.KeyVersion, state.AzkeysOperationParams())
	case OperationUnwrapKey:
		output, err = akv.UnwrapKey(c.Request.Context(), state.Vault, state.KeyId, state.KeyVersion, state.AzkeysOperationParams())
	default:
		err = fmt.Errorf("invalid operation %s", state.Operation)
	}
	if err != nil {
		_ = c.Error(err)
		var azErr *azcore.ResponseError
		if errors.As(err, &azErr) {
			// If the error comes from Key Vault, we need to cancel the request
			s.cancelRequest(stateId, state)
			errStr := fmt.Sprintf("Azure Key Vault returned an error: %s (%s)", azErr.ErrorCode, azErr.RawResponse.Status)
			c.AbortWithStatusJSON(http.StatusConflict, ErrorResponse(errStr))
			return
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, InternalServerError)
		return
	}

	// Record the latency
	s.metrics.RecordLatency(state.Vault, time.Since(start))

	// Re-acquire a lock before modifying the state object and sending a notification
	s.lock.Lock()
	defer s.lock.Unlock()

	// Ensure the request hasn't expired in the meanwhile
	if state.Expired() || state.Status != StatusPending {
		_ = c.Error(errors.New("state object is expired after receiving response from Key Vault"))
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("State not found or expired"))
		return
	}

	// Store the result and mark as complete
	state.Output = output
	state.Input = nil
	state.Status = StatusComplete

	// Response
	c.Set("log-message", "Operation confirmed: "+stateId)
	c.JSON(http.StatusOK, struct {
		Confirmed bool `json:"confirmed"`
	}{
		Confirmed: true,
	})

	// Send a notification to the subscriber if any
	s.notifySubscriber(stateId, state)
}

// Handle cancellation of operations
func (s *Server) handleCancel(c *gin.Context, stateId string, state *requestState) {
	s.cancelRequest(stateId, state)

	// Response
	c.Set("log-message", "Operation canceled: "+stateId)
	c.JSON(http.StatusOK, struct {
		Canceled bool `json:"canceled"`
	}{
		Canceled: true,
	})
}

// Marks a request as canceled and sends a notification to the subscribers
func (s *Server) cancelRequest(stateId string, state *requestState) {
	// Re-acquire a lock before modifying the state object and sending a notification
	s.lock.Lock()
	defer s.lock.Unlock()

	// Mark the request as canceled and remove the input
	state.Input = nil
	state.Status = StatusCanceled

	// Send a notification to the subscriber if any
	s.notifySubscriber(stateId, state)

	// Record the result
	s.metrics.RecordResult("canceled")
}

type confirmRequest struct {
	StateId string `json:"state" form:"state"`
	Confirm bool   `json:"confirm" form:"confirm"`
	Cancel  bool   `json:"cancel" form:"cancel"`
}
