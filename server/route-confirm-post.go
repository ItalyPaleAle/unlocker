package server

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/unlocker/keyvault"
)

// RouteConfirmPost is the handler for the POST /confirm request
// This receives the results of the confirm/reject action
func (s *Server) RouteConfirmPost(c *gin.Context) {
	// Get the fields from the body
	req := &confirmRequest{}
	err := c.Bind(req)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}
	if req.StateId == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error": "Missing state in request body"})
		return
	}

	// Get the request
	s.lock.Lock()
	state, ok := s.states[req.StateId]
	if !ok || state == nil {
		c.Error(errors.New("State object not found or expired"))
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error": "State not found or expired"})
		s.lock.Unlock()
		return
	}
	if state.Status != StatusPending {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error": "Request already completed"})
		s.lock.Unlock()
		return
	}
	if state.Processing {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error": "Request is already being processed"})
		s.lock.Unlock()
		return
	}
	if (req.Confirm && req.Cancel) || (!req.Confirm && !req.Cancel) {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error": "One and only one of confirm and cancel must be set to true in the body"})
		s.lock.Unlock()
		return
	}

	// Set processing flag
	// It's safe then to release the lock as no other goroutine can alter this request then
	state.Processing = true
	s.lock.Unlock()

	if req.Cancel {
		s.handleCancel(c, req.StateId, state)
	} else if req.Confirm {
		s.handleConfirm(c, req.StateId, state)
	}
}

// Handle confirmation of operations
func (s *Server) handleConfirm(c *gin.Context, stateId string, state *requestState) {
	// Init the Key Vault client
	akv := keyvault.Client{}
	err := akv.Init(state.Token.AccessToken)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]string{"error": "Internal error"})
		return
	}

	// Check if we need to retrieve the key version
	keyVersion := state.KeyVersion
	if keyVersion == "" {
		keyVersion, err = akv.GetKeyLastVersion(state.Vault, state.KeyId)
		if err != nil {
			c.Error(err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]string{"error": "Internal error"})
			return
		}
	}

	// Make the request
	var output []byte
	keyUrl := akv.KeyUrl(state.Vault, state.KeyId, keyVersion)
	if state.Operation == OperationWrap {
		output, err = akv.WrapKey(keyUrl, state.Input)
	} else if state.Operation == OperationUnwrap {
		output, err = akv.UnwrapKey(keyUrl, state.Input)
	}
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]string{"error": "Internal error"})
		return
	}

	// Re-acquire a lock before modifying the state object and sending a notification
	s.lock.Lock()
	defer s.lock.Unlock()

	// Store the result and mark as complete
	state.Output = output
	state.Input = nil
	state.Status = StatusComplete

	// Response
	c.Set("log-message", "Done: "+stateId)
	c.JSON(http.StatusOK, map[string]bool{"done": true})

	// Send a notification to the subscriber if any
	s.notifySubscriber(stateId, state)
}

// Handle cancellation of operations
func (s *Server) handleCancel(c *gin.Context, stateId string, state *requestState) {
	// Re-acquire a lock before modifying the state object and sending a notification
	s.lock.Lock()
	defer s.lock.Unlock()

	// Mark the request as canceled and remove the input and access token
	state.Input = nil
	state.Status = StatusCanceled

	// Response
	c.Set("log-message", "Operation canceled: "+stateId)
	c.JSON(http.StatusOK, map[string]bool{"canceled": true})

	// Send a notification to the subscriber if any
	s.notifySubscriber(stateId, state)
}

type confirmRequest struct {
	StateId string `json:"state" form:"state"`
	Confirm bool   `json:"confirm" form:"confirm"`
	Cancel  bool   `json:"cancel" form:"cancel"`
}
