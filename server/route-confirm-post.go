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
	state, ok := s.states[req.StateId]
	if !ok || state == nil {
		c.Error(errors.New("State object not found or expired"))
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error": "State not found or expired"})
		return
	}
	if state.Status != StatusPending {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error": "Request already completed"})
		return
	}
	if (req.Confirm && req.Cancel) || (!req.Confirm && !req.Cancel) {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error": "One and only one of confirm and cancel must be set to true in the body"})
		return
	}

	if req.Cancel {
		s.handleCancel(c, req.StateId)
	} else if req.Confirm {
		s.handleConfirm(c, req.StateId)
	}
}

// Handle confirmation of operations
func (s *Server) handleConfirm(c *gin.Context, stateId string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	state := s.states[stateId]

	// Init the Key Vault client
	akv := keyvault.Client{}
	err := akv.Init(state.Token.AccessToken)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]string{"error": "Internal error"})
		return
	}

	// Check if we need to retrieve the key version
	if state.KeyVersion == "" {
		state.KeyVersion, err = akv.GetKeyLastVersion(state.Vault, state.KeyId)
		if err != nil {
			c.Error(err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]string{"error": "Internal error"})
			return
		}
	}

	// Make the request
	var output []byte
	keyUrl := akv.KeyUrl(state.Vault, state.KeyId, state.KeyVersion)
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

	// Store the result and mark as complete
	state.Output = output
	state.Input = nil
	state.Status = StatusComplete

	// Response
	c.Set("log-message", "Done: "+stateId)
	c.JSON(http.StatusOK, map[string]bool{"done": true})
}

// Handle cancelation of operations
func (s *Server) handleCancel(c *gin.Context, stateId string) {
	// Mark the request as canceled and remove the input and access token
	s.lock.Lock()
	state := s.states[stateId]
	state.Input = nil
	state.Status = StatusCanceled
	s.lock.Unlock()

	// Response
	c.Set("log-message", "Operation canceled: "+stateId)
	c.JSON(http.StatusOK, map[string]bool{"canceled": true})
}

type confirmRequest struct {
	StateId string `json:"state" form:"state"`
	Confirm bool   `json:"confirm" form:"confirm"`
	Cancel  bool   `json:"cancel" form:"cancel"`
}
