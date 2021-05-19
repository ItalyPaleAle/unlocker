package server

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// RouteResult is the handler for the GET /result/:state request
// This can be invoked by the app to periodically poll for the result
func (s *Server) RouteResult(c *gin.Context) {
	// Get the state parameter
	stateId := c.Param("state")
	if stateId == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error": "Missing parameter state"})
		return
	}

	// Check if the operation is complete
	if s.checkOperation(c, stateId) {
		// Response to the client already sent
		return
	}

	// Now, wait to see if the request is completed, or if the context is done
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-c.Request.Context().Done():
			// Client has probably disconnected at this point, but just respond with the pending message
			c.JSON(http.StatusAccepted, operationResponse{
				State:   stateId,
				Pending: true,
			})
			return
		case <-ticker.C:
			// Check if there's an update
			if s.checkOperation(c, stateId) {
				// Response to the client already sent
				return
			}
		}
	}
}

func (s *Server) checkOperation(c *gin.Context, stateId string) bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Get the state and ensure the it's valid
	// We re-check this every time in case the operation was removed in the meanwhile
	state, ok := s.states[stateId]
	if !ok || state == nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error": "State not found or expired"})
		return true
	}

	// Check if the operation is done (complete or canceled)
	if state.Status == StatusComplete {
		// Respond with the result
		c.JSON(http.StatusOK, &operationResponse{
			State: stateId,
			Done:  true,
			Value: base64.StdEncoding.EncodeToString(state.Output),
		})
		// Remove from the states map
		delete(s.states, stateId)
		return true
	} else if state.Status == StatusCanceled {
		// It's been canceled, so tell the client
		c.JSON(http.StatusConflict, &operationResponse{
			State:  stateId,
			Failed: true,
		})
		// Remove from the states map
		delete(s.states, stateId)
		return true
	}

	return false
}
