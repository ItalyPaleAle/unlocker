package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type apiListResponse []requestStatePublic

// RouteApiListGet is the handler for the GET /api/list request
// This returns the list of all pending requests
func (s *Server) RouteApiListGet(c *gin.Context) {
	res := apiListResponse{}

	// Get the list of pending requests
	s.lock.Lock()
	if len(s.states) > 0 {
		res = make([]requestStatePublic, len(s.states))
		i := 0
		for stateId, state := range s.states {
			if state.Status != StatusPending || state.Processing || state.Expired() {
				continue
			}
			res[i] = state.Public(stateId)
			i++
		}
		res = res[:i]
	}
	s.lock.Unlock()

	c.JSON(http.StatusOK, res)
}
