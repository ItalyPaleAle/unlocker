package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type apiListResponse struct {
	Pending []pendingRequestItem `json:"pending"`
}

type pendingRequestItem struct {
	State     string `json:"state"`
	Operation string `json:"operation"`
	KeyId     string `json:"keyId"`
	VaultName string `json:"vaultName"`
	Requestor string `json:"requestor"`
	Date      int64  `json:"date"`
	Expiry    int64  `json:"expiry"`
}

// RouteApiListGet is the handler for the GET /api/list request
// This returns the list of all pending requests
func (s *Server) RouteApiListGet(c *gin.Context) {
	res := apiListResponse{}

	// Get the list of pending requests
	s.lock.Lock()
	if len(s.states) > 0 {
		res.Pending = make([]pendingRequestItem, len(s.states))
		i := 0
		for stateId, state := range s.states {
			if state.Status != StatusPending || state.Processing || state.Expired() {
				continue
			}
			operationName := "wrap"
			if state.Operation == OperationUnwrap {
				operationName = "unwrap"
			}
			res.Pending[i] = pendingRequestItem{
				State:     stateId,
				Operation: operationName,
				KeyId:     state.KeyId,
				VaultName: state.Vault,
				Requestor: state.Requestor,
				Date:      state.Date.Unix(),
				Expiry:    state.Expiry.Unix(),
			}
			i++
		}
		res.Pending = res.Pending[:i]
	}
	s.lock.Unlock()

	c.JSON(http.StatusOK, res)
}
