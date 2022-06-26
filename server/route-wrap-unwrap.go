package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/italypaleale/unlocker/utils"
)

// Default timeout, in seconds
const DefaultRequestTimeout = 300

// RouteWrapUnwrap is the handler for the POST /wrap and /unwrap request
func (s *Server) RouteWrapUnwrap(op requestOperation) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the fields from the body
		req := &keyRequest{}
		err := c.Bind(req)
		if err != nil {
			c.Error(err)
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Invalid request body"))
			return
		}
		if req.Vault == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Missing parameter vault"))
			return
		}
		if req.KeyId == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Missing parameter keyId"))
			return
		}
		if req.Value == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Missing parameter value"))
			return
		}
		if req.Timeout < 1 {
			req.Timeout = DefaultRequestTimeout
		}
		val, err := utils.DecodeBase64String(req.Value)
		if err != nil {
			c.Error(err)
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Invalid value format"))
			return
		}

		// If we don't have the key version, or if it's "latest", we'll leave this empty and later we'll retrieve the latest version
		if strings.ToLower(req.KeyVersion) == "latest" {
			req.KeyVersion = ""
		}

		// Start the request process
		// First, store the request in the states map
		stateUuid, err := uuid.NewRandom()
		if err != nil {
			c.Error(err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, InternalServerError)
			return
		}
		stateId := stateUuid.String()
		now := time.Now()
		ip := c.ClientIP()
		s.states[stateId] = &requestState{
			Operation:  op,
			Input:      val,
			Vault:      req.Vault,
			KeyId:      req.KeyId,
			KeyVersion: req.KeyVersion,
			Requestor:  ip,
			Date:       now,
			Expiry:     now.Add(time.Duration(req.Timeout) * time.Second),
		}

		// Invoke the webhook and send a message with the URL to unlock
		opName := "wrap"
		if op == OperationUnwrap {
			opName = "unwrap"
		}
		err = s.webhook.SendWebhook(&utils.WebhookRequest{
			OperationName: opName,
			KeyId:         req.KeyId,
			Vault:         req.Vault,
			StateId:       stateId,
			Requestor:     ip,
		})
		if err != nil {
			c.Error(err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, ErrorResponse("Error sending webhook"))
			return
		}

		// Respond with the state ID
		c.JSON(http.StatusAccepted, operationResponse{
			State:   stateId,
			Pending: true,
		})
	}
}

type keyRequest struct {
	Value      string `json:"value" form:"value"`
	Vault      string `json:"vault" form:"vault"`
	KeyId      string `json:"keyId" form:"keyId"`
	KeyVersion string `json:"keyVersion" form:"keyVersion"`
	Timeout    int    `json:"timeout" form:"timeout"`
}
