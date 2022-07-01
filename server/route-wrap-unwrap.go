package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/spf13/viper"

	"github.com/italypaleale/unlocker/utils"
)

// RouteWrapUnwrap is the handler for the POST /wrap and /unwrap request
func (s *Server) RouteWrapUnwrap(op requestOperation) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the fields from the body
		req := &keyRequest{}
		err := c.Bind(req)
		if err != nil {
			_ = c.Error(err)
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
			req.Timeout = viper.GetInt("requestTimeout")
		}
		val, err := utils.DecodeBase64String(req.Value)
		if err != nil {
			_ = c.Error(err)
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
			_ = c.Error(err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, InternalServerError)
			return
		}
		stateId := stateUuid.String()
		now := time.Now()
		ip := c.ClientIP()
		validity := time.Duration(req.Timeout) * time.Second
		state := &requestState{
			Operation:  op,
			Input:      val,
			Vault:      req.Vault,
			KeyId:      req.KeyId,
			KeyVersion: req.KeyVersion,
			Requestor:  ip,
			Date:       now,
			Expiry:     now.Add(validity),
		}
		s.states[stateId] = state

		// Invoke the webhook and send a message with the URL to unlock
		err = s.webhook.SendWebhook(&utils.WebhookRequest{
			OperationName: op.String(),
			KeyId:         req.KeyId,
			Vault:         req.Vault,
			StateId:       stateId,
			Requestor:     ip,
		})
		if err != nil {
			_ = c.Error(err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, ErrorResponse("Error sending webhook"))
			return
		}

		// Make the request expire in background
		go s.expireRequest(stateId, validity)

		// Respond with the state ID
		c.JSON(http.StatusAccepted, operationResponse{
			State:   stateId,
			Pending: true,
		})

		// Send a notification to all subscribers, in background
		pub := state.Public(stateId)
		go s.pubsub.Publish(&pub)
	}
}

type keyRequest struct {
	Value      string `json:"value" form:"value"`
	Vault      string `json:"vault" form:"vault"`
	KeyId      string `json:"keyId" form:"keyId"`
	KeyVersion string `json:"keyVersion" form:"keyVersion"`
	Timeout    int    `json:"timeout" form:"timeout"`
}
