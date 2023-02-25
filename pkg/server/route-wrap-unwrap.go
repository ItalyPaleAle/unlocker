package server

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/spf13/viper"

	"github.com/italypaleale/unlocker/pkg/config"
	"github.com/italypaleale/unlocker/pkg/utils"
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
		err = req.Validate()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Invalid request: "+err.Error()))
			return
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
			_ = c.Error(fmt.Errorf("failed to generate UUID: %w", err))
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
			Note:       req.Note,
		}

		// Use the lock to ensure we are not modifying s.states concurrently
		s.lock.Lock()
		s.states[stateId] = state
		s.lock.Unlock()

		s.metrics.RecordRequest(op.String(), req.Vault+"/"+req.KeyId)

		// Invoke the webhook and send a message with the URL to unlock, in background
		go func() {
			webhookErr := s.webhook.SendWebhook(&utils.WebhookRequest{
				OperationName: op.String(),
				KeyId:         req.KeyId,
				Vault:         req.Vault,
				StateId:       stateId,
				Requestor:     ip,
				Note:          req.Note,
			})
			if webhookErr != nil {
				s.log.Raw().Error().
					Err(webhookErr).
					Msg("Fatal error sending webhook")
			}
		}()

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
	Note       string `json:"note" form:"note"`
}

var noteValidate = regexp.MustCompile(`[^A-Za-z0-9 .\/_-]`)

func (req *keyRequest) Validate() error {
	if req.Vault == "" {
		return errors.New("missing parameter 'vault'")
	}
	if req.KeyId == "" {
		return errors.New("missing parameter 'keyId'")
	}
	if req.Value == "" {
		return errors.New("missing parameter 'value'")
	}
	if req.Note != "" && noteValidate.MatchString(req.Note) {
		return errors.New("parameter 'note' contains invalid characters (only `A-Za-z0-9 ._\\/-` are allowed)")
	}
	if len(req.Note) > 40 {
		return errors.New("parameter 'note' cannot be longer than 40 characters")
	}
	if req.Timeout < 1 {
		req.Timeout = viper.GetInt(config.KeyRequestTimeout)
	}
	return nil
}
