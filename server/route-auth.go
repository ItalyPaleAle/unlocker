package server

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// RouteAuth is the handler for the GET /auth request
// This redirects users to the auth page on Azure
func (s *Server) RouteAuth(c *gin.Context) {
	// Get the state from the querystring
	stateId := c.Query("state")
	if stateId == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Missing parameter state"))
		return
	}
	// Ensure the state is valid
	state, ok := s.states[stateId]
	if !ok || state == nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("State not found or expired"))
		return
	}
	if state.Status != StatusPending {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Request already completed"))
		return
	}

	// Build the redirect URL
	tenantId := viper.GetString("azureTenantId")
	qs := url.Values{
		"response_type": []string{"code"},
		"client_id":     []string{viper.GetString("azureClientId")},
		"redirect_uri":  []string{viper.GetString("baseUrl") + "/confirm"},
		"response_mode": []string{"query"},
		"state":         []string{stateId},
		"scope":         []string{"https://vault.azure.net/user_impersonation"},
		"domain_hint":   []string{tenantId},
	}
	redirectUrl := "https://login.microsoftonline.com/" + tenantId + "/oauth2/v2.0/authorize?" + qs.Encode()
	c.Redirect(http.StatusTemporaryRedirect, redirectUrl)
}
