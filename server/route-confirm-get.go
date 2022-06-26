package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// AccessToken contains the details of the access token
type AccessToken struct {
	TokenType        string `json:"token_type"`
	Resource         string `json:"resource"`
	Scope            string `json:"scope"`
	ExpiresIn        int    `json:"expires_in"`
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// RouteConfirmGet is the handler for the GET /confirm request
// This exchanges an authorization code for an access token
// then shows the page where the user can confirm the operation
func (s *Server) RouteConfirmGet(c *gin.Context) {
	// Ensure we have the required params in the querystring
	code := c.Query("code")
	if code == "" {
		_ = c.Error(errors.New("Missing parameter code in the request"))
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Invalid request"))
		return
	}
	stateId := c.Query("state")
	if stateId == "" {
		_ = c.Error(errors.New("Parameter state is missing in the request"))
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Invalid request"))
		return
	}

	// Get the state object
	state, ok := s.states[stateId]
	if !ok || state == nil {
		_ = c.Error(errors.New("State object not found or expired"))
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("State not found or expired"))
		return
	}
	if state.Status != StatusPending {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Request already completed"))
		return
	}

	// Exchange the code for an access token
	token, err := s.requestAccessToken(code)
	if err != nil {
		_ = c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, ErrorResponse("Error obtaining access token"))
		return
	}
	state.Token = token

	// Respond by rendering the web page
	operationName := "wrap"
	if state.Operation == OperationUnwrap {
		operationName = "unwrap"
	}
	c.HTML(http.StatusOK, "confirm-page", struct {
		State     string
		Operation string
		KeyId     string
		VaultName string
		Requestor string
		Date      string
	}{
		State:     stateId,
		Operation: operationName,
		KeyId:     state.KeyId,
		VaultName: state.Vault,
		Requestor: state.Requestor,
		Date:      state.Date.Format(time.RFC1123),
	})
}

func (s *Server) requestAccessToken(code string) (*AccessToken, error) {
	// Build the request
	data := url.Values{
		"code":          []string{code},
		"client_id":     []string{viper.GetString("azureClientId")},
		"client_secret": []string{viper.GetString("azureClientSecret")},
		"redirect_uri":  []string{viper.GetString("baseUrl") + "/confirm"},
		"scope":         []string{"https://vault.azure.net/user_impersonation"},
		"grant_type":    []string{"authorization_code"},
	}
	body := strings.NewReader(data.Encode())

	req, err := http.NewRequest("POST", "https://login.microsoftonline.com/"+viper.GetString("azureTenantId")+"/oauth2/v2.0/token", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	// Parse the response as JSON
	token := &AccessToken{}
	err = json.NewDecoder(res.Body).Decode(&token)
	if err != nil {
		return nil, err
	}
	if token.Error != "" {
		return nil, errors.New("error in token (" + token.Error + "): " + token.ErrorDescription)
	}
	if token.TokenType != "Bearer" {
		return nil, errors.New("invalid token type: " + token.TokenType)
	}
	if token.Scope == "" {
		return nil, errors.New("empty scope in token")
	}
	if token.AccessToken == "" {
		return nil, errors.New("empty access_token in token")
	}

	return token, nil
}
