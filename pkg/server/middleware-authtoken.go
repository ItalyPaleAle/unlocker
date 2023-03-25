package server

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

const headerSessionTTL = "x-session-ttl"
const contextKeySessionAccessToken = "sessionAccessToken"
const contextKeySessionExpiration = "sessionExpiration"

// AccessTokenMiddleware is a middleware that requires the user to be authenticated and present a cookie with the access token for Azure Key Vault
// This injects the token in the request's context if it exists and it's valid
// If required is true, the request fails if the token is not present
func (s *Server) AccessTokenMiddleware(required bool) func(c *gin.Context) {
	return func(c *gin.Context) {
		// Get the cookie and parse it
		at, ttl, err := getSecureCookie(c, atCookieName)
		if err != nil || at == "" {
			if err != nil {
				_ = c.Error(fmt.Errorf("cookie error: %v", err))
			}
			if required {
				c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse("User is not authenticated or there's no access token in the cookies"))
			}
			return
		}

		// Set the TTL in the header
		c.Header(headerSessionTTL, strconv.Itoa(int(ttl.Seconds())))

		// Set the values in the context
		c.Set(contextKeySessionAccessToken, at)
		c.Set(contextKeySessionExpiration, time.Now().Add(ttl))
	}
}
