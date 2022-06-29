package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AccessTokenMiddleware is a middleware that requires the user to be authenticated and present a cookie with the access token for Azure Key Vault
// This injects the token in the request's context if it exists and it's valid
// If required is true, the request fails if the token is not present
func (s *Server) AccessTokenMiddleware(required bool) func(c *gin.Context) {
	return func(c *gin.Context) {
		// Get the cookie and parse it
		at, err := getSecureCookie(c, atCookieName)
		if err != nil || at == "" {
			if required {
				c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse("User is not authenticated or there's no access token in the cookies"))
			}
			return
		}

		c.Set("accessToken", at)
	}
}
