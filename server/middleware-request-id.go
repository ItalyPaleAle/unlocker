package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequestIdMiddleware is a middleware that generates a unique request ID for each request
func (s *Server) RequestIdMiddleware(c *gin.Context) {
	// Generate a new UUID
	reqUuid, err := uuid.NewRandom()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	c.Set("request-id", reqUuid.String())
}
