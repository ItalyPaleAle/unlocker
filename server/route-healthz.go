package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RouteHealthz is the handler for the GET /healthz request
// It can be used to ping the server and ensure everything is working
func (s *Server) RouteHealthz(c *gin.Context) {
	c.JSON(http.StatusOK, routeHealthzResponse{
		Status: "ok",
	})
}

type routeHealthzResponse struct {
	Status string
}
