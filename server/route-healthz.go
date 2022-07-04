package server

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/unlocker/buildinfo"
)

// RouteHealthz is the handler for the GET /healthz request
// It can be used to ping the server and ensure everything is working
func (s *Server) RouteHealthz(c *gin.Context) {
	prod, _ := strconv.ParseBool(buildinfo.Production)

	c.JSON(http.StatusOK, routeHealthzResponse{
		Status:     "ok",
		AppVersion: buildinfo.AppVersion,
		Build:      fmt.Sprintf("%s, %s (%s)", buildinfo.BuildId, buildinfo.BuildDate, buildinfo.CommitHash),
		Production: prod,
	})
}

type routeHealthzResponse struct {
	Status     string `json:"status"`
	AppVersion string `json:"appVersion"`
	Build      string `json:"build"`
	Production bool   `json:"production"`
}
