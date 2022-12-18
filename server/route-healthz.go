package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/italypaleale/unlocker/buildinfo"
)

var routeHealthzResponse []byte

type routeHealthzResponseType struct {
	Status     string `json:"status"`
	AppVersion string `json:"appVersion"`
	Build      string `json:"build"`
	Production bool   `json:"production"`
}

func init() {
	prod, _ := strconv.ParseBool(buildinfo.Production)
	routeHealthzResponse, _ = json.Marshal(routeHealthzResponseType{
		Status:     "ok",
		AppVersion: buildinfo.AppVersion,
		Build:      buildinfo.BuildDescription,
		Production: prod,
	})
}

// RouteHealthzHandler is the handler for the GET /healthz request as a http.Handler.
// It can be used to ping the server and ensure everything is working.
func (s *Server) RouteHealthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(routeHealthzResponse)
}
