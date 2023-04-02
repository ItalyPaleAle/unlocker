package server

import (
	"github.com/gin-gonic/gin"
)

// RouteApiKeywrapping is the handler for the routes that key wrapping and unwrapping operations (high-level):
// - POST /api/keywrap
// - POST /api/keyunwrap
func (s *Server) RouteApiKeywrapping(op requestOperation) gin.HandlerFunc {
	return s.createOperationRoute(op, func(req *subtleRequest) {
		// Set the algorithm to RSA-OAEP-256
		req.Algorithm = "RSA-OAEP-256"

		// Make sure there's no additional data
		req.AdditionalData = ""
	})
}
