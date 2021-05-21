package server

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// AllowIpMiddleware is a middleware that allows requests from certain IPs only
func (s *Server) AllowIpMiddleware() (gin.HandlerFunc, error) {
	// Get the list of IPs and ranges that are allowed
	conf := viper.GetString("allowedIps")
	if conf == "" {
		// Allow all IPs, so do nothing
		return func(c *gin.Context) {}, nil
	}
	parts := strings.Split(conf, ",")
	ips := []net.IP{}
	ipRanges := []*net.IPNet{}
	for _, v := range parts {
		// Check if we have a single IP or a range
		if strings.ContainsRune(v, '/') {
			_, r, err := net.ParseCIDR(v)
			if err != nil {
				return nil, errors.New("invalid IP range: " + v)
			}
			ipRanges = append(ipRanges, r)
		} else {
			ip := net.ParseIP(v)
			if ip == nil {
				return nil, errors.New("invalid IP: " + v)
			}
			ips = append(ips, ip)
		}
	}

	// Return the middleware
	return func(c *gin.Context) {
		// Get the IP connecting
		ip, _ := c.RemoteIP()
		if ip == nil {
			c.Error(errors.New("invalid remote IP address"))
			c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]string{"error": "Internal error"})
			return
		}

		// Check if the IP is in the allowlists
		for _, e := range ips {
			if e.Equal(ip) {
				// Can continue
				return
			}
		}
		for _, e := range ipRanges {
			if e.Contains(ip) {
				// Can continue
				return
			}
		}

		// If we reach this point, the IP is not in the allow-list
		c.Error(errors.New("IP not allowed"))
		c.AbortWithStatusJSON(http.StatusForbidden, map[string]string{"error": "This client's IP is not allowed to perform this request"})
		return
	}, nil
}