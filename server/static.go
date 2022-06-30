package server

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

//go:generate ../client/build.sh
//go:generate rm -rvf static
//go:generate cp -r ../client/dist static

//go:embed static
var staticFS embed.FS

const staticBaseDir = "static"

func (s *Server) serveClient() func(c *gin.Context) {
	// Option used during development to proxy to another server (such as a dev server)
	clientProxyServer := viper.GetString("dev.clientProxyServer")

	if clientProxyServer == "" {
		return func(c *gin.Context) {
			// Only respond to GET requests
			if c.Request.Method != "GET" {
				c.AbortWithStatusJSON(http.StatusNotFound, ErrorResponse("Not found"))
				return
			}
			serveStaticFiles(c, c.Request.URL.Path, staticFS)
		}
	} else {
		u, err := url.Parse(clientProxyServer)
		if err != nil {
			panic(fmt.Sprintf("Failed to parse value for 'dev.clientProxyServer': %v", err))
		}
		proxy := proxyStaticFilesFunc(u)
		return func(c *gin.Context) {
			proxy.ServeHTTP(c.Writer, c.Request)
		}
	}
}

// Serve static files from an embedded FS
func serveStaticFiles(c *gin.Context, reqPath string, filesystem fs.FS) {
	reqPath = strings.TrimLeft(reqPath, "/")

	// Check if the static file exists
	f, err := filesystem.Open(staticBaseDir + "/" + reqPath)
	if err != nil {
		// If there's no "index.html" at the end, try appending that
		if reqPath != "index.html" && !strings.HasSuffix(reqPath, "/index.html") {
			// ...but first make sure there's a trailing slash
			if reqPath != "" && !strings.HasSuffix(reqPath, "/") {
				redirect := reqPath + "/"
				if c.Request.URL.RawQuery != "" {
					redirect += "?" + c.Request.URL.RawQuery
				}
				c.Header("location", redirect)
				c.Status(http.StatusMovedPermanently)
				return
			}
			serveStaticFiles(c, path.Join(reqPath, "index.html"), filesystem)
			return
		}
		c.AbortWithStatusJSON(http.StatusNotFound, ErrorResponse("Page not found"))
		return
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			c.AbortWithStatusJSON(http.StatusNotFound, ErrorResponse("Page not found"))
			return
		case errors.Is(err, fs.ErrPermission):
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse("Forbidden"))
			return
		default:
			c.AbortWithStatusJSON(http.StatusInternalServerError, InternalServerError)
			return
		}
	}

	// If it's a directory, load the index.html file
	if stat.IsDir() {
		// Redirect if the directory name doesn't end in a slash
		if reqPath != "" && !strings.HasSuffix(reqPath, "/") {
			redirect := reqPath + "/"
			if c.Request.URL.RawQuery != "" {
				redirect += "?" + c.Request.URL.RawQuery
			}
			c.Header("location", redirect)
			c.Status(http.StatusMovedPermanently)
			return
		}

		// Load the index.html file in the directory instead
		serveStaticFiles(c, path.Join(reqPath, "index.html"), filesystem)
		return
	}

	// File should implement io.Seeker when it's not a directory
	fseek, ok := f.(io.ReadSeekCloser)
	if !ok {
		_ = c.Error(fmt.Errorf("file %s does not implement io.ReadSeekCloser", stat.Name()))
		c.AbortWithStatusJSON(http.StatusInternalServerError, InternalServerError)
		return
	}
	http.ServeContent(c.Writer, c.Request, stat.Name(), stat.ModTime(), fseek)
}

// Returns a proxy that serves static files proxying from another server
func proxyStaticFilesFunc(upstream *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Director = func(req *http.Request) {
		req.Host = upstream.Host
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
	}
	return proxy
}
