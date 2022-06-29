package server

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:generate ../client/build.sh
//go:generate rm -rvf static
//go:generate cp -r ../client/dist static

//go:embed static
var staticFS embed.FS

const staticBaseDir = "static"

func (s *Server) serveClient(c *gin.Context) {
	// Only respond to GET requests
	if c.Request.Method != "GET" {
		c.AbortWithStatusJSON(http.StatusNotFound, ErrorResponse("Not found"))
		return
	}

	serveStaticFile(c, c.Request.URL.Path, staticFS)
}

func serveStaticFile(c *gin.Context, reqPath string, filesystem fs.FS) {
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
			serveStaticFile(c, path.Join(reqPath, "index.html"), filesystem)
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
		serveStaticFile(c, path.Join(reqPath, "index.html"), filesystem)
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
