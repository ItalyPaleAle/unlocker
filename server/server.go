package server

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "embed"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	"github.com/italypaleale/unlocker/utils"
)

//go:embed confirm-page.html
var confirmPage string

// Server is the server based on Gin
type Server struct {
	ctx        context.Context
	router     *gin.Engine
	httpClient *http.Client
	log        *utils.AppLogger
	states     map[string]*requestState
	lock       *sync.Mutex
}

// Init the Server object and create a Gin server
func (s *Server) Init(log *utils.AppLogger) error {
	s.log = log
	s.states = map[string]*requestState{}
	s.lock = &sync.Mutex{}

	// Set Gin to Release mode
	gin.SetMode(gin.ReleaseMode)

	// Init a HTTP client
	s.httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}

	// Create the Gin router and add various middlewares
	s.router = gin.New()
	s.router.Use(gin.Recovery())
	s.router.Use(s.RequestIdMiddleware)
	s.router.Use(s.log.LoggerMiddleware)

	// CORS configuration
	corsConfig := cors.Config{
		AllowMethods: []string{"GET", "POST", "HEAD"},
		AllowHeaders: []string{
			"Authorization",
			"Origin",
			"Content-Length",
			"Content-Type",
			"X-System-Creds",
			"X-System-Code",
		},
		ExposeHeaders: []string{
			"Retry-After",
			"Content-Type",
		},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}

	// Check if we are restricting the origins for CORS
	originsStr := viper.GetString("origins")
	if originsStr != "" {
		corsConfig.AllowAllOrigins = false
		corsConfig.AllowOrigins = strings.Split(originsStr, ",")
	} else {
		corsConfig.AllowAllOrigins = true
	}
	s.router.Use(cors.New(corsConfig))

	// Regexp that removes the auth code from the URL
	codeFilterExp := regexp.MustCompile("(\\?|&)(code=)([^&]*)")

	// HTML template for the confirmation page
	confirmPageTpl, err := template.New("confirm-page").Parse(confirmPage)
	if err != nil {
		return err
	}
	s.router.SetHTMLTemplate(confirmPageTpl)

	// Middleware to allow certain IPs
	allowIpMw, err := s.AllowIpMiddleware()
	if err != nil {
		return err
	}

	// Add routes
	s.router.POST("/wrap", allowIpMw, s.RouteWrapUnwrap(OperationWrap))
	s.router.POST("/unwrap", allowIpMw, s.RouteWrapUnwrap(OperationUnwrap))
	s.router.GET("/result/:state", allowIpMw, s.RouteResult)
	s.router.GET("/auth", s.RouteAuth)
	s.router.GET("/confirm", s.log.LoggerMaskMiddleware(codeFilterExp, "$1$2***"), s.RouteConfirmGet)
	s.router.POST("/confirm", s.RouteConfirmPost)

	// Start the background worker that cleans up all states
	s.statesCleanup()

	return nil
}

// Start the web server
// Note this function is blocking, and will return only when the servers are shut down (via context cancelation or via SIGINT/SIGTERM signals)
func (s *Server) Start(ctx context.Context) {
	s.ctx = ctx

	// Get address and port to bind to (fallback to default)
	bindAddr := viper.GetString("bind")
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	bindPort := viper.GetInt("port")
	if bindPort == 0 {
		bindPort = 8080
	}

	// Launch the server (this is a blocking call)
	s.launchServer(bindAddr, bindPort)
}

// Start the server
func (s *Server) launchServer(bindAddr string, bindPort int) {
	// HTTP server (no TLS)
	httpSrv := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", bindAddr, bindPort),
		Handler:        s.router,
		MaxHeaderBytes: 1 << 20,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
	}

	// Start the HTTP server in a background goroutine
	go func() {
		fmt.Printf("HTTP server listening on http://%s:%d\n", bindAddr, bindPort)
		// Next call blocks until the server is shut down
		err := httpSrv.ListenAndServe()
		if err != http.ErrServerClosed {
			panic(err)
		}
	}()

	// Listen to SIGINT and SIGTERM signals
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	// Block until we either get a termination signal, or until the context is canceled
	select {
	case <-s.ctx.Done():
	case <-ch:
	}

	// We received an interrupt signal, shut down the server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := httpSrv.Shutdown(shutdownCtx)
	shutdownCancel()
	// Log the errors (could be context canceled)
	if err != nil {
		log.Println("HTTP server shutdown error:", err)
	}
}

// Starts a goroutine that periodically removes expired states
func (s *Server) statesCleanup() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		for range ticker.C {
			// Iterate through states and look for expired ones
			s.lock.Lock()
			now := time.Now()
			for k, v := range s.states {
				if v.Expiry.Before(now) {
					s.log.Raw().Info().Msg("Removed expired operation " + k)
					delete(s.states, k)
				}
			}
			s.lock.Unlock()
		}
	}()
}

const (
	OperationWrap = iota
	OperationUnwrap
)

const (
	StatusPending = iota
	StatusComplete
	StatusCanceled
)

type requestState struct {
	Status     int
	Operation  int
	Input      []byte
	Output     []byte
	Vault      string
	KeyId      string
	KeyVersion string
	Requestor  string
	Date       time.Time
	Expiry     time.Time
	Token      *AccessToken
}

type operationResponse struct {
	State   string `json:"state"`
	Pending bool   `json:"pending,omitempty"`
	Done    bool   `json:"done,omitempty"`
	Failed  bool   `json:"failed,omitempty"`
	Value   string `json:"value,omitempty"`
}
