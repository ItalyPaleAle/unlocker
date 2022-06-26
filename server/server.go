package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
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

// Interval to run garbage collection to remove expired requests
const cleanupInterval = 30 * time.Second

// Server is the server based on Gin
type Server struct {
	ctx        context.Context
	router     *gin.Engine
	httpClient *http.Client
	log        *utils.AppLogger
	states     map[string]*requestState
	lock       *sync.Mutex
	webhook    *utils.Webhook
	// Subscriptions to watch for state changes
	// Each state can only have one subscription
	// If another call tries to subscribe to the same state, it will evict the first call
	subs map[string]chan *requestState
}

// Init the Server object and create a Gin server
func (s *Server) Init(log *utils.AppLogger) error {
	s.log = log
	s.states = map[string]*requestState{}
	s.lock = &sync.Mutex{}
	s.subs = map[string]chan *requestState{}

	// Set Gin to Release mode
	gin.SetMode(gin.ReleaseMode)

	// Init the webhook
	s.webhook = &utils.Webhook{}
	s.webhook.Init()

	// Init a HTTP client
	s.httpClient = &http.Client{
		Timeout: 15 * time.Second,
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
	if originsStr == "" {
		// Default is baseUrl
		originsStr = viper.GetString("baseUrl")
	}
	if originsStr == "*" {
		corsConfig.AllowAllOrigins = true
	} else {
		corsConfig.AllowAllOrigins = false
		corsConfig.AllowOrigins = strings.Split(originsStr, ",")
	}
	s.router.Use(cors.New(corsConfig))

	// Logger middleware that removes the auth code from the URL
	codeFilterLogMw := s.log.LoggerMaskMiddleware(regexp.MustCompile("(\\?|&)(code=)([^&]*)"), "$1$2***")

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
	s.router.GET("/confirm", codeFilterLogMw, s.RouteConfirmGet)
	s.router.POST("/confirm", s.RouteConfirmPost)

	// Start the background worker that cleans up all states
	s.statesCleanup()

	return nil
}

// Start the web server
// Note this function is blocking, and will return only when the servers are shut down (via context cancelation or via SIGINT/SIGTERM signals)
func (s *Server) Start(ctx context.Context) error {
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
	return s.launchServer(bindAddr, bindPort)
}

// Start the server
func (s *Server) launchServer(bindAddr string, bindPort int) error {
	// HTTPS server
	tlsCert, err := s.loadTLSCert()
	if err != nil {
		return err
	}
	httpSrv := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", bindAddr, bindPort),
		Handler:        s.router,
		MaxHeaderBytes: 1 << 20,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: tlsCert,
		},
	}

	// Start the HTTPS server in a background goroutine
	go func() {
		s.log.Raw().Info().
			Str("bind", bindAddr).
			Int("port", bindPort).
			Str("url", viper.GetString("baseUrl")).
			Msg("HTTPS server started")
		// Next call blocks until the server is shut down
		err := httpSrv.ListenAndServeTLS("", "")
		if err != http.ErrServerClosed {
			s.log.Raw().Panic().Msgf("Error starting server: %v", err)
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
	err = httpSrv.Shutdown(shutdownCtx)
	shutdownCancel()
	// Log the errors (could be context canceled)
	if err != nil {
		s.log.Raw().Warn().
			AnErr("error", err).
			Msg("HTTP server shutdown error")
	}

	return nil
}

// Adds a subscription to a state by key
// If another subscription to the same key exists, evicts that first
// Important: invocations must be wrapped in s.lock being locked
func (s *Server) subscribeToState(stateId string) chan *requestState {
	ch, ok := s.subs[stateId]
	if ok && ch != nil {
		// Close the previous subscription
		close(ch)
	}

	// Create a new subscription
	ch = make(chan *requestState)
	s.subs[stateId] = ch
	return ch
}

// Sends a notification to a state subscriber, if any
// The channel is then closed right after
// Important: invocations must be wrapped in s.lock being locked
func (s *Server) notifySubscriber(stateId string, state *requestState) {
	ch, ok := s.subs[stateId]
	if !ok || ch == nil {
		return
	}

	// Send the notification
	ch <- state

	// Close the channel and remove it from the subscribers
	close(ch)
	delete(s.subs, stateId)
}

// Starts a goroutine that periodically removes expired states
func (s *Server) statesCleanup() {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
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
			// Iterate through subscriptions to find those that are for expired states
			for k, v := range s.subs {
				_, ok := s.states[k]
				if ok {
					continue
				}
				if v != nil {
					close(v)
				}
				delete(s.subs, k)
			}
			s.lock.Unlock()
		}
	}()
}

// Loads the TLS certificate specified in the config file
func (s *Server) loadTLSCert() ([]tls.Certificate, error) {
	tlsCert := viper.GetString("tlsCert")
	tlsKey := viper.GetString("tlsKey")

	// Check if the values from the config file are PEM-encoded certificates directly
	obj, err := tls.X509KeyPair([]byte(tlsCert), []byte(tlsKey))
	if err == nil {
		return []tls.Certificate{obj}, nil
	}

	// Try loading from file
	obj, err = tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return nil, err
	}
	return []tls.Certificate{obj}, nil
}

type requestOperation uint8

const (
	OperationWrap requestOperation = iota
	OperationUnwrap
)

type requestStatus uint8

const (
	StatusPending requestStatus = iota
	StatusComplete
	StatusCanceled
)

type requestState struct {
	Status     requestStatus
	Operation  requestOperation
	Processing bool
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
