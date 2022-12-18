package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"

	"github.com/italypaleale/unlocker/utils"
)

// Server is the server based on Gin
type Server struct {
	ctx        context.Context
	router     *gin.Engine
	httpClient *http.Client
	log        *utils.AppLogger
	states     map[string]*requestState
	lock       *sync.RWMutex
	webhook    *utils.Webhook
	// Subscribers that receive public events
	pubsub *utils.Broker[*requestStatePublic]
	// Subscriptions to watch for state changes
	// Each state can only have one subscription
	// If another call tries to subscribe to the same state, it will evict the first call
	subs map[string]chan *requestState
}

// Init the Server object and create a Gin server
func (s *Server) Init(log *utils.AppLogger) error {
	s.log = log
	s.states = map[string]*requestState{}
	s.lock = &sync.RWMutex{}
	s.subs = map[string]chan *requestState{}
	s.pubsub = utils.NewBroker[*requestStatePublic]()

	// Set Gin to Release mode
	gin.SetMode(gin.ReleaseMode)

	// Init the webhook
	s.webhook = &utils.Webhook{}
	s.webhook.Init(log)

	// Init a HTTP client
	s.httpClient = &http.Client{
		Timeout: 15 * time.Second,
	}

	err := s.initAppServer()
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) initAppServer() error {
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
	codeFilterLogMw := s.log.LoggerMaskMiddleware(regexp.MustCompile(`(\?|&)(code=)([^&]*)`), "$1$2***")

	// Middleware to allow certain IPs
	allowIpMw, err := s.AllowIpMiddleware()
	if err != nil {
		return err
	}

	// Add routes
	s.router.GET("/healthz", gin.WrapF(s.RouteHealthzHandler))
	s.router.POST("/wrap", allowIpMw, s.RouteWrapUnwrap(OperationWrap))
	s.router.POST("/unwrap", allowIpMw, s.RouteWrapUnwrap(OperationUnwrap))
	s.router.GET("/result/:state", allowIpMw, s.RouteResult)
	s.router.GET("/auth", s.RouteAuth)
	s.router.GET("/auth/confirm", codeFilterLogMw, s.RouteAuthConfirm)
	s.router.GET("/api/list", s.AccessTokenMiddleware(true), s.RouteApiListGet)
	s.router.POST("/api/confirm", s.AccessTokenMiddleware(true), s.RouteApiConfirmPost)

	// Static files as fallback
	s.router.NoRoute(s.serveClient())

	return nil
}

// Start the web server
// Note this function is blocking, and will return only when the servers are shut down (via context cancellation or via SIGINT/SIGTERM signals)
func (s *Server) Start(ctx context.Context) error {
	s.ctx = ctx

	// App server
	appBindAddr := viper.GetString("bind")
	if appBindAddr == "" {
		appBindAddr = "0.0.0.0"
	}
	appBindPort := viper.GetInt("port")
	if appBindPort == 0 {
		appBindPort = 8080
	}
	appSrv, err := s.startAppServer(appBindAddr, appBindPort)
	if err != nil {
		return err
	}

	// Metrics server
	var metricsSrv *http.Server
	if viper.GetBool("enableMetrics") {
		metricsBindAddr := viper.GetString("metricsBind")
		if metricsBindAddr == "" {
			metricsBindAddr = "0.0.0.0"
		}
		metricsBindPort := viper.GetInt("metricsPort")
		if metricsBindPort == 0 {
			metricsBindPort = 9000
		}
		metricsSrv, err = s.startMetricsServer(metricsBindAddr, metricsBindPort)
		if err != nil {
			return err
		}
	}

	// Listen to SIGINT and SIGTERM signals
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	// Block until we either get a termination signal, or until the context is canceled
	select {
	case <-s.ctx.Done():
	case <-ch:
	}

	// We received an interrupt signal, shut down the server
	s.pubsub.Shutdown()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = appSrv.Shutdown(shutdownCtx)
	shutdownCancel()
	if err != nil {
		// Log the error only (could be context canceled)
		s.log.Raw().Warn().
			AnErr("error", err).
			Msg("App server shutdown error")
	}

	shutdownCtx, shutdownCancel = context.WithTimeout(context.Background(), time.Second)
	err = metricsSrv.Shutdown(shutdownCtx)
	shutdownCancel()
	if err != nil {
		// Log the error only (could be context canceled)
		s.log.Raw().Warn().
			AnErr("error", err).
			Msg("Metrics server shutdown error")
	}

	return nil
}

func (s *Server) startAppServer(bindAddr string, bindPort int) (*http.Server, error) {
	// Create the HTTPS server
	tlsCert, err := s.loadTLSCert()
	if err != nil {
		return nil, err
	}
	httpSrv := &http.Server{
		Addr:              net.JoinHostPort(bindAddr, strconv.Itoa(bindPort)),
		Handler:           s.router,
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
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
			Msg("App server started")
		// Next call blocks until the server is shut down
		err := httpSrv.ListenAndServeTLS("", "")
		if err != http.ErrServerClosed {
			s.log.Raw().Panic().Msgf("Error starting app server: %v", err)
		}
	}()

	return httpSrv, nil
}

func (s *Server) startMetricsServer(bindAddr string, bindPort int) (*http.Server, error) {
	// Handler
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.RouteHealthzHandler)
	mux.Handle("/metrics", promhttp.Handler())

	// Create the HTTP server
	httpSrv := &http.Server{
		Addr:              net.JoinHostPort(bindAddr, strconv.Itoa(bindPort)),
		Handler:           mux,
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start the HTTPS server in a background goroutine
	go func() {
		s.log.Raw().Info().
			Int("port", bindPort).
			Msg("Metrics server started")
		// Next call blocks until the server is shut down
		err := httpSrv.ListenAndServe()
		if err != http.ErrServerClosed {
			s.log.Raw().Panic().Msgf("Error starting metrics server: %v", err)
		}
	}()

	return httpSrv, nil
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

// This method makes a pending request expire after the given time interval
// It should be invoked in a background goroutine
func (s *Server) expireRequest(stateId string, validity time.Duration) {
	// Wait until the request is expired
	time.Sleep(validity)

	// Acquire a lock to ensure consistency
	s.lock.Lock()
	defer s.lock.Unlock()

	// Check if the request still exists
	req, ok := s.states[stateId]
	if !ok || req == nil {
		return
	}
	s.log.Raw().Info().Msg("Removing expired operation " + stateId)

	// Set the request as canceled
	req.Status = StatusCanceled

	// If there's a subscription, send a notification
	ch, ok := s.subs[stateId]
	if ok {
		if ch != nil {
			ch <- req
			close(ch)
		}
		delete(s.subs, stateId)
	}

	// Delete the state object
	delete(s.states, stateId)

	// Publish a message that the request has been removed
	go s.pubsub.Publish(&requestStatePublic{
		State:  stateId,
		Status: StatusRemoved.String(),
	})
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

type operationResponse struct {
	State   string `json:"state"`
	Pending bool   `json:"pending,omitempty"`
	Done    bool   `json:"done,omitempty"`
	Failed  bool   `json:"failed,omitempty"`
	Value   string `json:"value,omitempty"`
}
