package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"

	"github.com/italypaleale/unlocker/pkg/config"
	"github.com/italypaleale/unlocker/pkg/metrics"
	"github.com/italypaleale/unlocker/pkg/utils"
)

// Server is the server based on Gin
type Server struct {
	appRouter  *gin.Engine
	httpClient *http.Client
	log        *utils.AppLogger
	states     map[string]*requestState
	lock       *sync.RWMutex
	webhook    *utils.Webhook
	metrics    metrics.UnlockerMetrics
	// Subscribers that receive public events
	pubsub *utils.Broker[*requestStatePublic]
	// Subscriptions to watch for state changes
	// Each state can only have one subscription
	// If another call tries to subscribe to the same state, it will evict the first call
	subs map[string]chan *requestState
	// Servers
	appSrv     *http.Server
	metricsSrv *http.Server
	// Method that forces a reload of TLS certificates from disk
	tlsCertWatchFn tlsCertWatchFn
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

	// Init the Prometheus metrics
	s.metrics.Init()

	// Init the app server
	err := s.initAppServer()
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) initAppServer() error {
	// Create the Gin router and add various middlewares
	s.appRouter = gin.New()
	s.appRouter.Use(gin.Recovery())
	s.appRouter.Use(s.RequestIdMiddleware)
	s.appRouter.Use(s.log.LoggerMiddleware)

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
	originsStr := viper.GetString(config.KeyOrigins)
	if originsStr == "" {
		// Default is baseUrl
		originsStr = viper.GetString(config.KeyBaseUrl)
	}
	if originsStr == "*" {
		corsConfig.AllowAllOrigins = true
	} else {
		corsConfig.AllowAllOrigins = false
		corsConfig.AllowOrigins = strings.Split(originsStr, ",")
	}
	s.appRouter.Use(cors.New(corsConfig))

	// Logger middleware that removes the auth code from the URL
	codeFilterLogMw := s.log.LoggerMaskMiddleware(regexp.MustCompile(`(\?|&)(code|state|session_state)=([^&]*)`), "$1$2***")

	// Middleware to allow certain IPs
	allowIpMw, err := s.AllowIpMiddleware()
	if err != nil {
		return err
	}

	// Add routes
	s.appRouter.GET("/healthz", gin.WrapF(s.RouteHealthzHandler))
	s.appRouter.GET("/api/result/:state", allowIpMw, s.RouteApiResult)
	s.appRouter.POST("/api/subtle/encrypt", allowIpMw, s.RouteApiSubtle(OperationEncrypt))
	s.appRouter.POST("/api/subtle/decrypt", allowIpMw, s.RouteApiSubtle(OperationDecrypt))
	s.appRouter.POST("/api/subtle/sign", allowIpMw, s.RouteApiSubtle(OperationSign))
	s.appRouter.POST("/api/subtle/verify", allowIpMw, s.RouteApiSubtle(OperationVerify))
	s.appRouter.POST("/api/subtle/wrap", allowIpMw, s.RouteApiSubtle(OperationWrap))
	s.appRouter.POST("/api/subtle/unwrap", allowIpMw, s.RouteApiSubtle(OperationUnwrap))
	s.appRouter.POST("/api/keywrap", allowIpMw, s.RouteApiKeywrapping(OperationWrap))
	s.appRouter.POST("/api/keyunwrap", allowIpMw, s.RouteApiKeywrapping(OperationUnwrap))
	s.appRouter.GET("/auth", s.RouteAuth)
	s.appRouter.GET("/auth/confirm", codeFilterLogMw, s.RouteAuthConfirm)
	s.appRouter.GET("/client/list", s.AccessTokenMiddleware(true), s.RouteClientListGet)
	s.appRouter.POST("/client/confirm", s.AccessTokenMiddleware(true), s.RouteClientConfirmPost)

	// Static files as fallback
	s.appRouter.NoRoute(s.serveClient())

	return nil
}

// Start the web server
// Note this function is blocking, and will return only when the servers are shut down via context cancellation.
func (s *Server) Start(ctx context.Context) error {
	// App server
	err := s.startAppServer()
	if err != nil {
		return err
	}
	//nolint:errcheck
	defer s.stopAppServer()
	defer s.pubsub.Shutdown()

	// Metrics server
	if viper.GetBool(config.KeyEnableMetrics) {
		err = s.startMetricsServer()
		if err != nil {
			return err
		}
	}
	//nolint:errcheck
	defer s.stopMetricsServer()

	// If we have a tlsCertWatchFn, invoke that
	if s.tlsCertWatchFn != nil {
		err = s.tlsCertWatchFn(ctx, s.log.Raw())
		if err != nil {
			return fmt.Errorf("failed to watch for TLS certificates: %w", err)
		}
	}

	// Block until the context is canceled
	<-ctx.Done()

	// Servers are stopped with deferred calls
	return nil
}

func (s *Server) startAppServer() error {
	bindAddr := viper.GetString(config.KeyBind)
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}
	bindPort := viper.GetInt(config.KeyPort)
	if bindPort < 1 {
		bindPort = 8080
	}

	// Create the HTTPS server
	tlsConfig, tlsCertReloadFn, err := s.loadTLSConfig()
	if err != nil {
		return err
	}
	s.appSrv = &http.Server{
		Addr:              net.JoinHostPort(bindAddr, strconv.Itoa(bindPort)),
		Handler:           s.appRouter,
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConfig,
	}
	s.tlsCertWatchFn = tlsCertReloadFn

	// Start the HTTPS server in a background goroutine
	go func() {
		s.log.Raw().Info().
			Str("bind", bindAddr).
			Int("port", bindPort).
			Str("url", viper.GetString(config.KeyBaseUrl)).
			Msg("App server started")
		// Next call blocks until the server is shut down
		err := s.appSrv.ListenAndServeTLS("", "")
		if err != http.ErrServerClosed {
			s.log.Raw().Fatal().Msgf("Error starting app server: %v", err)
		}
	}()

	return nil
}

func (s *Server) stopAppServer() error {
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := s.appSrv.Shutdown(shutdownCtx)
	shutdownCancel()
	if err != nil {
		// Log the error only (could be context canceled)
		s.log.Raw().Warn().
			AnErr("error", err).
			Msg("App server shutdown error")
		return err
	}
	return nil
}

func (s *Server) startMetricsServer() error {
	bindAddr := viper.GetString(config.KeyMetricsBind)
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}
	bindPort := viper.GetInt(config.KeyMetricsPort)
	if bindPort < 1 {
		bindPort = 2112
	}

	// Handler
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.RouteHealthzHandler)
	mux.Handle("/metrics", promhttp.Handler())

	// Create the HTTP server
	s.metricsSrv = &http.Server{
		Addr:              net.JoinHostPort(bindAddr, strconv.Itoa(bindPort)),
		Handler:           mux,
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start the HTTPS server in a background goroutine
	go func() {
		s.log.Raw().Info().
			Str("bind", bindAddr).
			Int("port", bindPort).
			Msg("Metrics server started")
		// Next call blocks until the server is shut down
		err := s.metricsSrv.ListenAndServe()
		if err != http.ErrServerClosed {
			s.log.Raw().Fatal().Msgf("Error starting metrics server: %v", err)
		}
	}()

	return nil
}

func (s *Server) stopMetricsServer() error {
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	err := s.metricsSrv.Shutdown(shutdownCtx)
	shutdownCancel()
	if err != nil {
		// Log the error only (could be context canceled)
		s.log.Raw().Warn().
			AnErr("error", err).
			Msg("Metrics server shutdown error")
		return err
	}
	return nil
}

// Adds a subscription to a state by key
// If another subscription to the same key exists, evicts that first
// Important: invocations must be wrapped in s.lock being locked
func (s *Server) subscribeToState(stateId string) chan *requestState {
	ch := s.subs[stateId]
	if ch != nil {
		// Close the previous subscription
		close(ch)
	}

	// Create a new subscription
	ch = make(chan *requestState, 1)
	s.subs[stateId] = ch
	return ch
}

// Removes a subscription to a state by key, only if the channel matches the given one
// Important: invocations must be wrapped in s.lock being locked
func (s *Server) unsubscribeToState(stateId string, watch chan *requestState) {
	ch := s.subs[stateId]
	if ch != nil && ch == watch {
		close(ch)
	}
	delete(s.subs, stateId)
}

// Sends a notification to a state subscriber, if any
// The channel is then closed right after
// Important: invocations must be wrapped in s.lock being locked
func (s *Server) notifySubscriber(stateId string, state *requestState) {
	ch := s.subs[stateId]
	if ch == nil {
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
	req := s.states[stateId]
	if req == nil {
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

	// Record the result
	s.metrics.RecordResult("expired")
}

// Loads the TLS configuration
func (s *Server) loadTLSConfig() (tlsConfig *tls.Config, watchFn tlsCertWatchFn, err error) {
	tlsConfig = &tls.Config{
		MinVersion: minTLSVersion,
	}

	// First, check if we have actual keys
	tlsCert := viper.GetString(config.KeyTLSCertPEM)
	tlsKey := viper.GetString(config.KeyTLSKeyPEM)

	// If we don't have actual keys, then we need to load from file and reload when the files change
	if tlsCert == "" && tlsKey == "" {
		// If "tlsPath" is empty, use the folder where the config file is located
		tlsPath := viper.GetString(config.KeyTLSPath)
		if tlsPath == "" {
			file := viper.ConfigFileUsed()
			tlsPath = filepath.Dir(file)
		}

		var provider *tlsCertProvider
		provider, err = newTLSCertProvider(tlsPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load TLS certificates from path '%s': %w", tlsPath, err)
		}

		s.log.Raw().Debug().
			Str("path", tlsPath).
			Msg("Loaded TLS certificates from disk")

		tlsConfig.GetCertificate = provider.GetCertificateFn()

		return tlsConfig, provider.Watch, nil
	}

	// Assume the values from the config file are PEM-encoded certs and key
	if tlsCert == "" {
		return nil, nil, errors.New("missing TLS certificate")
	}
	if tlsKey == "" {
		return nil, nil, errors.New("missing TLS key")
	}

	cert, err := tls.X509KeyPair([]byte(tlsCert), []byte(tlsKey))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse TLS certificate or key: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	s.log.Raw().Debug().Msg("Loaded TLS certificates from PEM values")

	return tlsConfig, nil, nil
}

type operationResponse struct {
	State   string `json:"state"`
	Pending bool   `json:"pending,omitempty"`
	Done    bool   `json:"done,omitempty"`
	Failed  bool   `json:"failed,omitempty"`
	Value   string `json:"value,omitempty"`
}
