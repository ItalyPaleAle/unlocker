package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/unlocker/pkg/config"
	"github.com/italypaleale/unlocker/pkg/utils"
	"github.com/italypaleale/unlocker/pkg/utils/bufconn"
)

const (
	// Servers are started on in-memory listeners so these ports aren't actually used for TCP sockets
	testServerPort  = 5701
	testMetricsPort = 5702

	// Size for the in-memory buffer for bufconn
	bufconnBufSize = 1 << 20 // 1MB
)

func TestMain(m *testing.M) {
	defer utils.SetTestConfigs(map[string]any{
		config.KeyLogLevel:       "info",
		config.KeyPort:           testServerPort,
		config.KeyBind:           "127.0.0.1",
		config.KeyBaseUrl:        "https://localhost:" + strconv.Itoa(testServerPort),
		config.KeySessionTimeout: 5 * time.Minute,
		config.KeyRequestTimeout: 5 * time.Minute,
		config.KeyWebhookUrl:     "http://test.local",
		config.KeyEnableMetrics:  false,
		config.KeyMetricsBind:    "127.0.0.1",
		config.KeyMetricsPort:    testMetricsPort,
	})()

	gin.SetMode(gin.ReleaseMode)

	os.Exit(m.Run())
}

func TestServerLifecycle(t *testing.T) {
	testFn := func(metricsEnabled bool) func(t *testing.T) {
		return func(t *testing.T) {
			defer utils.SetTestConfigs(map[string]any{
				config.KeyEnableMetrics: metricsEnabled,
			})()

			// Create the server
			// This will create in-memory listeners with bufconn too
			srv, cleanup := newTestServer(t, nil)
			require.NotNil(t, srv)
			defer cleanup()
			stopServerFn := startTestServer(t, srv)

			// Make a request to the /healthz endpoint in the app server
			appClient := clientForListener(srv.appListener)
			reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer reqCancel()
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
				fmt.Sprintf("https://localhost:%d/healthz", testServerPort), nil)
			require.NoError(t, err)
			res, err := appClient.Do(req)
			require.NoError(t, err)
			defer res.Body.Close()

			healthzRes, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			require.NotEmpty(t, healthzRes)

			// Make a request to the /healthz endpoint in the metrics server
			if metricsEnabled {
				metricsClient := clientForListener(srv.metricsListener)
				reqCtx, reqCancel = context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				req, err = http.NewRequestWithContext(reqCtx, http.MethodGet,
					fmt.Sprintf("http://localhost:%d/healthz", testMetricsPort), nil)
				require.NoError(t, err)
				res, err = metricsClient.Do(req)
				require.NoError(t, err)
				defer res.Body.Close()

				resBody, err := io.ReadAll(res.Body)
				require.NoError(t, err)
				require.Equal(t, healthzRes, resBody)
			}

			// Shutdown the server
			stopServerFn(t)
		}
	}

	t.Run("run the server without metrics", testFn(false))

	t.Run("run the server with metrics enabled", testFn(true))
}

func TestServerHealthz(t *testing.T) {
	// Create the server
	// This will create in-memory listeners with bufconn too
	srv, cleanup := newTestServer(t, nil)
	require.NotNil(t, srv)
	defer cleanup()
	stopServerFn := startTestServer(t, srv)

	// Make a request to the /healthz endpoint
	appClient := clientForListener(srv.appListener)
	reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer reqCancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
		fmt.Sprintf("https://localhost:%d/healthz", testServerPort), nil)
	require.NoError(t, err)
	res, err := appClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()

	// Check the response
	require.Equal(t, "application/json", res.Header.Get("content-type"))

	body := map[string]any{}
	err = json.NewDecoder(res.Body).Decode(&body)
	require.NoError(t, err)
	require.NotEmpty(t, body)
	require.Equal(t, "ok", body["status"])

	// Shutdown the server
	stopServerFn(t)
}

func newTestServer(t *testing.T, wh *mockWebhook) (*Server, func()) {
	t.Helper()

	log := utils.NewAppLogger("test", io.Discard)
	if wh == nil {
		wh = &mockWebhook{}
	}
	srv, err := NewServer(log, wh)
	require.NoError(t, err)

	srv.appListener = bufconn.Listen(bufconnBufSize)
	srv.metricsListener = bufconn.Listen(bufconnBufSize)

	cert, key, err := getSelfSignedTLSCredentials()
	require.NoError(t, err, "cannot get TLS credentials")

	cleanup := utils.SetTestConfigs(map[string]any{
		config.KeyTLSCertPEM: cert,
		config.KeyTLSKeyPEM:  key,
	})

	return srv, cleanup
}

func startTestServer(t *testing.T, srv *Server) func(t *testing.T) {
	t.Helper()

	// Start the server in a background goroutine
	srvCtx, srvCancel := context.WithCancel(context.Background())
	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Run(srvCtx)
	}()

	// Ensure the server has started and there's no error
	// This may report false positives if the server just takes longer to start, but we'll still catch those errors later on
	select {
	case <-time.After(100 * time.Millisecond):
		// all good
	case err := <-startErrCh:
		t.Fatalf("Received an unexpected error in startErrCh: %v", err)
	}

	// Return a function to tear down the test server, which must be invoked at the end of the test
	return func(t *testing.T) {
		t.Helper()

		// Shutdown the server
		srvCancel()

		// At the end of the test, there should be no error
		require.NoError(t, <-startErrCh, "received an unexpected error in startErrCh")
	}
}

func clientForListener(ln net.Listener) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	transport.DialContext = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		bl, ok := ln.(*bufconn.Listener)
		if !ok {
			return nil, errors.New("failed to cast listener to bufconn.Listener")
		}
		return bl.DialContext(ctx)
	}

	return &http.Client{
		Transport: transport,
	}
}

func getSelfSignedTLSCredentials() (certPem []byte, keyPem []byte, err error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	certDer, err := x509.CreateCertificate(rand.Reader, &template, &template, pk.Public(), pk)
	if err != nil {
		return nil, nil, err
	}
	certPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer})

	keyDer, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		return nil, nil, err
	}

	keyPem = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer})

	return certPem, keyPem, nil
}

// mockWebhook implements the Webhook interface
type mockWebhook struct {
	requests chan *utils.WebhookRequest
}

func (w mockWebhook) SendWebhook(_ context.Context, data *utils.WebhookRequest) error {
	if w.requests != nil {
		w.requests <- data
	}
	return nil
}
