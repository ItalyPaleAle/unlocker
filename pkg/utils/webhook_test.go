package utils

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/italypaleale/unlocker/pkg/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

type roundTripperTest struct {
	reqCh      chan *http.Request
	returnCode int
}

func (t *roundTripperTest) RoundTrip(r *http.Request) (*http.Response, error) {
	t.reqCh <- r

	return &http.Response{
		StatusCode: t.returnCode,
	}, nil
}

func TestWebhook(t *testing.T) {
	// Set configurations
	defer setTestConfigs(map[string]any{
		config.KeyWebhookUrl: "http://test.local/endpoint",
		config.KeyBaseUrl:    "http://test.local/app",
		config.KeyWebhookKey: "",
	})()

	logger, err := NewAppLogger("test", io.Discard)
	require.NoError(t, err)

	wh := NewWebhook(logger)

	// Create a roundtripper that captures the requests
	rt := &roundTripperTest{}
	wh.httpClient.Transport = rt

	getWebhookRequest := func() *WebhookRequest {
		return &WebhookRequest{
			OperationName: "wrap",
			KeyId:         "mykey",
			Vault:         "myvault",
			StateId:       "mystate",
			Requestor:     "127.0.0.1",
		}
	}

	basicTestFn := func(configs map[string]any, assertFn func(t *testing.T, r *http.Request)) func(*testing.T) {
		return func(t *testing.T) {
			if len(configs) > 0 {
				defer setTestConfigs(configs)()
			}

			reqCh := make(chan *http.Request, 1)
			rt.reqCh = reqCh
			rt.returnCode = http.StatusOK

			err = wh.SendWebhook(context.Background(), getWebhookRequest())
			require.NoError(t, err)

			r := <-reqCh
			assertFn(t, r)
			defer r.Body.Close()
		}
	}

	t.Run("format plain", basicTestFn(map[string]any{
		config.KeyWebhookFormat: "plain",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://test.local/endpoint", r.URL.String())
		requireBodyEqual(t, r.Body, "Received a request to wrap a key using key **mykey** in vault **myvault**.\n\nConfirm request: http://test.local/app\n\n(Request ID: mystate - Client IP: 127.0.0.1)")
	}))

	t.Run("empty format, fallback to plain", basicTestFn(map[string]any{
		config.KeyWebhookFormat: "",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://test.local/endpoint", r.URL.String())
		requireBodyEqual(t, r.Body, "Received a request to wrap a key using key **mykey** in vault **myvault**.\n\nConfirm request: http://test.local/app\n\n(Request ID: mystate - Client IP: 127.0.0.1)")
	}))

	t.Run("format slack", basicTestFn(map[string]any{
		config.KeyWebhookFormat: "slack",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://test.local/endpoint", r.URL.String())
		requireBodyEqual(t, r.Body, `{"text":"Received a request to wrap a key using key **mykey** in vault **myvault**.\n[Confirm request](http://test.local/app)\n`+"`(Request ID: mystate - Client IP: 127.0.0.1)`"+`"}`+"\n")
	}))

	t.Run("format discord appends /slack", basicTestFn(map[string]any{
		config.KeyWebhookFormat: "discord",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://test.local/endpoint/slack", r.URL.String())
		requireBodyEqual(t, r.Body, `{"text":"Received a request to wrap a key using key **mykey** in vault **myvault**.\n[Confirm request](http://test.local/app)\n`+"`(Request ID: mystate - Client IP: 127.0.0.1)`"+`"}`+"\n")
	}))

	t.Run("format discord with /slack already appended", basicTestFn(map[string]any{
		config.KeyWebhookUrl:    "http://my.local/endpoint/slack",
		config.KeyWebhookFormat: "discord",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://my.local/endpoint/slack", r.URL.String())
		requireBodyEqual(t, r.Body, `{"text":"Received a request to wrap a key using key **mykey** in vault **myvault**.\n[Confirm request](http://test.local/app)\n`+"`(Request ID: mystate - Client IP: 127.0.0.1)`"+`"}`+"\n")
	}))
}

func requireBodyEqual(t *testing.T, body io.ReadCloser, expect string) {
	t.Helper()

	read, err := io.ReadAll(body)
	require.NoError(t, err, "failed to read body")

	require.Equal(t, expect, string(read))
}

// Updates the configuration in the viper global object for the test
// Returns a function that should be called with "defer" to restore the previous configuration
func setTestConfigs(values map[string]any) func() {
	prevConfig := make(map[string]any, len(values))
	for k, v := range values {
		prevConfig[k] = viper.Get(k)
		viper.Set(k, v)
	}

	return func() {
		for k, v := range prevConfig {
			viper.Set(k, v)
		}
	}
}
