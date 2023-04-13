package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/italypaleale/unlocker/pkg/config"
)

const webhookTimeout = 20 * time.Second

// Webhook client
type Webhook struct {
	httpClient *http.Client
	log        *AppLogger
}

// NewWebhook creates a new Webhook
func NewWebhook(log *AppLogger) *Webhook {
	w := &Webhook{}
	w.Init(log)
	return w
}

// Init the object
func (w *Webhook) Init(log *AppLogger) {
	w.log = log

	// Init a HTTP client
	w.httpClient = &http.Client{
		Timeout: webhookTimeout,
	}
}

// SendWebhook sends the notification
func (w *Webhook) SendWebhook(ctx context.Context, data *WebhookRequest) (err error) {
	webhookUrl := viper.GetString(config.KeyWebhookUrl)

	// Retry up to 3 times
	const attempts = 3
	for i := 0; i < attempts; i++ {
		var req *http.Request
		reqCtx, reqCancel := context.WithTimeout(ctx, webhookTimeout)
		switch viper.GetString(config.KeyWebhookFormat) {
		case "slack":
			req, err = w.prepareSlackRequest(reqCtx, webhookUrl, data)
		case "discord":
			// Shorthand for using Slack-compatible webhooks with Discord
			if !strings.HasSuffix(webhookUrl, "/slack") {
				webhookUrl += "/slack"
			}
			req, err = w.prepareSlackRequest(reqCtx, webhookUrl, data)
		//case "plain":
		default:
			req, err = w.preparePlainRequest(reqCtx, webhookUrl, data)
		}
		if err != nil {
			reqCancel()
			return err
		}

		res, err := w.httpClient.Do(req)
		reqCancel()
		if err != nil {
			// Retry after 15 seconds on network failures
			w.log.Raw().Warn().
				Err(err).
				Msg("Network error sending webhook; will retry after 15 seconds")
			time.Sleep(15 * time.Second)
			continue
		}

		// Drain body before closing
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()

		// Handle throttling on 429 responses and on 5xx errors
		if res.StatusCode == http.StatusTooManyRequests {
			retryAfter, _ := strconv.Atoi(res.Header.Get("Retry-After"))
			if retryAfter < 1 || retryAfter > 30 {
				retryAfter = 30
			}
			w.log.Raw().Warn().
				Msgf("Webhook throttled; will retry after %d seconds", retryAfter)
			time.Sleep(time.Duration(retryAfter) * time.Second)
			continue
		}

		// Retry after a delay on 5xx errors, which indicate a problem with the server
		if res.StatusCode >= 500 && res.StatusCode < 600 {
			w.log.Raw().Warn().
				Msgf("Webhook returned an error response: %d; will retry after 30 seconds", res.StatusCode)
			time.Sleep(30 * time.Second)
			continue
		}

		// Any other error is permanent
		if res.StatusCode < 200 || res.StatusCode > 299 {
			return fmt.Errorf("invalid response status code: %d", res.StatusCode)
		}
		return nil
	}

	return fmt.Errorf("failed to send webhook after %d attempts", attempts)
}

func (w *Webhook) getLink(data *WebhookRequest) string {
	return viper.GetString(config.KeyBaseUrl)
}

func (w *Webhook) preparePlainRequest(ctx context.Context, webhookUrl string, data *WebhookRequest) (req *http.Request, err error) {
	// Format the message
	message := fmt.Sprintf(
		`Received a request to %s a key using key **%s** in vault **%s**.

Confirm request: %s

(Request ID: %s - Client IP: %s)`,
		data.OperationName,
		data.KeyId,
		data.Vault,
		w.getLink(data),
		data.StateId,
		data.Requestor,
	)

	// Create the request
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, webhookUrl, strings.NewReader(message))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")

	webhookKey := viper.GetString(config.KeyWebhookKey)
	if webhookKey != "" {
		req.Header.Set("Authorization", webhookKey)
	}

	return req, nil
}

func (w *Webhook) prepareSlackRequest(ctx context.Context, webhookUrl string, data *WebhookRequest) (req *http.Request, err error) {
	// Format the message
	var note string
	if data.Note != "" {
		note = "Note: *" + data.Note + "*\n"
	}
	message := fmt.Sprintf(
		"Received a request to %s a key using key **%s** in vault **%s**.\n%s[Confirm request](%s)\n`(Request ID: %s - Client IP: %s)`",
		data.OperationName,
		data.KeyId,
		data.Vault,
		note,
		w.getLink(data),
		data.StateId,
		data.Requestor,
	)

	// Build the body
	buf := &bytes.Buffer{}
	err = json.NewEncoder(buf).Encode(struct {
		Text string `json:"text"`
	}{
		Text: message,
	})
	if err != nil {
		return nil, err
	}

	// Create the request
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, webhookUrl, buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	webhookKey := viper.GetString(config.KeyWebhookKey)
	if webhookKey != "" {
		req.Header.Set("Authorization", webhookKey)
	}

	return req, nil
}

type WebhookRequest struct {
	OperationName string
	KeyId         string
	Vault         string
	StateId       string
	Requestor     string
	Note          string
}
