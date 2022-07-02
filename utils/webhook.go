package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Webhook client
type Webhook struct {
	httpClient *http.Client
}

// Init the object
func (w *Webhook) Init() {
	// Init a HTTP client
	w.httpClient = &http.Client{
		Timeout: 15 * time.Second,
	}
}

// SendWebhook sends the notification
func (w *Webhook) SendWebhook(data *WebhookRequest) (err error) {
	var req *http.Request
	switch strings.ToLower(viper.GetString("webhookFormat")) {
	case "slack":
		req, err = w.prepareSlackRequest(data)
	//case "plain":
	default:
		req, err = w.preparePlainRequest(data)
	}
	if err != nil {
		return err
	}

	res, err := w.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("invalid response status code: %d", res.StatusCode)
	}
	return nil
}

func (w *Webhook) getLink(data *WebhookRequest) string {
	return viper.GetString("baseUrl")
}

func (w *Webhook) preparePlainRequest(data *WebhookRequest) (req *http.Request, err error) {
	// Format the message
	message := fmt.Sprintf(
		"Received a request to %s a key using key **%s** in vault **%s**.\n\n[Confirm request](%s)\n\n(Request ID: %s - Client IP: %s)",
		data.OperationName,
		data.KeyId,
		data.Vault,
		w.getLink(data),
		data.StateId,
		data.Requestor,
	)

	// Create the request
	req, err = http.NewRequest("POST", viper.GetString("webhookUrl"), strings.NewReader(message))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")

	webhookKey := viper.GetString("webhookKey")
	if webhookKey != "" {
		req.Header.Set("Authorization", webhookKey)
	}

	return req, nil
}

func (w *Webhook) prepareSlackRequest(data *WebhookRequest) (req *http.Request, err error) {
	// Format the message
	message := fmt.Sprintf(
		"Received a request to %s a key using key **%s** in vault **%s**.\n[Confirm request](%s)\n`(Request ID: %s - Client IP: %s)`",
		data.OperationName,
		data.KeyId,
		data.Vault,
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
	req, err = http.NewRequest("POST", viper.GetString("webhookUrl"), buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	webhookKey := viper.GetString("webhookKey")
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
}
