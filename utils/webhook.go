package utils

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Webhook struct {
	httpClient *http.Client
}

func (w *Webhook) Init() {
	// Init a HTTP client
	w.httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}
}

func (w *Webhook) SendWebhook(message string) error {
	// Trigger the webhook
	req, err := http.NewRequest("POST", viper.GetString("webhookUrl"), strings.NewReader(message))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	webhookKey := viper.GetString("webhookKey")
	if webhookKey != "" {
		req.Header.Set("Authorization", webhookKey)
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
