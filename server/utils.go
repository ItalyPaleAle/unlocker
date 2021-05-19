package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/viper"
)

// Sends a webhook notification
func (s *Server) sendWebhook(message string) error {
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
	res, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("invalid response status code: %d", res.StatusCode)
	}
	return nil
}
