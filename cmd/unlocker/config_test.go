package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/unlocker/pkg/config"
	"github.com/italypaleale/unlocker/pkg/utils"
)

func TestValidateConfig(t *testing.T) {
	// Set initial variables in the viper global object
	defer utils.SetTestConfigs(getDefaultConfig())()
	defer utils.SetTestConfigs(map[string]any{
		config.KeyAzureClientId: "d196f679-da38-492c-946a-60ae8324e7f9",
		config.KeyAzureTenantId: "e440d651-3dcf-4c20-b147-96a2ff00ee25",
		config.KeyWebhookUrl:    "http://test.local",
	})()

	t.Run("succeeds with all required vars", func(t *testing.T) {
		err := validateConfig()
		require.NoError(t, err)
	})

	t.Run("fails without azureClientId", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeyAzureClientId: "",
		})()

		err := validateConfig()
		require.Error(t, err)
		require.ErrorContains(t, err, "'azureClientId' missing")
	})

	t.Run("fails without azureTenantId", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeyAzureTenantId: "",
		})()

		err := validateConfig()
		require.Error(t, err)
		require.ErrorContains(t, err, "'azureTenantId' missing")
	})

	t.Run("fails without webhookUrl", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeyWebhookUrl: "",
		})()

		err := validateConfig()
		require.Error(t, err)
		require.ErrorContains(t, err, "'webhookUrl' missing")
	})

	t.Run("fails with sessionTimeout too small", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeySessionTimeout: 100 * time.Millisecond,
		})()

		err := validateConfig()
		require.Error(t, err)
		require.ErrorContains(t, err, "'sessionTimeout' is invalid")
	})

	t.Run("fails with sessionTimeout too big", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeySessionTimeout: 3 * time.Hour,
		})()

		err := validateConfig()
		require.Error(t, err)
		require.ErrorContains(t, err, "'sessionTimeout' is invalid")
	})

	t.Run("fails with requestTimeout too small", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeyRequestTimeout: 100 * time.Millisecond,
		})()

		err := validateConfig()
		require.Error(t, err)
		require.ErrorContains(t, err, "'requestTimeout' is invalid")
	})
}

func TestEnsureTokenSigningKey(t *testing.T) {
	logs := &bytes.Buffer{}
	utils.SetAppLogger(&appLogger, logs)

	t.Run("tokenSigningKey present", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeyTokenSigningKey: "hello-world",
		})()

		err := ensureTokenSigningKey()
		require.NoError(t, err)
		require.Equal(t, "hello-world", viper.GetString(config.KeyInternalTokenSigningKey))
	})

	t.Run("tokenSigningKey not present", func(t *testing.T) {
		defer utils.SetTestConfigs(map[string]any{
			config.KeyTokenSigningKey: "",
		})()

		err := ensureTokenSigningKey()
		require.NoError(t, err)
		require.Len(t, viper.GetString(config.KeyInternalTokenSigningKey), 21)

		logsMsg := logs.String()
		require.Contains(t, logsMsg, "No 'tokenSigningKey' found in the configuration")
	})
}
