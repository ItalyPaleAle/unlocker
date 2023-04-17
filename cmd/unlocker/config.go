package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	nanoid "github.com/matoous/go-nanoid/v2"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"

	"github.com/italypaleale/unlocker/pkg/config"
)

func loadConfig() error {
	// Defaults
	viper.SetDefault(config.KeyLogLevel, "info")
	viper.SetDefault(config.KeyPort, 8080)
	viper.SetDefault(config.KeyBind, "0.0.0.0")
	viper.SetDefault(config.KeyBaseUrl, "https://localhost:8080")
	viper.SetDefault(config.KeySessionTimeout, 300)
	viper.SetDefault(config.KeyRequestTimeout, 300)

	// Env
	viper.SetEnvPrefix("UNLOCKER")
	viper.AutomaticEnv()

	// Config file
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.unlocker")
	viper.AddConfigPath("/etc/unlocker")

	// Check if we have a specific config file to load
	confFile := os.Getenv("UNLOCKER_CONFIG")
	if confFile != "" {
		viper.SetConfigFile(confFile)
	}

	// Read the config
	// Note: don't print any log that's not fatal-level before loading the desired log level
	err := viper.ReadInConfig()
	if err != nil {
		// Ignore errors if the config file doesn't exist
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return newLoadConfigError(err, "Error loading config file")
		}
	}

	// Process the configuration
	return processConfig()
}

// Processes the configuration from viper
func processConfig() (err error) {
	// Log level
	switch strings.ToLower(viper.GetString(config.KeyLogLevel)) {
	case "debug":
		appLogger.SetLogLevel(zerolog.DebugLevel)
	case "", "info": // Also default log level
		appLogger.SetLogLevel(zerolog.InfoLevel)
	case "warn":
		appLogger.SetLogLevel(zerolog.WarnLevel)
	case "error":
		appLogger.SetLogLevel(zerolog.ErrorLevel)
	default:
		return newLoadConfigError("Invalid value for 'logLevel'", "Invalid configuration")
	}

	// Check required variables
	if viper.GetString(config.KeyAzureClientId) == "" {
		return newLoadConfigError("Config entry key 'azureClientId' missing", "Invalid configuration")
	}
	if viper.GetString(config.KeyAzureTenantId) == "" {
		return newLoadConfigError("Config entry key 'azureTenantId' missing", "Invalid configuration")
	}
	if viper.GetString(config.KeyWebhookUrl) == "" {
		return newLoadConfigError("Config entry key 'webhookUrl' missing", "Invalid configuration")
	}

	// Check for invalid values
	if v := viper.GetInt(config.KeySessionTimeout); v < 1 || v > 3600 {
		return newLoadConfigError("Config entry key 'sessionTimeout' is invalid: must be between 1 and 3600", "Invalid configuration")
	}
	if v := viper.GetInt(config.KeyRequestTimeout); v < 1 {
		return newLoadConfigError("Config entry key 'requestTimeout' is invalid: must be greater than 1", "Invalid configuration")
	}

	// Lowercase the webhook format
	viper.Set(config.KeyWebhookFormat, strings.ToLower(viper.GetString(config.KeyWebhookFormat)))

	// Generate random tokenSigningKey if needed
	tokenSigningKey := viper.GetString(config.KeyTokenSigningKey)
	if tokenSigningKey == "" {
		appLogger.Raw().Debug().Msg("No 'tokenSigningKey' found in the configuration: a random one will be generated")

		tokenSigningKey, err = nanoid.New(21)
		if err != nil {
			return newLoadConfigError(err, "Failed to generate random tokenSigningKey")
		}
	}
	viper.Set(config.KeyInternalTokenSigningKey, tokenSigningKey)

	// Set the cookie keys
	err = setCookieKeys()
	if err != nil {
		return err
	}

	return nil
}

// Sets the cookie encryption and signing keys
func setCookieKeys() error {
	// If we have cookieEncryptionKey set, derive the keys from that
	// Otherwise, generate the keys randomly
	var (
		// Cookie Encryption Key, 128-bit (for AES-KW)
		cekRaw []byte
		// Cookie Signing Key, 256-bit (for HMAC-SHA256)
		cskRaw []byte
	)
	cekStr := viper.GetString(config.KeyCookieEncryptionKey)
	if cekStr != "" {
		h := hmac.New(crypto.SHA384.New, []byte(cekStr))
		h.Write([]byte("unlocker-cookie-keys"))
		sum := h.Sum(nil)
		cekRaw = sum[0:16]
		cskRaw = sum[16:]
	} else {
		appLogger.Raw().Debug().Msg("No 'cookieEncryptionKey' found in the configuration: a random one will be generated")

		cekRaw = make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, cekRaw)
		if err != nil {
			return newLoadConfigError(err, "Failed to generate random cookieEncryptionKey")
		}

		cskRaw = make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, cekRaw)
		if err != nil {
			return newLoadConfigError(err, "Failed to generate random cookieEncryptionKey")
		}
	}

	// Calculate the key ID
	kid := computeKeyId(cskRaw)

	// Import the keys as JWKs
	cek, err := jwk.FromRaw(cekRaw)
	if err != nil {
		return newLoadConfigError(err, "Failed to import cookieEncryptionKey as jwk.Key")
	}
	_ = cek.Set("kid", kid)
	viper.Set(config.KeyInternalCookieEncryptionKey, cek)

	csk, err := jwk.FromRaw(cskRaw)
	if err != nil {
		return newLoadConfigError(err, "Failed to import cookieSigningKey as jwk.Key")
	}
	_ = csk.Set("kid", kid)
	viper.Set(config.KeyInternalCookieSigningKey, csk)

	return nil
}

// Returns the key ID from a key
func computeKeyId(k []byte) string {
	h := sha256.Sum256(k)
	return base64.RawURLEncoding.EncodeToString(h[0:12])
}

// Error returned by loadConfig
type loadConfigError struct {
	err string
	msg string
}

// newLoadConfigError returns a new loadConfigError.
// The err argument can be a string or an error.
func newLoadConfigError(err any, msg string) *loadConfigError {
	return &loadConfigError{
		err: fmt.Sprintf("%v", err),
		msg: msg,
	}
}

// Error implements the error interface
func (e loadConfigError) Error() string {
	return e.msg
}

// LogFatal causes a fatal log
func (e loadConfigError) LogFatal() {
	appLogger.Raw().Fatal().
		Str("error", e.err).
		Msg(e.msg)
}
