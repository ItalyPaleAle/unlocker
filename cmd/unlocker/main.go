package main

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"

	"github.com/italypaleale/unlocker/pkg/config"
	"github.com/italypaleale/unlocker/pkg/server"
	"github.com/italypaleale/unlocker/pkg/utils"
)

var appLogger *utils.AppLogger

func main() {
	// Init the app logger object
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	appLogger = &utils.AppLogger{
		App: "unlocker",
	}
	err := appLogger.InitWithWriter(os.Stderr)
	if err != nil {
		panic(err)
	}

	// Load config
	loadConfig()

	// Create the Server object
	srv := server.Server{}
	err = srv.Init(appLogger)
	if err != nil {
		appLogger.Raw().Fatal().
			AnErr("error", err).
			Msg("Cannot initialize the server")
		return
	}

	// Listen for SIGTERM and SIGINT in background to stop the context
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

		<-ch
		appLogger.Raw().Info().Msg("Received interrupt signal. Shutting down…")
		cancel()
	}()

	// Start the server in background and block until the server is shut down (gracefully)
	err = srv.Start(ctx)
	if err != nil {
		appLogger.Raw().Fatal().
			AnErr("error", err).
			Msg("Cannot start the server")
		return
	}
}

func loadConfig() {
	// Defaults
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
	err := viper.ReadInConfig()
	if err != nil {
		// Ignore errors if the config file doesn't exist
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			appLogger.Raw().Fatal().AnErr("error", err).Msg("Error loading config file")
		}
	}

	// Check required variables
	if viper.GetString(config.KeyAzureClientId) == "" {
		appLogger.Raw().Fatal().
			AnErr("error", errors.New("Config entry key 'azureClientId' missing")).
			Msg("Invalid configuration")
	}
	if viper.GetString(config.KeyAzureClientSecret) == "" {
		appLogger.Raw().Fatal().
			AnErr("error", errors.New("Config entry key 'azureClientSecret' missing")).
			Msg("Invalid configuration")
	}
	if viper.GetString(config.KeyAzureTenantId) == "" {
		appLogger.Raw().Fatal().
			AnErr("error", errors.New("Config entry key 'azureTenantId' missing")).
			Msg("Invalid configuration")
	}
	if viper.GetString(config.KeyWebhookUrl) == "" {
		appLogger.Raw().Fatal().
			AnErr("error", errors.New("Config entry key 'webhookUrl' missing")).
			Msg("Invalid configuration")
	}

	// Check for invalid values
	if v := viper.GetInt(config.KeySessionTimeout); v < 1 || v > 3600 {
		appLogger.Raw().Fatal().
			AnErr("error", errors.New("Config entry key 'sessionTimeout' is invalid: must be between 1 and 3600")).
			Msg("Invalid configuration")
	}
	if v := viper.GetInt(config.KeyRequestTimeout); v < 1 {
		appLogger.Raw().Fatal().
			AnErr("error", errors.New("Config entry key 'requestTimeout' is invalid: must be greater than 1")).
			Msg("Invalid configuration")
	}

	// TLS certificate
	// Fallback to tls-cert.pem and tls-key.pem if not set
	if viper.GetString(config.KeyTLSCert) == "" || viper.GetString(config.KeyTLSKey) == "" {
		file := viper.ConfigFileUsed()
		dir := filepath.Dir(file)
		viper.Set(config.KeyTLSCert, filepath.Join(dir, "tls-cert.pem"))
		viper.Set(config.KeyTLSKey, filepath.Join(dir, "tls-key.pem"))
	}

	// Generate random tokenSigningKey if needed
	if viper.GetString(config.KeyTokenSigningKey) == "" {
		appLogger.Raw().Info().Msg("No 'tokenSigningKey' found in the configuration: a random one will be generated")

		tokenSigningKey, err := utils.RandomString()
		if err != nil {
			appLogger.Raw().Fatal().
				AnErr("error", err).
				Msg("Failed to generate random tokenSigningKey")
		}

		viper.Set(config.KeyInternalTokenSigningKey, tokenSigningKey)
	}

	// Set the cookie keys
	// This panics in case of errors
	setCookieKeys()
}

// Sets the cookie encryption and signing keys
func setCookieKeys() {
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
		appLogger.Raw().Info().Msg("No 'cookieEncryptionKey' found in the configuration: a random one will be generated")

		cekRaw = make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, cekRaw)
		if err != nil {
			appLogger.Raw().Fatal().
				AnErr("error", err).
				Msg("Failed to generate random cookieEncryptionKey")
		}

		cskRaw = make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, cekRaw)
		if err != nil {
			appLogger.Raw().Fatal().
				AnErr("error", err).
				Msg("Failed to generate random cookieEncryptionKey")
		}
	}

	// Calculate the key ID
	kid := computeKeyId(cskRaw)

	// Import the keys as JWKs
	cek, err := jwk.FromRaw(cekRaw)
	if err != nil {
		appLogger.Raw().Fatal().
			AnErr("error", err).
			Msg("Failed to import cookieEncryptionKey as jwk.Key")
	}
	_ = cek.Set("kid", kid)
	viper.Set(config.KeyInternalCookieEncryptionKey, cek)

	csk, err := jwk.FromRaw(cskRaw)
	if err != nil {
		appLogger.Raw().Fatal().
			AnErr("error", err).
			Msg("Failed to import cookieSigningKey as jwk.Key")
	}
	_ = csk.Set("kid", kid)
	viper.Set(config.KeyInternalCookieSigningKey, csk)
}

// Returns the key ID from a key
func computeKeyId(k []byte) string {
	h := sha256.Sum256(k)
	return base64.RawURLEncoding.EncodeToString(h[0:12])
}
