package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"

	"github.com/italypaleale/unlocker/server"
	"github.com/italypaleale/unlocker/utils"
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
	viper.SetDefault("port", 8080)
	viper.SetDefault("bind", "0.0.0.0")
	viper.SetDefault("baseUrl", "https://localhost:8080")
	viper.SetDefault("sessionTimeout", 300)
	viper.SetDefault("requestTimeout", 300)

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
	if viper.GetString("azureClientId") == "" {
		appLogger.Raw().Fatal().
			AnErr("error", errors.New("Config entry key 'azureClientId' missing")).
			Msg("Invalid configuration")
	}
	if viper.GetString("azureClientSecret") == "" {
		appLogger.Raw().Fatal().
			AnErr("error", errors.New("Config entry key 'azureClientSecret' missing")).
			Msg("Invalid configuration")
	}
	if viper.GetString("azureTenantId") == "" {
		appLogger.Raw().Fatal().
			AnErr("error", errors.New("Config entry key 'azureTenantId' missing")).
			Msg("Invalid configuration")
	}
	if viper.GetString("webhookUrl") == "" {
		appLogger.Raw().Fatal().
			AnErr("error", errors.New("Config entry key 'webhookUrl' missing")).
			Msg("Invalid configuration")
	}

	// Check for invalid values
	if v := viper.GetInt("sessionTimeout"); v < 1 || v > 3600 {
		appLogger.Raw().Fatal().
			AnErr("error", errors.New("Config entry key 'sessionTimeout' is invalid: must be between 1 and 3600")).
			Msg("Invalid configuration")
	}
	if v := viper.GetInt("requestTimeout"); v < 1 {
		appLogger.Raw().Fatal().
			AnErr("error", errors.New("Config entry key 'requestTimeout' is invalid: must be greater than 1")).
			Msg("Invalid configuration")
	}

	// TLS certificate
	// Fallback to tls-cert.pem and tls-key.pem if not set
	if viper.GetString("tlsCert") == "" || viper.GetString("tlsKey") == "" {
		file := viper.ConfigFileUsed()
		dir := filepath.Dir(file)
		viper.Set("tlsCert", filepath.Join(dir, "tls-cert.pem"))
		viper.Set("tlsKey", filepath.Join(dir, "tls-key.pem"))
	}

	// Generate random tokenSigningKey if needed
	if viper.GetString("tokenSigningKey") == "" {
		tokenSigningKey, err := utils.RandomString()
		if err != nil {
			appLogger.Raw().Fatal().
				AnErr("error", err).
				Msg("Failed to generate random tokenSigningKey")
		}

		viper.Set("tokenSigningKey", tokenSigningKey)
	}

	// If we have cookieEncryptionKey set, derive a 128-bit key from that
	// Otherwise, generate a random 128-bit key
	var cek []byte
	cekStr := viper.GetString("cookieEncryptionKey")
	if cekStr != "" {
		h := sha256.Sum256([]byte(cekStr))
		cek = h[:]
	} else {
		cek = make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, cek)
		if err != nil {
			appLogger.Raw().Fatal().
				AnErr("error", err).
				Msg("Failed to generate random cookieEncryptionKey")
		}
	}
	viper.Set("cookieEncryptionKey", cek)
}
