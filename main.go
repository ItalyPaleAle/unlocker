package main

import (
	"context"
	"errors"
	"os"

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

	// Start the server in background and block until the server is shut down
	srv.Start(context.Background())
}

func loadConfig() {
	// Defaults
	viper.SetDefault("port", 8080)
	viper.SetDefault("bind", "0.0.0.0")
	viper.SetDefault("baseUrl", "http://localhost:8080")

	// Env
	viper.SetEnvPrefix("UNLOCKER")
	viper.AutomaticEnv()

	// Config file
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.unlocker")
	viper.AddConfigPath("/etc/unlocker")

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
}
