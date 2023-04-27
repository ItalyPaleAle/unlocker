//go:build unit

// This file is only built when the "unit" tag is set

package utils

import (
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

// Sets appLogger, optionally with a custom buffer as destination
// Returns a function that should be called with "defer" to restore the previous appLogger
func SetAppLogger(appLogger **AppLogger, dest io.Writer) func() {
	prevAppLogger := *appLogger

	if dest == nil {
		dest = os.Stderr
	}
	*appLogger = NewAppLogger("test", dest)
	(*appLogger).SetLogLevel(zerolog.DebugLevel)

	return func() {
		*appLogger = prevAppLogger
	}
}

// Updates the configuration in the viper global object for the test
// Returns a function that should be called with "defer" to restore the previous configuration
func SetTestConfigs(values map[string]any) func() {
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
