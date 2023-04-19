package testutils

import (
	"github.com/spf13/viper"
)

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
