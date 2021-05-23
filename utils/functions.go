package utils

import (
	"strings"
)

// IsTruthy returns true if a string is truthy, such as "1", "on", "yes", "true", "t", "y"
func IsTruthy(str string) bool {
	str = strings.ToLower(str)
	return str == "1" ||
		str == "true" ||
		str == "t" ||
		str == "on" ||
		str == "yes" ||
		str == "y"
}
