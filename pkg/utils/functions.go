package utils

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
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

// RandomString generates a random string of 20 base64url-encoded characters
func RandomString() (string, error) {
	buf := make([]byte, 15)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// FileExists returns true if a file exists on disk and is a regular file
func FileExists(path string) (bool, error) {
	s, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return false, err
	}
	return !s.IsDir(), nil
}
