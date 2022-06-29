package server

import (
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/spf13/viper"
)

const jwtIssuer = "unlocker"

func getSecureCookie(c *gin.Context, name string) (plaintextValue string, err error) {
	key, ok := viper.Get("cookieEncryptionKey").([]byte)
	if !ok || len(key) != 16 {
		return "", errors.New("empty or invalid cookieEncryptionKey in the configuration")
	}

	// Get the cookie
	cookieValue, err := c.Cookie(name)
	if err != nil {
		return "", err
	}
	if cookieValue == "" {
		return "", fmt.Errorf("cookie %s is empty", name)
	}

	// Parse the encrypted JWT in the cookie
	token, err := jwt.ParseEncrypted(cookieValue)
	if err != nil {
		return "", err
	}
	c1 := jwt.Claims{}
	c2 := map[string]string{}
	err = token.Claims(key, &c1, &c2)
	if err != nil {
		return "", err
	}

	// Validate the claims
	if c1.Issuer != jwtIssuer {
		return "", errors.New("invalid value for 'iss' claim")
	}
	if len(c1.Audience) != 1 || c1.Audience[0] != viper.GetString("azureClientId") {
		return "", errors.New("invalid value for 'aud' claim")
	}
	now := time.Now()
	if c1.NotBefore == nil || c1.NotBefore.Time().After(now) {
		return "", errors.New("invalid value for 'nbf' claim")
	}
	if c1.Expiry == nil || c1.Expiry.Time().Before(now) {
		return "", errors.New("invalid value for 'exp' claim")
	}
	if v, ok := c2["v"]; !ok || v == "" {
		return "", errors.New("invalid value for 'v' claim")
	}

	return c2["v"], nil
}

func setSecureCookie(c *gin.Context, name string, plaintextValue string, maxAge int, path string, domain string, secureCookie bool, httpOnly bool) error {
	key, ok := viper.Get("cookieEncryptionKey").([]byte)
	if !ok || len(key) != 16 {
		return errors.New("empty or invalid cookieEncryptionKey in the configuration")
	}

	// Claims for the JWT
	now := time.Now()
	c1 := jwt.Claims{
		Issuer: jwtIssuer,
		Audience: jwt.Audience{
			// Use the Azure client ID as our audience too
			viper.GetString("azureClientId"),
		},
		Expiry:    jwt.NewNumericDate(now.Add(time.Duration(maxAge) * time.Second)),
		NotBefore: jwt.NewNumericDate(now),
	}
	c2 := map[string]string{
		"v": plaintextValue,
	}

	// Generate and encrypt the JWT
	enc, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       key,
		},
		(&jose.EncrypterOptions{}).WithType("JWT"),
	)
	if err != nil {
		return err
	}
	cookieValue, err := jwt.Encrypted(enc).
		Claims(c1).
		Claims(c2).
		CompactSerialize()
	if err != nil {
		return err
	}

	// Set the cookie
	c.SetCookie(atCookieName, cookieValue, maxAge, "/", c.Request.URL.Host, secureCookie, true)

	return nil
}
