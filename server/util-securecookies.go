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

func getSecureCookie(c *gin.Context, name string) (plaintextValue string, ttl time.Duration, err error) {
	key, ok := viper.Get("cookieEncryptionKey").([]byte)
	if !ok || len(key) != 16 {
		return "", 0, errors.New("empty or invalid cookieEncryptionKey in the configuration")
	}

	// Get the cookie
	cookieValue, err := c.Cookie(name)
	if err != nil {
		return "", 0, err
	}
	if cookieValue == "" {
		return "", 0, fmt.Errorf("cookie %s is empty", name)
	}

	// Parse the encrypted JWT in the cookie
	token, err := jwt.ParseEncrypted(cookieValue)
	if err != nil {
		return "", 0, err
	}
	c1 := jwt.Claims{}
	c2 := map[string]interface{}{}
	err = token.Claims(key, &c1, &c2)
	if err != nil {
		return "", 0, err
	}

	// Validate the claims
	if c1.Issuer != jwtIssuer {
		return "", 0, errors.New("invalid value for 'iss' claim")
	}
	if len(c1.Audience) != 1 || c1.Audience[0] != viper.GetString("azureClientId") {
		return "", 0, errors.New("invalid value for 'aud' claim")
	}
	now := time.Now()
	if c1.NotBefore == nil || c1.NotBefore.Time().After(now) {
		return "", 0, errors.New("invalid value for 'nbf' claim")
	}
	if c1.Expiry == nil {
		return "", 0, errors.New("invalid value for 'exp' claim")
	}
	ttl = c1.Expiry.Time().Sub(now)
	if ttl < 0 {
		return "", 0, errors.New("invalid value for 'exp' claim")
	}
	var v string
	if vI, ok := c2["v"]; ok {
		v, ok = vI.(string)
		if !ok {
			v = ""
		}
	}
	if v == "" {
		return "", 0, errors.New("invalid value for 'v' claim")
	}

	return v, ttl, nil
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
		// Add 1 extra second to synchronize with cookie expiry
		Expiry:    jwt.NewNumericDate(now.Add(time.Duration(maxAge+1) * time.Second)),
		NotBefore: jwt.NewNumericDate(now),
	}
	c2 := map[string]interface{}{
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
	c.SetCookie(name, cookieValue, maxAge, "/", c.Request.URL.Host, secureCookie, true)

	return nil
}
