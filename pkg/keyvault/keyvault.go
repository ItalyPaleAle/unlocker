package keyvault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a client for Azure Key Vault
type Client struct {
	accessToken string
	httpClient  *http.Client
}

// Init the object
func (c *Client) Init(accessToken string) error {
	c.accessToken = accessToken

	// Init a HTTP client
	c.httpClient = &http.Client{
		Timeout: 20 * time.Second,
	}

	return nil
}

// KeyUrl returns the URL for a key in Azure Key Vault
func (c *Client) KeyUrl(vault, keyId, keyVersion string) string {
	if keyVersion == "" {
		return fmt.Sprintf("https://%s.vault.azure.net/keys/%s", vault, keyId)
	}
	return fmt.Sprintf("https://%s.vault.azure.net/keys/%s/%s", vault, keyId, keyVersion)
}

// GetKeyLastVersion returns the latest version of a key stored in Key Vault
func (c *Client) GetKeyLastVersion(ctx context.Context, vault string, keyId string) (string, error) {
	reqUrl := fmt.Sprintf("https://%s.vault.azure.net/keys/%s", vault, keyId)
	req, err := http.NewRequestWithContext(ctx, "GET", reqUrl+"?api-version=7.2", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	// Send the request and read the result
	res, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	if res.StatusCode != 200 {
		resError := &KeyVaultError{}
		if json.Unmarshal(resBody, resError) != nil {
			// Body cannot be unmarshalled into keyVaultError
			return "", errors.New("response error: " + string(resBody))
		}
		return "", errors.New(resError.String())
	}
	resData := &struct {
		Key struct {
			Kid string `json:"kid"`
		} `json:"key"`
	}{}
	err = json.Unmarshal(resBody, resData)
	if err != nil {
		return "", err
	}
	if resData.Key.Kid == "" {
		return "", errors.New("empty key id in response")
	}

	// Extract the version at the end of the URL
	return resData.Key.Kid[len(reqUrl)+1:], nil
}

// WrapKey wraps a key using the key-encryption-key stored in the Key Vault at keyUrl
func (c *Client) WrapKey(ctx context.Context, keyUrl string, key []byte) ([]byte, error) {
	if keyUrl == "" {
		return nil, errors.New("argument keyUrl is empty")
	}
	if len(key) == 0 {
		return nil, errors.New("argument key is empty")
	}

	// Send the request
	return c.doWrapUnwrap(ctx, keyUrl+"/wrapkey", key)
}

// UnwrapKey unwrap a wrapped key using the key-encryption-key stored in the Key Vault at keyUrl
func (c *Client) UnwrapKey(ctx context.Context, keyUrl string, wrappedKey []byte) ([]byte, error) {
	if keyUrl == "" {
		return nil, errors.New("argument keyUrl is empty")
	}
	if len(wrappedKey) == 0 {
		return nil, errors.New("argument wrappedKey is empty")
	}

	// Send the request
	return c.doWrapUnwrap(ctx, keyUrl+"/unwrapkey", wrappedKey)
}

// Internal function that performs wrap and unwrap operations on the keys
func (c *Client) doWrapUnwrap(ctx context.Context, reqUrl string, key []byte) ([]byte, error) {
	// Request body
	// We need to encode the value ourselves using base64 URL-encoding
	reqBodyData := struct {
		Algorithm string `json:"alg"`
		Value     string `json:"value"`
	}{
		Algorithm: "RSA-OAEP-256",
		Value:     base64.RawURLEncoding.EncodeToString(key),
	}
	reqBody, err := json.Marshal(reqBodyData)
	if err != nil {
		return nil, err
	}

	// Build the request
	req, err := http.NewRequestWithContext(ctx, "POST", reqUrl+"?api-version=7.2", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	// Send the request and read the result
	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		kvErr := &KeyVaultError{}
		if json.Unmarshal(resBody, kvErr) != nil || kvErr.Err.Code == "" {
			// Body cannot be unmarshalled into keyVaultError
			return nil, errors.New("response error: " + string(resBody))
		}
		return nil, kvErr
	}
	resData := &keyOperationResult{}
	err = json.Unmarshal(resBody, resData)
	if err != nil {
		return nil, err
	}
	if resData.Value == "" {
		return nil, errors.New("empty value in response")
	}

	// Decode the value from the response
	// We need to do it ourselves because Key Vault uses base64 URL-encoding
	val, err := base64.RawURLEncoding.DecodeString(resData.Value)
	if err != nil {
		return nil, err
	}
	return val, nil
}

// Type of responses containing a key (wrapped or unwrapped)
// Value is used as string because Key Vault uses base64 URL encoding
type keyOperationResult struct {
	KeyId string `json:"kid"`
	Value string `json:"value"`
}

// Type of error responses
type KeyVaultError struct {
	Err struct {
		Message    string         `json:"message"`
		Code       string         `json:"code"`
		InnerError *KeyVaultError `json:"innererror"`
	} `json:"error"`
}

// String representation
func (e *KeyVaultError) String() string {
	var details string
	if e.Err.InnerError != nil {
		details = fmt.Sprintf("\ndetails='%v'", e.Err.InnerError)
	}
	return fmt.Sprintf("error from Key Vault (code='%s') error='%s'%s", e.Err.Code, e.Err.Message, details)
}

// Error implements the error interface
func (e *KeyVaultError) Error() string {
	return e.String()
}
