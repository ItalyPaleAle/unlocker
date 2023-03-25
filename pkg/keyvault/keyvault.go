package keyvault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
)

// Client is a client for Azure Key Vault
type Client struct {
	cred tokenProvider
}

// Init the object
func (c *Client) Init(accessToken string, expiration time.Time) error {
	c.cred = newTokenProvider(accessToken, expiration)
	return nil
}

// vaultUrl returns the URL for the Azure Key Vault
// Parameter vault can be one of:
// - The address of the vault, such as "https://<name>.vault.azure.net" (could be a different format if using different clouds or private endpoints)
// - The FQDN of the vault, such as "<name>.vault.azure.net" (or another domain if using different clouds or private endpoints)
// - Only the name of the vault, which will be formatted for "vault.azure.net"
func (c Client) vaultUrl(vault string) string {
	// If there's a dot, assume it's either a full URL or a FQDN
	if strings.ContainsRune(vault, '.') {
		if !strings.HasPrefix(vault, "https://") {
			vault = "https://" + vault
		}
		return vault
	}

	return "https://" + vault + ".vault.azure.net"
}

// getClient returns the azkeys.Client object for the given vault
func (c *Client) getClient(vault string) (*azkeys.Client, error) {
	vaultUrl := c.vaultUrl(vault)

	return azkeys.NewClient(vaultUrl, c.cred, &azkeys.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Telemetry: policy.TelemetryOptions{
				Disabled: true,
			},
		},
	})
}

// WrapKey wraps a key using the key-encryption-key stored in the Key Vault at keyUrl
func (c *Client) WrapKey(ctx context.Context, vault, keyName, keyVersion string, key []byte) ([]byte, error) {
	if vault == "" {
		return nil, errors.New("argument vault is empty")
	}
	if keyName == "" {
		return nil, errors.New("argument keyName is empty")
	}
	if len(key) == 0 {
		return nil, errors.New("argument key is empty")
	}

	// Get the client
	client, err := c.getClient(vault)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure Key Vault client: %w", err)
	}

	// Perform the operation
	res, err := client.WrapKey(ctx, keyName, keyVersion, azkeys.KeyOperationsParameters{
		Value:     key,
		Algorithm: to.Ptr(azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256),
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("error from Azure Key Vault: %w", err)
	}
	if res.Result == nil {
		return nil, errors.New("response from Azure Key Vault is empty")
	}

	return res.Result, nil
}

// UnwrapKey unwrap a wrapped key using the key-encryption-key stored in the Key Vault at keyUrl
func (c *Client) UnwrapKey(ctx context.Context, vault, keyName, keyVersion string, wrappedKey []byte) ([]byte, error) {
	if vault == "" {
		return nil, errors.New("argument vault is empty")
	}
	if keyName == "" {
		return nil, errors.New("argument keyName is empty")
	}
	if len(wrappedKey) == 0 {
		return nil, errors.New("argument wrappedKey is empty")
	}

	// Get the client
	client, err := c.getClient(vault)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure Key Vault client: %w", err)
	}

	// Perform the operation
	res, err := client.UnwrapKey(ctx, keyName, keyVersion, azkeys.KeyOperationsParameters{
		Value:     wrappedKey,
		Algorithm: to.Ptr(azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256),
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("error from Azure Key Vault: %w", err)
	}
	if res.Result == nil {
		return nil, errors.New("response from Azure Key Vault is empty")
	}

	return res.Result, nil
}
