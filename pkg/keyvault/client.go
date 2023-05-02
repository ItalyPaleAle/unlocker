package keyvault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// Client is a client for Azure Key Vault
type Client struct {
	cred tokenProvider
}

// NewClient returns a new Client object
func NewClient(accessToken string, expiration time.Time) *Client {
	return &Client{
		cred: newTokenProvider(accessToken, expiration),
	}
}

// Encrypt a message using a key stored in the Key Vault
func (c *Client) Encrypt(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationsParameters) (*KeyVaultEncryptResponse, error) {
	// Get the client
	client, err := c.getClient(vault)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure Key Vault client: %w", err)
	}

	// Perform the operation
	res, err := client.Encrypt(ctx, keyName, keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("error from Azure Key Vault: %w", err)
	}
	if res.Result == nil || res.KID == nil {
		return nil, errors.New("response from Azure Key Vault is invalid")
	}

	return &KeyVaultEncryptResponse{
		keyVaultResponseBase: keyVaultResponseBase{
			keyID: string(*res.KID),
		},
		Data:  res.Result,
		Nonce: params.IV,
		Tag:   res.AuthenticationTag,
	}, nil
}

// Decrypt a message using a key stored in the Key Vault.
func (c *Client) Decrypt(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationsParameters) (*KeyVaultDecryptResponse, error) {
	// Get the client
	client, err := c.getClient(vault)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure Key Vault client: %w", err)
	}

	// Perform the operation
	res, err := client.Decrypt(ctx, keyName, keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("error from Azure Key Vault: %w", err)
	}
	if res.Result == nil || res.KID == nil {
		return nil, errors.New("response from Azure Key Vault is invalid")
	}

	return &KeyVaultDecryptResponse{
		keyVaultResponseBase: keyVaultResponseBase{
			keyID: string(*res.KID),
		},
		Data: res.Result,
	}, nil
}

// WrapKey wraps a key using the key-encryption-key stored in the Key Vault
func (c *Client) WrapKey(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationsParameters) (*KeyVaultEncryptResponse, error) {
	// Get the client
	client, err := c.getClient(vault)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure Key Vault client: %w", err)
	}

	// Perform the operation
	res, err := client.WrapKey(ctx, keyName, keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("error from Azure Key Vault: %w", err)
	}
	if res.Result == nil || res.KID == nil {
		return nil, errors.New("response from Azure Key Vault is invalid")
	}

	return &KeyVaultEncryptResponse{
		keyVaultResponseBase: keyVaultResponseBase{
			keyID: string(*res.KID),
		},
		Data:  res.Result,
		Nonce: params.IV,
		Tag:   res.AuthenticationTag,
	}, nil
}

// UnwrapKey unwrap a wrapped key using the key-encryption-key stored in the Key Vault
func (c *Client) UnwrapKey(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationsParameters) (*KeyVaultDecryptResponse, error) {
	// Get the client
	client, err := c.getClient(vault)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure Key Vault client: %w", err)
	}

	// Perform the operation
	res, err := client.UnwrapKey(ctx, keyName, keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("error from Azure Key Vault: %w", err)
	}
	if res.Result == nil || res.KID == nil {
		return nil, errors.New("response from Azure Key Vault is invalid")
	}

	return &KeyVaultDecryptResponse{
		keyVaultResponseBase: keyVaultResponseBase{
			keyID: string(*res.KID),
		},
		Data: res.Result,
	}, nil
}

// Sign a message using a key stored in the Key Vault
func (c *Client) Sign(ctx context.Context, vault, keyName, keyVersion string, params azkeys.SignParameters) (*KeyVaultSignResponse, error) {
	// Get the client
	client, err := c.getClient(vault)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure Key Vault client: %w", err)
	}

	// Perform the operation
	res, err := client.Sign(ctx, keyName, keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("error from Azure Key Vault: %w", err)
	}
	if res.Result == nil || res.KID == nil {
		return nil, errors.New("response from Azure Key Vault is invalid")
	}

	return &KeyVaultSignResponse{
		keyVaultResponseBase: keyVaultResponseBase{
			keyID: string(*res.KID),
		},
		Data: res.Result,
	}, nil
}

// Verify a signature using a key stored in the Key Vault
func (c *Client) Verify(ctx context.Context, vault, keyName, keyVersion string, params azkeys.VerifyParameters) (*KeyVaultVerifyResponse, error) {
	// Get the client
	client, err := c.getClient(vault)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure Key Vault client: %w", err)
	}

	// Perform the operation
	res, err := client.Verify(ctx, keyName, keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("error from Azure Key Vault: %w", err)
	}
	if res.Value == nil {
		return nil, errors.New("response from Azure Key Vault is empty")
	}

	return &KeyVaultVerifyResponse{
		keyVaultResponseBase: keyVaultResponseBase{
			// Response from Azure Key Vault does not contain a key ID
			keyID: "",
		},
		Valid: *res.Value,
	}, nil
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
