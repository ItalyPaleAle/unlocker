package keyvault

import (
	"context"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

var _ azcore.TokenCredential = tokenProvider{}

// tokenProvider implements azcore.TokenCredential
type tokenProvider struct {
	token      string
	expiration time.Time
}

func newTokenProvider(token string, expiration time.Time) tokenProvider {
	return tokenProvider{
		token:      token,
		expiration: expiration,
	}
}

func (t tokenProvider) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{
		Token:     t.token,
		ExpiresOn: t.expiration,
	}, nil
}
