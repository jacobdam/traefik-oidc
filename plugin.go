// Package traefik_oidc provides an OIDC PKCE authentication middleware for Traefik.
package traefik_oidc

import (
	"context"
	"fmt"
	"net/http"
)

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Scopes:             []string{"openid", "profile", "email"},
		CallbackPath:       "/oauth2/callback",
		LogoutPath:         "/oauth2/logout",
		CookieName:         "oidc_session",
		CookieSecure:       true,
		CookieSameSite:     "Lax",
		ExcludedPaths:      []string{},
		ForwardAccessToken: true,
	}
}

// New creates a new OIDC PKCE middleware instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	crypto, err := NewCrypto(config.SessionEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize crypto: %w", err)
	}

	provider := NewOIDCProvider(config.ProviderURL)

	return &OIDCMiddleware{
		next:     next,
		name:     name,
		config:   config,
		crypto:   crypto,
		provider: provider,
	}, nil
}
