package traefik_oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OIDCProviderConfig holds the discovered OIDC provider configuration.
type OIDCProviderConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// OIDCProvider handles OIDC discovery and caching.
type OIDCProvider struct {
	providerURL string
	config      *OIDCProviderConfig
	mu          sync.RWMutex
	lastFetch   time.Time
	httpClient  *http.Client
}

// NewOIDCProvider creates a new OIDCProvider instance.
func NewOIDCProvider(providerURL string) *OIDCProvider {
	return &OIDCProvider{
		providerURL: strings.TrimSuffix(providerURL, "/"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetConfig returns the OIDC provider configuration, fetching it if necessary.
func (p *OIDCProvider) GetConfig() (*OIDCProviderConfig, error) {
	p.mu.RLock()
	if p.config != nil && time.Since(p.lastFetch) < time.Hour {
		config := p.config
		p.mu.RUnlock()
		return config, nil
	}
	p.mu.RUnlock()

	return p.fetchConfig()
}

// fetchConfig fetches the OIDC discovery document from the provider.
func (p *OIDCProvider) fetchConfig() (*OIDCProviderConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.config != nil && time.Since(p.lastFetch) < time.Hour {
		return p.config, nil
	}

	discoveryURL := p.providerURL + "/.well-known/openid-configuration"
	resp, err := p.httpClient.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var config OIDCProviderConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode OIDC discovery document: %w", err)
	}

	if config.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery missing authorization_endpoint")
	}
	if config.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery missing token_endpoint")
	}

	p.config = &config
	p.lastFetch = time.Now()

	return p.config, nil
}

// GetAuthorizationEndpoint returns the authorization endpoint URL.
func (p *OIDCProvider) GetAuthorizationEndpoint() (string, error) {
	config, err := p.GetConfig()
	if err != nil {
		return "", err
	}
	return config.AuthorizationEndpoint, nil
}

// GetTokenEndpoint returns the token endpoint URL.
func (p *OIDCProvider) GetTokenEndpoint() (string, error) {
	config, err := p.GetConfig()
	if err != nil {
		return "", err
	}
	return config.TokenEndpoint, nil
}

// GetEndSessionEndpoint returns the end session endpoint URL (if available).
func (p *OIDCProvider) GetEndSessionEndpoint() (string, error) {
	config, err := p.GetConfig()
	if err != nil {
		return "", err
	}
	return config.EndSessionEndpoint, nil
}
