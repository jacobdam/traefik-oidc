package traefik_oidc

import (
	"errors"
	"strings"
)

// ForwardAuth constants define which token to forward to backend services.
const (
	ForwardAuthNone        = "none"
	ForwardAuthIDToken     = "id_token"
	ForwardAuthAccessToken = "access_token"
)

// Config holds the middleware configuration.
type Config struct {
	// Required fields
	ProviderURL          string `json:"providerURL"`          // OIDC provider base URL
	ClientID             string `json:"clientID"`             // OAuth 2.0 client ID
	SessionEncryptionKey string `json:"sessionEncryptionKey"` // AES-256 encryption key (32 bytes)

	// Optional fields with defaults
	Audience       string   `json:"audience"`       // OAuth audience (for Auth0 API)
	Scopes         []string `json:"scopes"`         // OAuth scopes (default: openid, profile, email)
	CallbackPath   string   `json:"callbackPath"`   // Callback endpoint (default: /oauth2/callback)
	LogoutPath     string   `json:"logoutPath"`     // Logout endpoint (default: /oauth2/logout)
	CookieName     string   `json:"cookieName"`     // Session cookie name (default: oidc_session)
	CookieSecure   bool     `json:"cookieSecure"`   // HTTPS-only cookies (default: true)
	CookieSameSite string   `json:"cookieSameSite"` // SameSite policy (default: Lax)
	ExcludedPaths  []string `json:"excludedPaths"`  // Paths to skip auth
	ForwardAuth    string   `json:"forwardAuth"`    // Token to forward: "none", "id_token", "access_token" (default: none)
}

// Validate checks that all required configuration fields are present and valid.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.ProviderURL) == "" {
		return errors.New("providerURL is required")
	}

	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("clientID is required")
	}

	if strings.TrimSpace(c.SessionEncryptionKey) == "" {
		return errors.New("sessionEncryptionKey is required")
	}

	if len(c.SessionEncryptionKey) != 32 {
		return errors.New("sessionEncryptionKey must be exactly 32 bytes for AES-256")
	}

	// Validate SameSite value
	sameSite := strings.ToLower(c.CookieSameSite)
	if sameSite != "" && sameSite != "strict" && sameSite != "lax" && sameSite != "none" {
		return errors.New("cookieSameSite must be one of: Strict, Lax, None")
	}

	// Validate ForwardAuth value
	forwardAuth := strings.ToLower(c.ForwardAuth)
	if forwardAuth != "" && forwardAuth != ForwardAuthNone && forwardAuth != ForwardAuthIDToken && forwardAuth != ForwardAuthAccessToken {
		return errors.New("forwardAuth must be one of: none, id_token, access_token")
	}

	// Ensure scopes include openid
	hasOpenID := false
	for _, scope := range c.Scopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID && len(c.Scopes) > 0 {
		c.Scopes = append([]string{"openid"}, c.Scopes...)
	}

	return nil
}

// GetForwardAuth returns the normalized forward auth setting.
func (c *Config) GetForwardAuth() string {
	if c.ForwardAuth == "" {
		return ForwardAuthNone
	}
	return strings.ToLower(c.ForwardAuth)
}

// GetSameSite returns the http.SameSite value based on configuration.
func (c *Config) GetSameSite() int {
	switch strings.ToLower(c.CookieSameSite) {
	case "strict":
		return 4 // http.SameSiteStrictMode
	case "none":
		return 3 // http.SameSiteNoneMode
	default:
		return 2 // http.SameSiteLaxMode
	}
}

// IsPathExcluded checks if a path should be excluded from authentication.
func (c *Config) IsPathExcluded(path string) bool {
	for _, excluded := range c.ExcludedPaths {
		if path == excluded || strings.HasPrefix(path, excluded+"/") {
			return true
		}
	}
	return false
}
