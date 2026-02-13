package traefik_oidc

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OIDCMiddleware is the main middleware handler.
type OIDCMiddleware struct {
	next     http.Handler
	name     string
	config   *Config
	crypto   *Crypto
	provider *OIDCProvider
}

// ServeHTTP handles the incoming HTTP request.
func (m *OIDCMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionManager := NewSessionManager(
		m.crypto,
		m.config.CookieName,
		m.config.CookieSecure,
		m.config.GetSameSite(),
	)

	// Check if path is excluded from authentication
	if m.config.IsPathExcluded(r.URL.Path) {
		m.next.ServeHTTP(w, r)
		return
	}

	// Handle callback path
	if r.URL.Path == m.config.CallbackPath {
		m.handleCallback(w, r, sessionManager)
		return
	}

	// Handle logout path
	if r.URL.Path == m.config.LogoutPath {
		m.handleLogout(w, r, sessionManager)
		return
	}

	// Check for existing session
	session, err := sessionManager.GetSession(r)
	if err == nil && session != nil {
		// Check if token is expiring soon and we have a refresh token
		if session.IsExpiringSoon(5*time.Minute) && session.RefreshToken != "" {
			newSession, err := m.refreshSession(session)
			if err == nil {
				session = newSession
				if err := sessionManager.SetSession(w, session); err != nil {
					http.Error(w, "Failed to update session", http.StatusInternalServerError)
					return
				}
			}
			// If refresh fails, continue with existing token (might still be valid)
		}

		// Session is valid, forward request with Bearer token
		if !session.IsExpired() {
			if m.config.ForwardIDToken && session.IDToken != "" {
				r.Header.Set("Authorization", "Bearer "+session.IDToken)
			} else if m.config.ForwardAccessToken {
				r.Header.Set("Authorization", "Bearer "+session.AccessToken)
			}
			m.next.ServeHTTP(w, r)
			return
		}
	}

	// No valid session, initiate PKCE auth flow
	m.initiateAuth(w, r, sessionManager)
}

// initiateAuth starts the PKCE authorization flow.
func (m *OIDCMiddleware) initiateAuth(w http.ResponseWriter, r *http.Request, sm *SessionManager) {
	// Generate PKCE parameters
	state, err := GenerateState()
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	codeVerifier, err := GenerateCodeVerifier()
	if err != nil {
		http.Error(w, "Failed to generate code verifier", http.StatusInternalServerError)
		return
	}

	codeChallenge := GenerateCodeChallenge(codeVerifier)

	// Store auth state in cookie
	authState := &AuthState{
		State:        state,
		CodeVerifier: codeVerifier,
		OriginalURL:  m.getFullURL(r),
		Timestamp:    time.Now(),
	}

	if err := sm.SetAuthState(w, authState); err != nil {
		http.Error(w, "Failed to store auth state", http.StatusInternalServerError)
		return
	}

	// Get authorization endpoint
	authEndpoint, err := m.provider.GetAuthorizationEndpoint()
	if err != nil {
		http.Error(w, "Failed to get authorization endpoint", http.StatusInternalServerError)
		return
	}

	// Build authorization URL
	authURL, err := url.Parse(authEndpoint)
	if err != nil {
		http.Error(w, "Invalid authorization endpoint", http.StatusInternalServerError)
		return
	}

	query := authURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", m.config.ClientID)
	query.Set("redirect_uri", m.getRedirectURI(r))
	query.Set("scope", strings.Join(m.config.Scopes, " "))
	query.Set("state", state)
	query.Set("code_challenge", codeChallenge)
	query.Set("code_challenge_method", "S256")
	if m.config.Audience != "" {
		query.Set("audience", m.config.Audience)
	}
	authURL.RawQuery = query.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// handleCallback processes the OAuth callback.
func (m *OIDCMiddleware) handleCallback(w http.ResponseWriter, r *http.Request, sm *SessionManager) {
	// Check for error response
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		// Log detailed error for debugging, but return generic message to client
		log.Printf("OAuth error: %s - %s", errParam, errDesc)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Get authorization code and state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "Missing code or state parameter", http.StatusBadRequest)
		return
	}

	// Retrieve and validate auth state
	authState, err := sm.GetAuthState(r)
	if err != nil {
		http.Error(w, "Invalid or missing auth state", http.StatusBadRequest)
		return
	}

	if authState.State != state {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	if authState.IsExpired() {
		http.Error(w, "Auth state expired", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	tokenEndpoint, err := m.provider.GetTokenEndpoint()
	if err != nil {
		http.Error(w, "Failed to get token endpoint", http.StatusInternalServerError)
		return
	}

	tokenResp, err := ExchangeCode(
		tokenEndpoint,
		code,
		authState.CodeVerifier,
		m.getRedirectURI(r),
		m.config.ClientID,
	)
	if err != nil {
		// Log detailed error for debugging, but return generic message to client
		log.Printf("Token exchange failed: %v", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Create session from token response
	session, err := TokenResponseToSession(tokenResp)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Store session and clear auth state
	if err := sm.SetSession(w, session); err != nil {
		http.Error(w, "Failed to store session", http.StatusInternalServerError)
		return
	}
	sm.ClearAuthState(w)

	// Redirect to original URL (validated to prevent open redirect)
	redirectURL := m.sanitizeRedirectURL(authState.OriginalURL, r)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleLogout clears the session.
func (m *OIDCMiddleware) handleLogout(w http.ResponseWriter, r *http.Request, sm *SessionManager) {
	sm.ClearSession(w)
	sm.ClearAuthState(w)

	// Check for post-logout redirect (validated to prevent open redirect)
	redirectURL := m.sanitizeRedirectURL(r.URL.Query().Get("redirect_uri"), r)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// refreshSession attempts to refresh the access token.
func (m *OIDCMiddleware) refreshSession(session *Session) (*Session, error) {
	tokenEndpoint, err := m.provider.GetTokenEndpoint()
	if err != nil {
		return nil, err
	}

	tokenResp, err := RefreshAccessToken(tokenEndpoint, session.RefreshToken, m.config.ClientID)
	if err != nil {
		return nil, err
	}

	newSession, err := TokenResponseToSession(tokenResp)
	if err != nil {
		return nil, err
	}

	// Preserve refresh token if not returned in response
	if newSession.RefreshToken == "" {
		newSession.RefreshToken = session.RefreshToken
	}

	return newSession, nil
}

// getFullURL returns the full URL of the request.
func (m *OIDCMiddleware) getFullURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		// Check X-Forwarded-Proto header
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else if !m.config.CookieSecure {
			scheme = "http"
		}
	}

	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, r.RequestURI)
}

// getRedirectURI returns the callback URL for OAuth.
func (m *OIDCMiddleware) getRedirectURI(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else if !m.config.CookieSecure {
			scheme = "http"
		}
	}

	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, m.config.CallbackPath)
}

// getRequestHost returns the host for the current request, considering X-Forwarded-Host.
func (m *OIDCMiddleware) getRequestHost(r *http.Request) string {
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		return fwdHost
	}
	return r.Host
}

// isSameOrigin checks if the given URL is same-origin with the current request.
// This prevents open redirect vulnerabilities by ensuring redirects stay within
// the same host.
func (m *OIDCMiddleware) isSameOrigin(redirectURL string, r *http.Request) bool {
	// Allow relative URLs (paths only)
	if strings.HasPrefix(redirectURL, "/") && !strings.HasPrefix(redirectURL, "//") {
		return true
	}

	parsed, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}

	// Reject URLs without scheme or with different scheme protocol
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	// Get the current request's host
	requestHost := m.getRequestHost(r)

	// Compare hosts (case-insensitive)
	return strings.EqualFold(parsed.Host, requestHost)
}

// sanitizeRedirectURL validates and sanitizes a redirect URL.
// Returns "/" if the URL is invalid or not same-origin.
func (m *OIDCMiddleware) sanitizeRedirectURL(redirectURL string, r *http.Request) string {
	if redirectURL == "" {
		return "/"
	}

	if !m.isSameOrigin(redirectURL, r) {
		return "/"
	}

	return redirectURL
}
