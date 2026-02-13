package traefik_oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCreateConfig(t *testing.T) {
	config := CreateConfig()

	if config.CallbackPath != "/oauth2/callback" {
		t.Errorf("Expected CallbackPath to be /oauth2/callback, got %s", config.CallbackPath)
	}

	if config.LogoutPath != "/oauth2/logout" {
		t.Errorf("Expected LogoutPath to be /oauth2/logout, got %s", config.LogoutPath)
	}

	if config.CookieName != "oidc_session" {
		t.Errorf("Expected CookieName to be oidc_session, got %s", config.CookieName)
	}

	if !config.CookieSecure {
		t.Error("Expected CookieSecure to be true by default")
	}

	if !config.ForwardAccessToken {
		t.Error("Expected ForwardAccessToken to be true by default")
	}

	if len(config.Scopes) != 3 || config.Scopes[0] != "openid" {
		t.Errorf("Expected default scopes to be [openid, profile, email], got %v", config.Scopes)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &Config{
				ProviderURL:          "https://accounts.google.com",
				ClientID:             "test-client",
				SessionEncryptionKey: "01234567890123456789012345678901",
				Scopes:               []string{"openid"},
			},
			expectError: false,
		},
		{
			name: "missing providerURL",
			config: &Config{
				ClientID:             "test-client",
				SessionEncryptionKey: "01234567890123456789012345678901",
			},
			expectError: true,
			errorMsg:    "providerURL is required",
		},
		{
			name: "missing clientID",
			config: &Config{
				ProviderURL:          "https://accounts.google.com",
				SessionEncryptionKey: "01234567890123456789012345678901",
			},
			expectError: true,
			errorMsg:    "clientID is required",
		},
		{
			name: "missing encryption key",
			config: &Config{
				ProviderURL: "https://accounts.google.com",
				ClientID:    "test-client",
			},
			expectError: true,
			errorMsg:    "sessionEncryptionKey is required",
		},
		{
			name: "invalid encryption key length",
			config: &Config{
				ProviderURL:          "https://accounts.google.com",
				ClientID:             "test-client",
				SessionEncryptionKey: "short",
			},
			expectError: true,
			errorMsg:    "sessionEncryptionKey must be exactly 32 bytes",
		},
		{
			name: "invalid sameSite",
			config: &Config{
				ProviderURL:          "https://accounts.google.com",
				ClientID:             "test-client",
				SessionEncryptionKey: "01234567890123456789012345678901",
				CookieSameSite:       "invalid",
			},
			expectError: true,
			errorMsg:    "cookieSameSite must be one of",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestConfigIsPathExcluded(t *testing.T) {
	config := &Config{
		ExcludedPaths: []string{"/health", "/metrics", "/api/public"},
	}

	tests := []struct {
		path     string
		excluded bool
	}{
		{"/health", true},
		{"/health/ready", true},
		{"/metrics", true},
		{"/api/public", true},
		{"/api/public/data", true},
		{"/api/private", false},
		{"/", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if config.IsPathExcluded(tt.path) != tt.excluded {
				t.Errorf("IsPathExcluded(%s) = %v, want %v", tt.path, !tt.excluded, tt.excluded)
			}
		})
	}
}

func TestCrypto(t *testing.T) {
	key := "01234567890123456789012345678901" // 32 bytes
	crypto, err := NewCrypto(key)
	if err != nil {
		t.Fatalf("Failed to create crypto: %v", err)
	}

	plaintext := []byte("test data to encrypt")

	encrypted, err := crypto.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if encrypted == string(plaintext) {
		t.Error("Encrypted data should not equal plaintext")
	}

	decrypted, err := crypto.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted data does not match original: got %s, want %s", decrypted, plaintext)
	}
}

func TestCryptoInvalidKey(t *testing.T) {
	_, err := NewCrypto("short")
	if err == nil {
		t.Error("Expected error for short key")
	}
}

func TestGenerateRandomString(t *testing.T) {
	s1, err := GenerateRandomString(32)
	if err != nil {
		t.Fatalf("Failed to generate random string: %v", err)
	}

	s2, err := GenerateRandomString(32)
	if err != nil {
		t.Fatalf("Failed to generate random string: %v", err)
	}

	if s1 == s2 {
		t.Error("Two random strings should not be equal")
	}

	if len(s1) == 0 {
		t.Error("Random string should not be empty")
	}
}

func TestPKCE(t *testing.T) {
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("Failed to generate code verifier: %v", err)
	}

	if len(verifier) == 0 {
		t.Error("Code verifier should not be empty")
	}

	challenge := GenerateCodeChallenge(verifier)
	if len(challenge) == 0 {
		t.Error("Code challenge should not be empty")
	}

	// Same verifier should produce same challenge
	challenge2 := GenerateCodeChallenge(verifier)
	if challenge != challenge2 {
		t.Error("Same verifier should produce same challenge")
	}
}

func TestGenerateState(t *testing.T) {
	state1, err := GenerateState()
	if err != nil {
		t.Fatalf("Failed to generate state: %v", err)
	}

	state2, err := GenerateState()
	if err != nil {
		t.Fatalf("Failed to generate state: %v", err)
	}

	if state1 == state2 {
		t.Error("Two state values should not be equal")
	}
}

func TestParseJWTPayload(t *testing.T) {
	// Create a test JWT (header.payload.signature)
	// This is a mock JWT - in reality the signature would be valid
	payload := `{"sub":"1234567890","email":"test@example.com","exp":1893456000}`
	encoded := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiZXhwIjoxODkzNDU2MDAwfQ." +
		"signature"

	claims, err := ParseJWTPayload(encoded)
	if err != nil {
		t.Fatalf("Failed to parse JWT: %v", err)
	}

	if claims.Subject != "1234567890" {
		t.Errorf("Expected subject '1234567890', got '%s'", claims.Subject)
	}

	if claims.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", claims.Email)
	}

	if claims.ExpiresAt != 1893456000 {
		t.Errorf("Expected exp 1893456000, got %d", claims.ExpiresAt)
	}

	_ = payload // suppress unused warning
}

func TestParseJWTPayloadInvalid(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"single part", "header"},
		{"two parts", "header.payload"},
		{"invalid base64", "header.!!!invalid!!!.signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseJWTPayload(tt.token)
			if err == nil {
				t.Error("Expected error for invalid JWT")
			}
		})
	}
}

func TestSessionExpiry(t *testing.T) {
	session := &Session{
		AccessToken: "test-token",
		Expiry:      time.Now().Add(-time.Hour),
	}

	if !session.IsExpired() {
		t.Error("Session should be expired")
	}

	session.Expiry = time.Now().Add(time.Hour)
	if session.IsExpired() {
		t.Error("Session should not be expired")
	}
}

func TestSessionIsExpiringSoon(t *testing.T) {
	session := &Session{
		AccessToken: "test-token",
		Expiry:      time.Now().Add(3 * time.Minute),
	}

	if !session.IsExpiringSoon(5 * time.Minute) {
		t.Error("Session expiring in 3 minutes should be expiring soon (within 5 minutes)")
	}

	if session.IsExpiringSoon(1 * time.Minute) {
		t.Error("Session expiring in 3 minutes should not be expiring soon (within 1 minute)")
	}
}

func TestAuthStateExpiry(t *testing.T) {
	state := &AuthState{
		State:     "test-state",
		Timestamp: time.Now().Add(-10 * time.Minute),
	}

	if !state.IsExpired() {
		t.Error("Auth state older than 5 minutes should be expired")
	}

	state.Timestamp = time.Now()
	if state.IsExpired() {
		t.Error("Fresh auth state should not be expired")
	}
}

func TestSessionManagerRoundTrip(t *testing.T) {
	key := "01234567890123456789012345678901"
	crypto, err := NewCrypto(key)
	if err != nil {
		t.Fatalf("Failed to create crypto: %v", err)
	}

	sm := NewSessionManager(crypto, "test_session", false, 2)

	session := &Session{
		AccessToken:  "access-token-123",
		RefreshToken: "refresh-token-456",
		IDToken:      "id-token-789",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
		Claims:       map[string]string{"sub": "user123"},
	}

	// Test SetSession and GetSession
	recorder := httptest.NewRecorder()
	if err := sm.SetSession(recorder, session); err != nil {
		t.Fatalf("Failed to set session: %v", err)
	}

	// Create request with the session cookie
	req := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range recorder.Result().Cookies() {
		req.AddCookie(cookie)
	}

	retrievedSession, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	if retrievedSession.AccessToken != session.AccessToken {
		t.Errorf("AccessToken mismatch: got %s, want %s", retrievedSession.AccessToken, session.AccessToken)
	}

	if retrievedSession.RefreshToken != session.RefreshToken {
		t.Errorf("RefreshToken mismatch: got %s, want %s", retrievedSession.RefreshToken, session.RefreshToken)
	}

	if retrievedSession.Claims["sub"] != "user123" {
		t.Errorf("Claims mismatch: got %v, want sub=user123", retrievedSession.Claims)
	}
}

func TestAuthStateRoundTrip(t *testing.T) {
	key := "01234567890123456789012345678901"
	crypto, err := NewCrypto(key)
	if err != nil {
		t.Fatalf("Failed to create crypto: %v", err)
	}

	sm := NewSessionManager(crypto, "test_session", false, 2)

	authState := &AuthState{
		State:        "state-123",
		CodeVerifier: "verifier-456",
		OriginalURL:  "https://example.com/page",
		Timestamp:    time.Now(),
	}

	recorder := httptest.NewRecorder()
	if err := sm.SetAuthState(recorder, authState); err != nil {
		t.Fatalf("Failed to set auth state: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range recorder.Result().Cookies() {
		req.AddCookie(cookie)
	}

	retrievedState, err := sm.GetAuthState(req)
	if err != nil {
		t.Fatalf("Failed to get auth state: %v", err)
	}

	if retrievedState.State != authState.State {
		t.Errorf("State mismatch: got %s, want %s", retrievedState.State, authState.State)
	}

	if retrievedState.CodeVerifier != authState.CodeVerifier {
		t.Errorf("CodeVerifier mismatch: got %s, want %s", retrievedState.CodeVerifier, authState.CodeVerifier)
	}

	if retrievedState.OriginalURL != authState.OriginalURL {
		t.Errorf("OriginalURL mismatch: got %s, want %s", retrievedState.OriginalURL, authState.OriginalURL)
	}
}

func TestNewMiddleware(t *testing.T) {
	config := &Config{
		ProviderURL:          "https://accounts.google.com",
		ClientID:             "test-client",
		SessionEncryptionKey: "01234567890123456789012345678901",
		Scopes:               []string{"openid"},
		CallbackPath:         "/oauth2/callback",
		LogoutPath:           "/oauth2/logout",
		CookieName:           "oidc_session",
		CookieSameSite:       "Lax",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware, err := New(context.Background(), next, config, "test")
	if err != nil {
		t.Fatalf("Failed to create middleware: %v", err)
	}

	if middleware == nil {
		t.Error("Middleware should not be nil")
	}
}

func TestNewMiddlewareInvalidConfig(t *testing.T) {
	config := &Config{
		ProviderURL: "", // Missing required field
		ClientID:    "test-client",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	_, err := New(context.Background(), next, config, "test")
	if err == nil {
		t.Error("Expected error for invalid config")
	}
}

func TestMiddlewareExcludedPath(t *testing.T) {
	config := &Config{
		ProviderURL:          "https://accounts.google.com",
		ClientID:             "test-client",
		SessionEncryptionKey: "01234567890123456789012345678901",
		Scopes:               []string{"openid"},
		CallbackPath:         "/oauth2/callback",
		LogoutPath:           "/oauth2/logout",
		CookieName:           "oidc_session",
		CookieSameSite:       "Lax",
		ExcludedPaths:        []string{"/health"},
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware, err := New(context.Background(), next, config, "test")
	if err != nil {
		t.Fatalf("Failed to create middleware: %v", err)
	}

	req := httptest.NewRequest("GET", "/health", nil)
	recorder := httptest.NewRecorder()

	middleware.ServeHTTP(recorder, req)

	if !nextCalled {
		t.Error("Next handler should be called for excluded path")
	}

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}
}

func TestTokenResponseToSession(t *testing.T) {
	// Create a mock token response with a valid JWT-like access token
	tokenResp := &TokenResponse{
		AccessToken:  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiZXhwIjoxODkzNDU2MDAwfQ.signature",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "refresh-token",
		IDToken:      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwibmFtZSI6IlRlc3QgVXNlciJ9.signature",
	}

	session, err := TokenResponseToSession(tokenResp)
	if err != nil {
		t.Fatalf("Failed to convert token response: %v", err)
	}

	if session.AccessToken != tokenResp.AccessToken {
		t.Error("AccessToken mismatch")
	}

	if session.RefreshToken != tokenResp.RefreshToken {
		t.Error("RefreshToken mismatch")
	}

	if session.Claims["sub"] != "1234567890" {
		t.Errorf("Expected sub claim '1234567890', got '%s'", session.Claims["sub"])
	}

	if session.Claims["email"] != "test@example.com" {
		t.Errorf("Expected email claim 'test@example.com', got '%s'", session.Claims["email"])
	}
}

// Mock OIDC provider server for testing
func setupMockOIDCServer() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		config := map[string]interface{}{
			"issuer":                 "https://mock-provider.example.com",
			"authorization_endpoint": "https://mock-provider.example.com/authorize",
			"token_endpoint":         "https://mock-provider.example.com/token",
			"userinfo_endpoint":      "https://mock-provider.example.com/userinfo",
		}
		json.NewEncoder(w).Encode(config)
	})

	return httptest.NewServer(mux)
}

func TestOIDCProviderDiscovery(t *testing.T) {
	server := setupMockOIDCServer()
	defer server.Close()

	provider := NewOIDCProvider(server.URL)

	config, err := provider.GetConfig()
	if err != nil {
		t.Fatalf("Failed to get OIDC config: %v", err)
	}

	if config.AuthorizationEndpoint != "https://mock-provider.example.com/authorize" {
		t.Errorf("Expected authorization_endpoint, got %s", config.AuthorizationEndpoint)
	}

	if config.TokenEndpoint != "https://mock-provider.example.com/token" {
		t.Errorf("Expected token_endpoint, got %s", config.TokenEndpoint)
	}
}

func TestOIDCProviderCaching(t *testing.T) {
	callCount := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		config := map[string]interface{}{
			"issuer":                 "https://mock-provider.example.com",
			"authorization_endpoint": "https://mock-provider.example.com/authorize",
			"token_endpoint":         "https://mock-provider.example.com/token",
		}
		json.NewEncoder(w).Encode(config)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	provider := NewOIDCProvider(server.URL)

	// First call should fetch
	_, err := provider.GetConfig()
	if err != nil {
		t.Fatalf("First GetConfig failed: %v", err)
	}

	// Second call should use cache
	_, err = provider.GetConfig()
	if err != nil {
		t.Fatalf("Second GetConfig failed: %v", err)
	}

	if callCount != 1 {
		t.Errorf("Expected 1 discovery call, got %d", callCount)
	}
}

func TestIsSameOrigin(t *testing.T) {
	server := setupMockOIDCServer()
	defer server.Close()

	config := &Config{
		ProviderURL:          server.URL,
		ClientID:             "test-client",
		SessionEncryptionKey: "01234567890123456789012345678901",
		Scopes:               []string{"openid"},
		CallbackPath:         "/oauth2/callback",
		LogoutPath:           "/oauth2/logout",
		CookieName:           "oidc_session",
		CookieSameSite:       "Lax",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware, err := New(context.Background(), next, config, "test")
	if err != nil {
		t.Fatalf("Failed to create middleware: %v", err)
	}

	m := middleware.(*OIDCMiddleware)

	tests := []struct {
		name        string
		redirectURL string
		host        string
		fwdHost     string
		expected    bool
	}{
		// Relative URLs should be allowed
		{"relative path", "/dashboard", "example.com", "", true},
		{"relative path with query", "/page?foo=bar", "example.com", "", true},
		{"root path", "/", "example.com", "", true},

		// Protocol-relative URLs should be rejected (potential bypass)
		{"protocol relative URL", "//evil.com/path", "example.com", "", false},

		// Same-origin absolute URLs should be allowed
		{"same origin https", "https://example.com/dashboard", "example.com", "", true},
		{"same origin http", "http://example.com/dashboard", "example.com", "", true},
		{"same origin case insensitive", "https://EXAMPLE.COM/dashboard", "example.com", "", true},

		// Different origin URLs should be rejected
		{"different host", "https://evil.com/dashboard", "example.com", "", false},
		{"subdomain", "https://sub.example.com/dashboard", "example.com", "", false},
		{"different port", "https://example.com:8080/dashboard", "example.com", "", false},

		// X-Forwarded-Host should be respected
		{"same origin with forwarded host", "https://app.example.com/dashboard", "internal.local", "app.example.com", true},
		{"different origin with forwarded host", "https://evil.com/dashboard", "internal.local", "app.example.com", false},

		// Non-http(s) schemes should be rejected
		{"javascript scheme", "javascript:alert(1)", "example.com", "", false},
		{"data scheme", "data:text/html,<script>alert(1)</script>", "example.com", "", false},
		{"file scheme", "file:///etc/passwd", "example.com", "", false},

		// Empty and malformed URLs
		{"empty URL", "", "example.com", "", false},
		{"malformed URL", "://invalid", "example.com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			if tt.fwdHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.fwdHost)
			}

			result := m.isSameOrigin(tt.redirectURL, req)
			if result != tt.expected {
				t.Errorf("isSameOrigin(%q) with host %q = %v, want %v",
					tt.redirectURL, tt.host, result, tt.expected)
			}
		})
	}
}

func TestSanitizeRedirectURL(t *testing.T) {
	server := setupMockOIDCServer()
	defer server.Close()

	config := &Config{
		ProviderURL:          server.URL,
		ClientID:             "test-client",
		SessionEncryptionKey: "01234567890123456789012345678901",
		Scopes:               []string{"openid"},
		CallbackPath:         "/oauth2/callback",
		LogoutPath:           "/oauth2/logout",
		CookieName:           "oidc_session",
		CookieSameSite:       "Lax",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware, err := New(context.Background(), next, config, "test")
	if err != nil {
		t.Fatalf("Failed to create middleware: %v", err)
	}

	m := middleware.(*OIDCMiddleware)

	tests := []struct {
		name        string
		redirectURL string
		host        string
		expected    string
	}{
		{"empty URL returns root", "", "example.com", "/"},
		{"valid relative path", "/dashboard", "example.com", "/dashboard"},
		{"valid same-origin absolute", "https://example.com/page", "example.com", "https://example.com/page"},
		{"malicious URL returns root", "https://evil.com/phish", "example.com", "/"},
		{"javascript URL returns root", "javascript:alert(1)", "example.com", "/"},
		{"protocol-relative returns root", "//evil.com/path", "example.com", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host

			result := m.sanitizeRedirectURL(tt.redirectURL, req)
			if result != tt.expected {
				t.Errorf("sanitizeRedirectURL(%q) = %q, want %q",
					tt.redirectURL, result, tt.expected)
			}
		})
	}
}

func TestLogoutOpenRedirectPrevention(t *testing.T) {
	server := setupMockOIDCServer()
	defer server.Close()

	config := &Config{
		ProviderURL:          server.URL,
		ClientID:             "test-client",
		SessionEncryptionKey: "01234567890123456789012345678901",
		Scopes:               []string{"openid"},
		CallbackPath:         "/oauth2/callback",
		LogoutPath:           "/oauth2/logout",
		CookieName:           "oidc_session",
		CookieSameSite:       "Lax",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware, err := New(context.Background(), next, config, "test")
	if err != nil {
		t.Fatalf("Failed to create middleware: %v", err)
	}

	tests := []struct {
		name             string
		redirectURI      string
		expectedLocation string
	}{
		{"no redirect param", "", "/"},
		{"valid relative path", "/home", "/home"},
		{"malicious external URL", "https://evil.com/phish", "/"},
		{"javascript injection", "javascript:alert(document.cookie)", "/"},
		{"protocol-relative URL", "//evil.com/steal", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := "/oauth2/logout"
			if tt.redirectURI != "" {
				path += "?redirect_uri=" + tt.redirectURI
			}
			req := httptest.NewRequest("GET", path, nil)
			req.Host = "example.com"

			recorder := httptest.NewRecorder()
			middleware.ServeHTTP(recorder, req)

			if recorder.Code != http.StatusFound {
				t.Errorf("Expected status 302, got %d", recorder.Code)
			}

			location := recorder.Header().Get("Location")
			if location != tt.expectedLocation {
				t.Errorf("Expected redirect to %q, got %q", tt.expectedLocation, location)
			}
		})
	}
}
