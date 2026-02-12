package traefik_oidc

import (
	"encoding/json"
	"net/http"
	"time"
)

// Session holds the authenticated user's session data.
type Session struct {
	AccessToken  string            `json:"access_token"`
	IDToken      string            `json:"id_token,omitempty"`
	RefreshToken string            `json:"refresh_token,omitempty"`
	TokenType    string            `json:"token_type"`
	Expiry       time.Time         `json:"expiry"`
	Claims       map[string]string `json:"claims,omitempty"`
}

// IsExpired checks if the session's access token has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.Expiry)
}

// IsExpiringSoon checks if the session's access token will expire within the given duration.
func (s *Session) IsExpiringSoon(within time.Duration) bool {
	return time.Now().Add(within).After(s.Expiry)
}

// AuthState holds the PKCE authentication state during the OAuth flow.
type AuthState struct {
	State        string    `json:"state"`
	CodeVerifier string    `json:"code_verifier"`
	OriginalURL  string    `json:"original_url"`
	Timestamp    time.Time `json:"timestamp"`
}

// IsExpired checks if the auth state has expired (5 minute timeout).
func (a *AuthState) IsExpired() bool {
	return time.Now().After(a.Timestamp.Add(5 * time.Minute))
}

// SessionManager handles session and auth state cookie operations.
type SessionManager struct {
	crypto         *Crypto
	cookieName     string
	authCookieName string
	secure         bool
	sameSite       int
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager(crypto *Crypto, cookieName string, secure bool, sameSite int) *SessionManager {
	return &SessionManager{
		crypto:         crypto,
		cookieName:     cookieName,
		authCookieName: cookieName + "_auth",
		secure:         secure,
		sameSite:       sameSite,
	}
}

// GetSession retrieves and decrypts the session from the request cookie.
func (sm *SessionManager) GetSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sm.cookieName)
	if err != nil {
		return nil, err
	}

	data, err := sm.crypto.Decrypt(cookie.Value)
	if err != nil {
		return nil, err
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

// SetSession encrypts and sets the session cookie.
func (sm *SessionManager) SetSession(w http.ResponseWriter, session *Session) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	encrypted, err := sm.crypto.Encrypt(data)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sm.cookieName,
		Value:    encrypted,
		Path:     "/",
		Secure:   sm.secure,
		HttpOnly: true,
		SameSite: http.SameSite(sm.sameSite),
		MaxAge:   86400 * 7, // 7 days
	})

	return nil
}

// ClearSession removes the session cookie.
func (sm *SessionManager) ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sm.cookieName,
		Value:    "",
		Path:     "/",
		Secure:   sm.secure,
		HttpOnly: true,
		SameSite: http.SameSite(sm.sameSite),
		MaxAge:   -1,
	})
}

// GetAuthState retrieves and decrypts the auth state from the request cookie.
func (sm *SessionManager) GetAuthState(r *http.Request) (*AuthState, error) {
	cookie, err := r.Cookie(sm.authCookieName)
	if err != nil {
		return nil, err
	}

	data, err := sm.crypto.Decrypt(cookie.Value)
	if err != nil {
		return nil, err
	}

	var state AuthState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	return &state, nil
}

// SetAuthState encrypts and sets the auth state cookie.
func (sm *SessionManager) SetAuthState(w http.ResponseWriter, state *AuthState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}

	encrypted, err := sm.crypto.Encrypt(data)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sm.authCookieName,
		Value:    encrypted,
		Path:     "/",
		Secure:   sm.secure,
		HttpOnly: true,
		SameSite: http.SameSite(sm.sameSite),
		MaxAge:   300, // 5 minutes
	})

	return nil
}

// ClearAuthState removes the auth state cookie.
func (sm *SessionManager) ClearAuthState(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sm.authCookieName,
		Value:    "",
		Path:     "/",
		Secure:   sm.secure,
		HttpOnly: true,
		SameSite: http.SameSite(sm.sameSite),
		MaxAge:   -1,
	})
}
