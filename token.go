package traefik_oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenResponse represents the response from the token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenError represents an error response from the token endpoint.
type TokenError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// JWTClaims represents the standard JWT claims we extract from tokens.
type JWTClaims struct {
	Subject   string `json:"sub"`
	Email     string `json:"email,omitempty"`
	Name      string `json:"name,omitempty"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
}

// ExchangeCode exchanges an authorization code for tokens using PKCE.
func ExchangeCode(tokenEndpoint, code, codeVerifier, redirectURI, clientID string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("code_verifier", codeVerifier)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)

	return makeTokenRequest(tokenEndpoint, data)
}

// RefreshAccessToken uses a refresh token to obtain a new access token.
func RefreshAccessToken(tokenEndpoint, refreshToken, clientID string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)

	return makeTokenRequest(tokenEndpoint, data)
}

// makeTokenRequest sends a token request to the token endpoint.
func makeTokenRequest(tokenEndpoint string, data url.Values) (*TokenResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var tokenErr TokenError
		if err := json.Unmarshal(body, &tokenErr); err == nil && tokenErr.Error != "" {
			return nil, fmt.Errorf("token error: %s - %s", tokenErr.Error, tokenErr.ErrorDescription)
		}
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// ParseJWTPayload extracts the claims from a JWT without verifying the signature.
// This is safe because tokens are received directly from the IdP's token endpoint
// over HTTPS, which is a trusted server-to-server exchange.
func ParseJWTPayload(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try standard base64 with padding
		payload, err = base64.StdEncoding.DecodeString(addPadding(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
		}
	}

	var claims JWTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return &claims, nil
}

// addPadding adds base64 padding if needed.
func addPadding(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}

// TokenResponseToSession converts a token response to a session.
func TokenResponseToSession(resp *TokenResponse) (*Session, error) {
	session := &Session{
		AccessToken:  resp.AccessToken,
		IDToken:      resp.IDToken,
		RefreshToken: resp.RefreshToken,
		TokenType:    resp.TokenType,
		Claims:       make(map[string]string),
	}

	// Calculate expiry from expires_in or extract from token
	if resp.ExpiresIn > 0 {
		session.Expiry = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	}

	// Try to extract claims from access token
	if claims, err := ParseJWTPayload(resp.AccessToken); err == nil {
		if claims.ExpiresAt > 0 {
			session.Expiry = time.Unix(claims.ExpiresAt, 0)
		}
		if claims.Subject != "" {
			session.Claims["sub"] = claims.Subject
		}
		if claims.Email != "" {
			session.Claims["email"] = claims.Email
		}
		if claims.Name != "" {
			session.Claims["name"] = claims.Name
		}
	}

	// If ID token exists, extract claims from it (usually has more user info)
	if resp.IDToken != "" {
		if claims, err := ParseJWTPayload(resp.IDToken); err == nil {
			if claims.Subject != "" {
				session.Claims["sub"] = claims.Subject
			}
			if claims.Email != "" {
				session.Claims["email"] = claims.Email
			}
			if claims.Name != "" {
				session.Claims["name"] = claims.Name
			}
		}
	}

	// Default expiry if not set
	if session.Expiry.IsZero() {
		session.Expiry = time.Now().Add(time.Hour)
	}

	return session, nil
}
