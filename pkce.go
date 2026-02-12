package traefik_oidc

import (
	"crypto/sha256"
	"encoding/base64"
)

// GenerateCodeVerifier generates a cryptographically random code verifier
// for PKCE. It generates 64 random bytes and encodes them in base64url format.
func GenerateCodeVerifier() (string, error) {
	return GenerateRandomString(64)
}

// GenerateCodeChallenge generates a code challenge from a code verifier
// using the S256 method (SHA256 hash, base64url encoded).
func GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// GenerateState generates a cryptographically random state parameter
// for CSRF protection. It generates 32 random bytes.
func GenerateState() (string, error) {
	return GenerateRandomString(32)
}
