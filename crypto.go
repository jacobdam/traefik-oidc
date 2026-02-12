package traefik_oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// Crypto handles AES-GCM encryption and decryption for session data.
type Crypto struct {
	gcm cipher.AEAD
}

// NewCrypto creates a new Crypto instance with the given 32-byte key.
func NewCrypto(key string) (*Crypto, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Crypto{gcm: gcm}, nil
}

// Encrypt encrypts plaintext using AES-GCM and returns base64url-encoded ciphertext.
func (c *Crypto) Encrypt(plaintext []byte) (string, error) {
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := c.gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decodes base64url-encoded ciphertext and decrypts it using AES-GCM.
func (c *Crypto) Decrypt(encoded string) ([]byte, error) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	nonceSize := c.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return c.gcm.Open(nil, nonce, ciphertext, nil)
}

// GenerateRandomBytes generates cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRandomString generates a cryptographically secure random string
// encoded in base64url format.
func GenerateRandomString(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
