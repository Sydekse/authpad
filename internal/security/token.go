package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

const TokenBytes = 32

// GenerateOpaqueToken returns a cryptographically secure random token (URL-safe base64).
func GenerateOpaqueToken() (string, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// HashToken returns a SHA-256 hash of the token for storage. We never store raw tokens.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(h[:])
}
