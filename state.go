package authhub

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// GenerateState generates a cryptographically random state string for use
// as a CSRF token in OAuth authorization flows. It returns a 43-character
// base64url-encoded (no padding) string derived from 32 random bytes.
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidateState performs a timing-safe comparison of two state strings.
// It returns nil if they match, or an AuthError with Kind ErrKindInvalidCode
// if either value is empty or the values do not match.
func ValidateState(expected, actual string) error {
	if expected == "" || actual == "" {
		return &AuthError{
			Kind:    ErrKindInvalidCode,
			Message: "state: expected and actual must not be empty",
		}
	}
	expectedHash := sha256.Sum256([]byte(expected))
	actualHash := sha256.Sum256([]byte(actual))
	if subtle.ConstantTimeCompare(expectedHash[:], actualHash[:]) != 1 {
		return &AuthError{
			Kind:    ErrKindInvalidCode,
			Message: "state mismatch",
		}
	}
	return nil
}
