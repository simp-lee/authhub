package authhub

import (
	"context"
	"fmt"
	"time"
)

// Gender represents the gender of a user.
type Gender int

const (
	// GenderUnknown indicates the gender is not known or not specified.
	GenderUnknown Gender = 0
	// GenderMale indicates male.
	GenderMale Gender = 1
	// GenderFemale indicates female.
	GenderFemale Gender = 2
)

// String returns the string representation of the Gender.
func (g Gender) String() string {
	switch g {
	case GenderMale:
		return "male"
	case GenderFemale:
		return "female"
	default:
		return "unknown"
	}
}

// Token represents an OAuth token returned by a provider.
type Token struct {
	// AccessToken is the token used to access protected resources.
	AccessToken string
	// RefreshToken is the token used to obtain a new access token.
	RefreshToken string
	// ExpiresIn is the number of seconds until the access token expires.
	ExpiresIn int
	// ExpiresAt is the absolute time when the access token expires.
	ExpiresAt time.Time
	// OpenID is the user's unique identifier within the provider.
	OpenID string
	// UnionID is the user's unique identifier across multiple apps of the same provider.
	UnionID string
	// Raw contains the raw token response data from the provider.
	Raw map[string]any
}

// IsExpired reports whether the token has expired.
// It returns true when ExpiresAt is the zero value or is not after the current time.
func (t *Token) IsExpired() bool {
	return t.isExpiredAt(time.Now())
}

func (t *Token) isExpiredAt(now time.Time) bool {
	return t.ExpiresAt.IsZero() || !t.ExpiresAt.After(now)
}

// maskToken masks a token string for safe display.
// If s is empty, it returns an empty string.
// If s has 4 or more characters, it returns the first 4 followed by "****".
// If s has fewer than 4 characters, it returns "****" to avoid leaking short values.
func maskToken(s string) string {
	if s == "" {
		return ""
	}
	if len(s) >= 4 {
		return s[:4] + "****"
	}
	return "****"
}

// String returns a sanitized string representation of the Token.
// Access and refresh tokens are masked to avoid exposing sensitive values.
func (t *Token) String() string {
	return fmt.Sprintf("Token{AccessToken:%q, RefreshToken:%q, ExpiresIn:%d, ExpiresAt:%s, OpenID:%q, UnionID:%q}",
		maskToken(t.AccessToken),
		maskToken(t.RefreshToken),
		t.ExpiresIn,
		t.ExpiresAt.Format(time.RFC3339),
		t.OpenID,
		t.UnionID,
	)
}

// UserInfo represents user profile information returned by a provider.
type UserInfo struct {
	// OpenID is the user's unique identifier within the provider.
	OpenID string
	// UnionID is the user's unique identifier across multiple apps of the same provider.
	UnionID string
	// Nickname is the user's display name.
	Nickname string
	// Avatar is the URL to the user's profile picture.
	Avatar string
	// Gender is the user's gender.
	Gender Gender
	// Province is the user's province or state.
	Province string
	// City is the user's city.
	City string
	// Raw contains the raw user info response data from the provider.
	Raw map[string]any
}

// Provider defines the interface that all OAuth providers must implement.
type Provider interface {
	// Name returns the name of the provider (e.g. "github", "wechat").
	Name() string

	// AuthURL returns the authorization URL that the user should be redirected to.
	// The state parameter is used to prevent CSRF attacks.
	AuthURL(state string, opts ...AuthOption) (string, error)

	// ExchangeCode exchanges an authorization code for an access token.
	ExchangeCode(ctx context.Context, code string) (*Token, error)

	// GetUserInfo retrieves the user's profile information using the provided token.
	GetUserInfo(ctx context.Context, token *Token) (*UserInfo, error)

	// RefreshToken refreshes an expired token and returns a new token.
	RefreshToken(ctx context.Context, refreshToken string) (*Token, error)
}
