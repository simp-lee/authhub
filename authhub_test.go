package authhub

import (
	"strings"
	"testing"
	"time"
)

// --- Gender tests ---

func TestGenderString(t *testing.T) {
	tests := []struct {
		name   string
		gender Gender
		want   string
	}{
		{"unknown", GenderUnknown, "unknown"},
		{"male", GenderMale, "male"},
		{"female", GenderFemale, "female"},
		{"out of range", Gender(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.gender.String(); got != tt.want {
				t.Errorf("Gender(%d).String() = %q; want %q", tt.gender, got, tt.want)
			}
		})
	}
}

func TestGenderConstants(t *testing.T) {
	if GenderUnknown != 0 {
		t.Errorf("GenderUnknown = %d; want 0", GenderUnknown)
	}
	if GenderMale != 1 {
		t.Errorf("GenderMale = %d; want 1", GenderMale)
	}
	if GenderFemale != 2 {
		t.Errorf("GenderFemale = %d; want 2", GenderFemale)
	}
}

// --- Token tests ---

func TestTokenIsExpired(t *testing.T) {
	tests := []struct {
		name string
		tok  Token
		want bool
	}{
		{
			name: "zero ExpiresAt is expired",
			tok:  Token{},
			want: true,
		},
		{
			name: "past ExpiresAt is expired",
			tok:  Token{ExpiresAt: time.Now().Add(-1 * time.Hour)},
			want: true,
		},
		{
			name: "future ExpiresAt is not expired",
			tok:  Token{ExpiresAt: time.Now().Add(1 * time.Hour)},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tok.IsExpired(); got != tt.want {
				t.Errorf("Token.IsExpired() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestTokenIsExpiredAt(t *testing.T) {
	now := time.Date(2026, 2, 27, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		tok  Token
		want bool
	}{
		{
			name: "zero ExpiresAt is expired",
			tok:  Token{},
			want: true,
		},
		{
			name: "past ExpiresAt is expired",
			tok:  Token{ExpiresAt: now.Add(-1 * time.Second)},
			want: true,
		},
		{
			name: "equal ExpiresAt is expired",
			tok:  Token{ExpiresAt: now},
			want: true,
		},
		{
			name: "future ExpiresAt is not expired",
			tok:  Token{ExpiresAt: now.Add(1 * time.Second)},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tok.isExpiredAt(now); got != tt.want {
				t.Errorf("Token.isExpiredAt() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestTokenString(t *testing.T) {
	tests := []struct {
		name         string
		tok          Token
		wantContains []string
		wantExcludes []string
	}{
		{
			name: "masks long tokens",
			tok: Token{
				AccessToken:  "abcdefghijklmnop",
				RefreshToken: "1234567890abcdef",
			},
			wantContains: []string{"abcd****", "1234****"},
			wantExcludes: []string{"abcdefghijklmnop", "1234567890abcdef"},
		},
		{
			name: "short access token masked",
			tok: Token{
				AccessToken:  "ab",
				RefreshToken: "",
			},
			wantContains: []string{"****"},
			wantExcludes: []string{"ab****"},
		},
		{
			name: "empty tokens",
			tok:  Token{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tok.String()
			for _, c := range tt.wantContains {
				if !strings.Contains(got, c) {
					t.Errorf("Token.String() = %q; want it to contain %q", got, c)
				}
			}
			for _, e := range tt.wantExcludes {
				if strings.Contains(got, e) {
					t.Errorf("Token.String() = %q; should NOT contain full token %q", got, e)
				}
			}
		})
	}
}

func TestTokenStringFormat(t *testing.T) {
	tok := Token{
		AccessToken: "abcdefgh",
		OpenID:      "open123",
	}
	s := tok.String()
	for _, want := range []string{"Token{", "AccessToken:", "RefreshToken:", "OpenID:"} {
		if !strings.Contains(s, want) {
			t.Errorf("Token.String() = %q; want it to contain %q", s, want)
		}
	}
}
