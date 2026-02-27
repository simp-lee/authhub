package authhub

import (
	"errors"
	"fmt"
	"testing"
)

// --- ErrorKind constants ---

func TestErrorKindValues(t *testing.T) {
	tests := []struct {
		kind ErrorKind
		want string
	}{
		{ErrKindNetwork, "network"},
		{ErrKindInvalidCode, "invalid_code"},
		{ErrKindTokenExpired, "token_expired"},
		{ErrKindSignature, "signature"},
		{ErrKindPlatform, "platform"},
		{ErrKindUnsupported, "unsupported"},
		{ErrKindInvalidConfig, "invalid_config"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if string(tt.kind) != tt.want {
				t.Errorf("ErrorKind = %q; want %q", tt.kind, tt.want)
			}
		})
	}
}

// --- AuthError.Error() ---

func TestAuthErrorError(t *testing.T) {
	tests := []struct {
		name string
		err  *AuthError
		want string
	}{
		{
			name: "basic format",
			err:  &AuthError{Kind: ErrKindNetwork, Provider: "github", Message: "connection refused"},
			want: "authhub [github] network: connection refused",
		},
		{
			name: "with code in message",
			err:  &AuthError{Kind: ErrKindInvalidCode, Provider: "wechat_web", Code: "40029", Message: "HTTP 200, POST https://api.weixin.qq.com/sns/...: errcode 40029"},
			want: "authhub [wechat_web] invalid_code: HTTP 200, POST https://api.weixin.qq.com/sns/...: errcode 40029",
		},
		{
			name: "platform error",
			err:  &AuthError{Kind: ErrKindPlatform, Provider: "alipay", Message: "user banned"},
			want: "authhub [alipay] platform: user banned",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q; want %q", got, tt.want)
			}
		})
	}
}

// --- AuthError.Unwrap() ---

func TestAuthErrorUnwrap(t *testing.T) {
	inner := fmt.Errorf("inner error")
	ae := &AuthError{Kind: ErrKindNetwork, Provider: "test", Message: "wrap", Err: inner}
	if got := ae.Unwrap(); got != inner {
		t.Errorf("Unwrap() = %v; want %v", got, inner)
	}

	ae2 := &AuthError{Kind: ErrKindNetwork, Provider: "test", Message: "no wrap"}
	if got := ae2.Unwrap(); got != nil {
		t.Errorf("Unwrap() = %v; want nil", got)
	}
}

// --- errors.Is with sentinel errors ---

func TestErrorsIsWithSentinels(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		sentinel error
		want     bool
	}{
		{
			name:     "ErrNetwork matches kind network",
			err:      &AuthError{Kind: ErrKindNetwork, Provider: "test", Message: "timeout"},
			sentinel: ErrNetwork,
			want:     true,
		},
		{
			name:     "ErrInvalidCode matches kind invalid_code",
			err:      &AuthError{Kind: ErrKindInvalidCode, Provider: "wechat", Message: "bad code"},
			sentinel: ErrInvalidCode,
			want:     true,
		},
		{
			name:     "ErrTokenExpired matches kind token_expired",
			err:      &AuthError{Kind: ErrKindTokenExpired, Provider: "qq", Message: "expired"},
			sentinel: ErrTokenExpired,
			want:     true,
		},
		{
			name:     "ErrSignature matches kind signature",
			err:      &AuthError{Kind: ErrKindSignature, Provider: "alipay", Message: "sig fail"},
			sentinel: ErrSignature,
			want:     true,
		},
		{
			name:     "ErrPlatform matches kind platform",
			err:      &AuthError{Kind: ErrKindPlatform, Provider: "wechat", Message: "banned"},
			sentinel: ErrPlatform,
			want:     true,
		},
		{
			name:     "ErrUnsupported matches kind unsupported",
			err:      &AuthError{Kind: ErrKindUnsupported, Provider: "test", Message: "not impl"},
			sentinel: ErrUnsupported,
			want:     true,
		},
		{
			name:     "ErrInvalidConfig matches kind invalid_config",
			err:      &AuthError{Kind: ErrKindInvalidConfig, Provider: "test", Message: "missing key"},
			sentinel: ErrInvalidConfig,
			want:     true,
		},
		{
			name:     "different kind does not match",
			err:      &AuthError{Kind: ErrKindNetwork, Provider: "test", Message: "timeout"},
			sentinel: ErrInvalidCode,
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errors.Is(tt.err, tt.sentinel); got != tt.want {
				t.Errorf("errors.Is() = %v; want %v", got, tt.want)
			}
		})
	}
}

// --- errors.As extracts *AuthError ---

func TestErrorsAs(t *testing.T) {
	origErr := &AuthError{Kind: ErrKindPlatform, Provider: "wechat", Code: "40226", Message: "user banned"}
	wrapped := fmt.Errorf("outer: %w", origErr)

	var ae *AuthError
	if !errors.As(wrapped, &ae) {
		t.Fatal("errors.As failed to extract *AuthError from wrapped error")
	}
	if ae.Kind != ErrKindPlatform {
		t.Errorf("Kind = %q; want %q", ae.Kind, ErrKindPlatform)
	}
	if ae.Provider != "wechat" {
		t.Errorf("Provider = %q; want %q", ae.Provider, "wechat")
	}
	if ae.Code != "40226" {
		t.Errorf("Code = %q; want %q", ae.Code, "40226")
	}
}

// --- errors.Is through wrapping ---

func TestErrorsIsThroughWrapping(t *testing.T) {
	inner := fmt.Errorf("tcp reset")
	ae := &AuthError{Kind: ErrKindNetwork, Provider: "github", Message: "connection error", Err: inner}
	wrapped := fmt.Errorf("call failed: %w", ae)

	if !errors.Is(wrapped, ErrNetwork) {
		t.Error("errors.Is(wrapped, ErrNetwork) = false; want true")
	}
	if errors.Is(wrapped, ErrInvalidCode) {
		t.Error("errors.Is(wrapped, ErrInvalidCode) = true; want false")
	}
}

// --- newAuthError helper ---

func TestNewAuthError(t *testing.T) {
	inner := fmt.Errorf("raw error")
	ae := newAuthError(ErrKindInvalidCode, "wechat_web", "40029", "invalid code", inner)

	if ae.Kind != ErrKindInvalidCode {
		t.Errorf("Kind = %q; want %q", ae.Kind, ErrKindInvalidCode)
	}
	if ae.Provider != "wechat_web" {
		t.Errorf("Provider = %q; want %q", ae.Provider, "wechat_web")
	}
	if ae.Code != "40029" {
		t.Errorf("Code = %q; want %q", ae.Code, "40029")
	}
	if ae.Message != "invalid code" {
		t.Errorf("Message = %q; want %q", ae.Message, "invalid code")
	}
	if ae.Err != inner {
		t.Errorf("Err = %v; want %v", ae.Err, inner)
	}

	// Should be usable as error and match sentinel
	if !errors.Is(ae, ErrInvalidCode) {
		t.Error("errors.Is(ae, ErrInvalidCode) = false; want true")
	}
}

// --- Sentinel errors are distinct ---

func TestSentinelErrorsAreDistinct(t *testing.T) {
	sentinels := []error{ErrNetwork, ErrInvalidCode, ErrTokenExpired, ErrSignature, ErrPlatform, ErrUnsupported, ErrInvalidConfig}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("errors.Is(sentinels[%d], sentinels[%d]) = true; want false (kinds: %q vs %q)",
					i, j, a.(*AuthError).Kind, b.(*AuthError).Kind)
			}
		}
	}
}
