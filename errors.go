package authhub

import "fmt"

// ErrorKind categorizes the type of error that occurred during an OAuth operation.
type ErrorKind string

const (
	// ErrKindNetwork indicates a network-level error (e.g. connection refused, timeout).
	ErrKindNetwork ErrorKind = "network"
	// ErrKindInvalidCode indicates the authorization code is invalid or the callback parameters failed validation.
	ErrKindInvalidCode ErrorKind = "invalid_code"
	// ErrKindTokenExpired indicates the access or refresh token has expired.
	ErrKindTokenExpired ErrorKind = "token_expired"
	// ErrKindSignature indicates a cryptographic signature verification failure.
	ErrKindSignature ErrorKind = "signature"
	// ErrKindPlatform indicates a platform-specific error returned by the provider.
	ErrKindPlatform ErrorKind = "platform"
	// ErrKindUnsupported indicates the requested operation is not supported by the provider.
	ErrKindUnsupported ErrorKind = "unsupported"
	// ErrKindInvalidConfig indicates the provider configuration is invalid or incomplete.
	ErrKindInvalidConfig ErrorKind = "invalid_config"
)

// AuthError represents a structured error from an OAuth operation.
// It carries the error kind, provider name, optional platform error code,
// a human-readable message, and an optional wrapped error.
type AuthError struct {
	// Kind categorizes the error.
	Kind ErrorKind
	// Provider is the name of the OAuth provider (e.g. "wechat_web", "alipay").
	Provider string
	// Code is an optional platform-specific error code.
	Code string
	// Message is a human-readable description of the error.
	// When an HTTP status code or request URL is available, it is included
	// in sanitized form (e.g. "HTTP 200, POST https://api.weixin.qq.com/sns/...: errcode 40029").
	Message string
	// Err is the underlying error, if any.
	Err error
}

// Error returns the string representation of the error in the format:
//
//	"authhub [provider] kind: message"
func (e *AuthError) Error() string {
	return fmt.Sprintf("authhub [%s] %s: %s", e.Provider, e.Kind, e.Message)
}

// Unwrap returns the underlying error, allowing errors.Unwrap to traverse
// the error chain.
func (e *AuthError) Unwrap() error {
	return e.Err
}

// Is reports whether the target error matches this AuthError by Kind.
// This enables errors.Is to match AuthError values against sentinel errors.
func (e *AuthError) Is(target error) bool {
	if t, ok := target.(*AuthError); ok {
		return e.Kind == t.Kind
	}
	return false
}

// Sentinel errors for use with errors.Is. Each sentinel corresponds to an ErrorKind.
var (
	// ErrNetwork is a sentinel error for network-level failures.
	ErrNetwork = &AuthError{Kind: ErrKindNetwork}
	// ErrInvalidCode is a sentinel error for invalid authorization codes or callback parameters.
	ErrInvalidCode = &AuthError{Kind: ErrKindInvalidCode}
	// ErrTokenExpired is a sentinel error for expired tokens.
	ErrTokenExpired = &AuthError{Kind: ErrKindTokenExpired}
	// ErrSignature is a sentinel error for signature verification failures.
	ErrSignature = &AuthError{Kind: ErrKindSignature}
	// ErrPlatform is a sentinel error for platform-specific errors.
	ErrPlatform = &AuthError{Kind: ErrKindPlatform}
	// ErrUnsupported is a sentinel error for unsupported operations.
	ErrUnsupported = &AuthError{Kind: ErrKindUnsupported}
	// ErrInvalidConfig is a sentinel error for invalid provider configurations.
	ErrInvalidConfig = &AuthError{Kind: ErrKindInvalidConfig}
)

// newAuthError creates a new AuthError with the given parameters.
// It is an internal helper to simplify error construction across providers.
func newAuthError(kind ErrorKind, provider, code, message string, err error) *AuthError {
	return &AuthError{
		Kind:     kind,
		Provider: provider,
		Code:     code,
		Message:  message,
		Err:      err,
	}
}
