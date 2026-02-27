package authhub

import (
	"net/http"
	"strings"
)

// Logger defines the interface for structured logging used by providers.
// Implementations should treat args as key-value pairs (e.g. "key1", val1, "key2", val2).
type Logger interface {
	// Debug logs a message at debug level.
	Debug(msg string, args ...any)
	// Info logs a message at info level.
	Info(msg string, args ...any)
	// Warn logs a message at warn level.
	Warn(msg string, args ...any)
	// Error logs a message at error level.
	Error(msg string, args ...any)
}

// noopLogger is a Logger that discards all log messages.
type noopLogger struct{}

func (n *noopLogger) Debug(msg string, args ...any) {}
func (n *noopLogger) Info(msg string, args ...any)  {}
func (n *noopLogger) Warn(msg string, args ...any)  {}
func (n *noopLogger) Error(msg string, args ...any) {}

// Option is a functional option for configuring a provider.
type Option func(*providerConfig)

// providerConfig holds common configuration for all providers.
type providerConfig struct {
	httpClient         *http.Client
	logger             Logger
	wechatCheckBaseURL string // internal: used by CheckWechatToken tests to override the API base URL
	lang               string // language preference for user info responses (e.g. "zh_CN", "en", "zh_TW")

	// Alipay-specific options
	alipayPublicKey string // raw public key for non-cert mode
	alipayAppCert   string // app certificate PEM content (cert mode)
	alipayCert      string // alipay certificate PEM content (cert mode)
	alipayRootCert  string // root certificate PEM content (cert mode)
	alipayCertMode  bool   // true if cert mode is enabled
	alipaySandbox   bool   // true if sandbox mode is enabled
}

// newProviderConfig creates a new providerConfig with sensible defaults
// and applies the given options.
func newProviderConfig(opts ...Option) *providerConfig {
	cfg := &providerConfig{
		httpClient: newDefaultHTTPClient(),
		logger:     &noopLogger{},
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(cfg)
	}
	return cfg
}

// WithHTTPClient returns an Option that sets the HTTP client used by the provider.
// If client is nil, the library default HTTP client is kept (10s timeout).
func WithHTTPClient(client *http.Client) Option {
	return func(cfg *providerConfig) {
		if client != nil {
			cfg.httpClient = client
		}
	}
}

// WithLogger returns an Option that sets the logger used by the provider.
// If l is nil, a no-op logger is used.
func WithLogger(l Logger) Option {
	return func(cfg *providerConfig) {
		if l != nil {
			cfg.logger = l
		}
	}
}

// AuthOption is a functional option for configuring the authorization URL.
type AuthOption func(*authConfig)

// authConfig holds optional parameters for AuthURL.
type authConfig struct {
	scope      string
	lang       string
	forceLogin bool
}

// newAuthConfig creates a new authConfig and applies the given options.
func newAuthConfig(opts ...AuthOption) *authConfig {
	cfg := &authConfig{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(cfg)
	}
	return cfg
}

// WithScope returns an AuthOption that sets the OAuth scope.
func WithScope(scope string) AuthOption {
	return func(cfg *authConfig) {
		cfg.scope = scope
	}
}

// WithLang returns an AuthOption that sets the language preference.
func WithLang(lang string) AuthOption {
	return func(cfg *authConfig) {
		cfg.lang = lang
	}
}

// WithForceLogin returns an AuthOption that forces the user to re-authenticate.
func WithForceLogin() AuthOption {
	return func(cfg *authConfig) {
		cfg.forceLogin = true
	}
}

// withDefaultLang sets the default language for user info responses.
// For WeChat providers this controls the lang parameter in the
// sns/userinfo API call (e.g. "zh_CN", "en", "zh_TW"). When not set,
// the provider defaults to "zh_CN".
func withDefaultLang(lang string) Option {
	return func(cfg *providerConfig) {
		cfg.lang = lang
	}
}

// sensitiveKeys lists substrings that indicate a field value should be masked.
var sensitiveKeys = []string{"token", "secret", "key", "password", "code"}

// maskSensitive masks the value if the key contains a sensitive substring
// (case-insensitive). Sensitive values are returned as the first 4 characters
// followed by "****". If the value has fewer than 4 characters, "****" is returned.
// Non-sensitive values are returned unchanged.
//
// Unlike maskToken (which returns "" for empty input), maskSensitive returns
// "****" for empty sensitive values to indicate the key was present in the URL.
func maskSensitive(key, value string) string {
	lower := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if strings.Contains(lower, s) {
			if len(value) >= 4 {
				return value[:4] + "****"
			}
			return "****"
		}
	}
	return value
}
