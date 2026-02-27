package authhub

import (
	"net/http"
	"testing"
	"time"
)

// --- Logger interface ---

func TestNoopLoggerImplementsLogger(t *testing.T) {
	var l Logger = &noopLogger{}
	// Should not panic
	l.Debug("test", "key", "value")
	l.Info("test", "key", "value")
	l.Warn("test", "key", "value")
	l.Error("test", "key", "value")
}

// --- providerConfig defaults ---

func TestNewProviderConfigDefaults(t *testing.T) {
	cfg := newProviderConfig()
	if cfg.httpClient == nil {
		t.Fatal("default httpClient should not be nil")
	}
	if cfg.httpClient.Timeout != 10*time.Second {
		t.Errorf("default httpClient.Timeout = %v; want %v", cfg.httpClient.Timeout, 10*time.Second)
	}
	if cfg.logger == nil {
		t.Error("default logger should not be nil")
	}
	// Should be noopLogger
	if _, ok := cfg.logger.(*noopLogger); !ok {
		t.Errorf("default logger should be *noopLogger, got %T", cfg.logger)
	}
}

// --- WithHTTPClient ---

func TestWithHTTPClient(t *testing.T) {
	custom := &http.Client{}
	cfg := newProviderConfig(WithHTTPClient(custom))
	if cfg.httpClient != custom {
		t.Error("WithHTTPClient did not set the custom client")
	}
}

func TestWithHTTPClientNil(t *testing.T) {
	cfg := newProviderConfig(WithHTTPClient(nil))
	if cfg.httpClient == nil {
		t.Fatal("WithHTTPClient(nil) should keep default client")
	}
	if cfg.httpClient.Timeout != 10*time.Second {
		t.Errorf("WithHTTPClient(nil) httpClient.Timeout = %v; want %v", cfg.httpClient.Timeout, 10*time.Second)
	}
}

// --- WithLogger ---

type testLogger struct{}

func (tl *testLogger) Debug(msg string, args ...any) {}
func (tl *testLogger) Info(msg string, args ...any)  {}
func (tl *testLogger) Warn(msg string, args ...any)  {}
func (tl *testLogger) Error(msg string, args ...any) {}

func TestWithLogger(t *testing.T) {
	l := &testLogger{}
	cfg := newProviderConfig(WithLogger(l))
	if cfg.logger != l {
		t.Error("WithLogger did not set the custom logger")
	}
}

func TestWithLoggerNil(t *testing.T) {
	cfg := newProviderConfig(WithLogger(nil))
	if _, ok := cfg.logger.(*noopLogger); !ok {
		t.Errorf("WithLogger(nil) should keep noopLogger, got %T", cfg.logger)
	}
}

func TestNewProviderConfig_NilOptionIgnored(t *testing.T) {
	cfg := newProviderConfig(nil)
	if cfg == nil {
		t.Fatal("newProviderConfig(nil) returned nil")
	}
	if cfg.httpClient == nil {
		t.Fatal("newProviderConfig(nil) should keep default httpClient")
	}
	if _, ok := cfg.logger.(*noopLogger); !ok {
		t.Errorf("newProviderConfig(nil) should keep noopLogger, got %T", cfg.logger)
	}
}

func TestNewProviderConfig_MixedNilOptionIgnored(t *testing.T) {
	custom := &http.Client{}
	cfg := newProviderConfig(nil, WithHTTPClient(custom), nil)
	if cfg.httpClient != custom {
		t.Error("newProviderConfig should apply non-nil options and ignore nil entries")
	}
}

// --- authConfig ---

func TestNewAuthConfigDefaults(t *testing.T) {
	cfg := newAuthConfig()
	if cfg.scope != "" {
		t.Errorf("default scope = %q; want empty", cfg.scope)
	}
	if cfg.lang != "" {
		t.Errorf("default lang = %q; want empty", cfg.lang)
	}
	if cfg.forceLogin {
		t.Error("default forceLogin should be false")
	}
}

func TestWithScope(t *testing.T) {
	cfg := newAuthConfig(WithScope("snsapi_userinfo"))
	if cfg.scope != "snsapi_userinfo" {
		t.Errorf("scope = %q; want %q", cfg.scope, "snsapi_userinfo")
	}
}

func TestWithLang(t *testing.T) {
	cfg := newAuthConfig(WithLang("zh_CN"))
	if cfg.lang != "zh_CN" {
		t.Errorf("lang = %q; want %q", cfg.lang, "zh_CN")
	}
}

func TestWithForceLogin(t *testing.T) {
	cfg := newAuthConfig(WithForceLogin())
	if !cfg.forceLogin {
		t.Error("forceLogin should be true after WithForceLogin()")
	}
}

func TestAuthConfigMultipleOptions(t *testing.T) {
	cfg := newAuthConfig(WithScope("openid"), WithLang("en"), WithForceLogin())
	if cfg.scope != "openid" {
		t.Errorf("scope = %q; want %q", cfg.scope, "openid")
	}
	if cfg.lang != "en" {
		t.Errorf("lang = %q; want %q", cfg.lang, "en")
	}
	if !cfg.forceLogin {
		t.Error("forceLogin should be true")
	}
}

func TestNewAuthConfig_NilOptionIgnored(t *testing.T) {
	cfg := newAuthConfig(nil)
	if cfg == nil {
		t.Fatal("newAuthConfig(nil) returned nil")
	}
	if cfg.scope != "" || cfg.lang != "" || cfg.forceLogin {
		t.Fatalf("newAuthConfig(nil) should keep defaults, got %+v", cfg)
	}
}

func TestNewAuthConfig_MixedNilOptionIgnored(t *testing.T) {
	cfg := newAuthConfig(nil, WithScope("openid"), nil, WithLang("zh_CN"))
	if cfg.scope != "openid" {
		t.Errorf("scope = %q; want %q", cfg.scope, "openid")
	}
	if cfg.lang != "zh_CN" {
		t.Errorf("lang = %q; want %q", cfg.lang, "zh_CN")
	}
}

// --- maskSensitive ---

func TestMaskSensitive(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{
			name:  "access_token is masked",
			key:   "access_token",
			value: "abcdefghijklmnop",
			want:  "abcd****",
		},
		{
			name:  "Token (case-insensitive) is masked",
			key:   "RefreshToken",
			value: "1234567890",
			want:  "1234****",
		},
		{
			name:  "secret key is masked",
			key:   "app_secret",
			value: "mysecretvalue",
			want:  "myse****",
		},
		{
			name:  "api_key is masked",
			key:   "api_key",
			value: "keyvalue12345",
			want:  "keyv****",
		},
		{
			name:  "password is masked",
			key:   "Password",
			value: "pass1234",
			want:  "pass****",
		},
		{
			name:  "code is masked",
			key:   "auth_code",
			value: "codeval123",
			want:  "code****",
		},
		{
			name:  "short value masked with ****",
			key:   "token",
			value: "ab",
			want:  "****",
		},
		{
			name:  "exactly 4 chars masked",
			key:   "token",
			value: "abcd",
			want:  "abcd****",
		},
		{
			name:  "empty value masked",
			key:   "token",
			value: "",
			want:  "****",
		},
		{
			name:  "non-sensitive key unchanged",
			key:   "username",
			value: "john_doe",
			want:  "john_doe",
		},
		{
			name:  "openid not masked",
			key:   "openid",
			value: "o1234567890",
			want:  "o1234567890",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskSensitive(tt.key, tt.value)
			if got != tt.want {
				t.Errorf("maskSensitive(%q, %q) = %q; want %q", tt.key, tt.value, got, tt.want)
			}
		})
	}
}
