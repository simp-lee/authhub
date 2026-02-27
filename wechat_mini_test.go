package authhub

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Compile-time interface compliance check.
var _ Provider = (*wechatMiniProvider)(nil)

// ---------------------------------------------------------------------------
// NewWechatMini — constructor validation
// ---------------------------------------------------------------------------

func TestNewWechatMini_Success(t *testing.T) {
	p, err := NewWechatMini("appid", "secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.Name() != "wechat_mini" {
		t.Errorf("Name() = %q, want %q", p.Name(), "wechat_mini")
	}
}

func TestNewWechatMini_WithOptions(t *testing.T) {
	client := &http.Client{}
	logger := &noopLogger{}
	p, err := NewWechatMini("appid", "secret",
		WithHTTPClient(client),
		WithLogger(logger),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestNewWechatMini_EmptyAppID(t *testing.T) {
	_, err := NewWechatMini("", "secret")
	if err == nil {
		t.Fatal("expected error for empty appID")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewWechatMini_EmptySecret(t *testing.T) {
	_, err := NewWechatMini("appid", "")
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Name
// ---------------------------------------------------------------------------

func TestWechatMiniProvider_Name(t *testing.T) {
	p, _ := NewWechatMini("appid", "secret")
	if p.Name() != "wechat_mini" {
		t.Errorf("Name() = %q, want %q", p.Name(), "wechat_mini")
	}
}

// ---------------------------------------------------------------------------
// AuthURL — must return ErrUnsupported
// ---------------------------------------------------------------------------

func TestWechatMiniProvider_AuthURL_Unsupported(t *testing.T) {
	p, _ := NewWechatMini("appid", "secret")

	got, err := p.AuthURL("some_state")
	if got != "" {
		t.Errorf("AuthURL() returned non-empty URL: %q", got)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("expected ErrUnsupported, got %v", err)
	}
	var ae *AuthError
	if errors.As(err, &ae) {
		if ae.Provider != "wechat_mini" {
			t.Errorf("Provider = %q, want %q", ae.Provider, "wechat_mini")
		}
	}
}

// ---------------------------------------------------------------------------
// ExchangeCode
// ---------------------------------------------------------------------------

func TestWechatMiniProvider_ExchangeCode_Success(t *testing.T) {
	resp := map[string]any{
		"openid":      "oMiniOpenID",
		"session_key": "test_session_key_value",
		"unionid":     "oMiniUnionID",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sns/jscode2session" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("appid") != "test_appid" {
			t.Errorf("appid = %q, want %q", q.Get("appid"), "test_appid")
		}
		if q.Get("secret") != "test_secret" {
			t.Errorf("secret = %q, want %q", q.Get("secret"), "test_secret")
		}
		if q.Get("js_code") != "test_code" {
			t.Errorf("js_code = %q, want %q", q.Get("js_code"), "test_code")
		}
		if q.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q, want %q", q.Get("grant_type"), "authorization_code")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	p := &wechatMiniProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:      "test_appid",
			secret:     "test_secret",
			httpClient: ts.Client(),
			logger:     &noopLogger{},
		},
		apiBase: ts.URL,
	}

	token, err := p.ExchangeCode(context.Background(), "test_code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// AccessToken should be empty — jscode2session doesn't return access_token
	if token.AccessToken != "" {
		t.Errorf("AccessToken = %q, want empty", token.AccessToken)
	}

	if token.OpenID != "oMiniOpenID" {
		t.Errorf("OpenID = %q, want %q", token.OpenID, "oMiniOpenID")
	}
	if token.UnionID != "oMiniUnionID" {
		t.Errorf("UnionID = %q, want %q", token.UnionID, "oMiniUnionID")
	}

	// ExpiresAt should be zero value so IsExpired() returns true
	if !token.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want zero value", token.ExpiresAt)
	}
	if !token.IsExpired() {
		t.Error("IsExpired() = false, want true")
	}

	// session_key must be in Raw, not exposed as a top-level field
	if token.Raw == nil {
		t.Fatal("Raw is nil")
	}
	sk, ok := token.Raw["session_key"]
	if !ok {
		t.Fatal("session_key not found in Raw")
	}
	if sk != "test_session_key_value" {
		t.Errorf("Raw[session_key] = %v, want %q", sk, "test_session_key_value")
	}
}

func TestWechatMiniProvider_ExchangeCode_EmptyCode(t *testing.T) {
	p := &wechatMiniProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:  "appid",
			secret: "secret",
			logger: &noopLogger{},
		},
		apiBase: "https://unused.example.com",
	}

	_, err := p.ExchangeCode(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty code")
	}
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

func TestWechatMiniProvider_ExchangeCode_NoUnionID(t *testing.T) {
	resp := map[string]any{
		"openid":      "oMiniOpenID",
		"session_key": "sk_value",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	p := &wechatMiniProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:      "appid",
			secret:     "secret",
			httpClient: ts.Client(),
			logger:     &noopLogger{},
		},
		apiBase: ts.URL,
	}

	token, err := p.ExchangeCode(context.Background(), "code123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.OpenID != "oMiniOpenID" {
		t.Errorf("OpenID = %q, want %q", token.OpenID, "oMiniOpenID")
	}
	if token.UnionID != "" {
		t.Errorf("UnionID = %q, want empty", token.UnionID)
	}
}

func TestWechatMiniProvider_ExchangeCode_APIError(t *testing.T) {
	resp := map[string]any{
		"errcode": 40029,
		"errmsg":  "invalid code",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	p := &wechatMiniProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:      "appid",
			secret:     "secret",
			httpClient: ts.Client(),
			logger:     &noopLogger{},
		},
		apiBase: ts.URL,
	}

	_, err := p.ExchangeCode(context.Background(), "bad_code")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

func TestWechatMiniProvider_ExchangeCode_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer ts.Close()

	p := &wechatMiniProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:      "appid",
			secret:     "secret",
			httpClient: ts.Client(),
			logger:     &noopLogger{},
		},
		apiBase: ts.URL,
	}

	_, err := p.ExchangeCode(context.Background(), "code")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrPlatform) {
		t.Errorf("expected ErrPlatform, got %v", err)
	}
}

func TestWechatMiniProvider_ExchangeCode_NetworkError(t *testing.T) {
	p := &wechatMiniProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:      "appid",
			secret:     "secret",
			httpClient: &http.Client{Timeout: 1 * time.Millisecond},
			logger:     &noopLogger{},
		},
		apiBase: "http://192.0.2.1:1", // non-routable address
	}

	_, err := p.ExchangeCode(context.Background(), "code")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNetwork) {
		t.Errorf("expected ErrNetwork, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetUserInfo — returns only OpenID and UnionID, no API call
// ---------------------------------------------------------------------------

func TestWechatMiniProvider_GetUserInfo_Success(t *testing.T) {
	p, _ := NewWechatMini("appid", "secret")

	token := &Token{
		OpenID:  "oMiniOpenID",
		UnionID: "oMiniUnionID",
	}

	info, err := p.GetUserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OpenID != "oMiniOpenID" {
		t.Errorf("OpenID = %q, want %q", info.OpenID, "oMiniOpenID")
	}
	if info.UnionID != "oMiniUnionID" {
		t.Errorf("UnionID = %q, want %q", info.UnionID, "oMiniUnionID")
	}
	// No nickname or avatar should be set
	if info.Nickname != "" {
		t.Errorf("Nickname = %q, want empty", info.Nickname)
	}
	if info.Avatar != "" {
		t.Errorf("Avatar = %q, want empty", info.Avatar)
	}
}

func TestWechatMiniProvider_GetUserInfo_NilToken(t *testing.T) {
	p := &wechatMiniProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:  "appid",
			secret: "secret",
			logger: &noopLogger{},
		},
		apiBase: "http://localhost",
	}

	_, err := p.GetUserInfo(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil token")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestWechatMiniProvider_GetUserInfo_NoUnionID(t *testing.T) {
	p, _ := NewWechatMini("appid", "secret")

	token := &Token{
		OpenID: "oMiniOpenID",
	}

	info, err := p.GetUserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OpenID != "oMiniOpenID" {
		t.Errorf("OpenID = %q, want %q", info.OpenID, "oMiniOpenID")
	}
	if info.UnionID != "" {
		t.Errorf("UnionID = %q, want empty", info.UnionID)
	}
}

// ---------------------------------------------------------------------------
// RefreshToken — must return ErrUnsupported
// ---------------------------------------------------------------------------

func TestWechatMiniProvider_RefreshToken_Unsupported(t *testing.T) {
	p, _ := NewWechatMini("appid", "secret")

	got, err := p.RefreshToken(context.Background(), "any_refresh_token")
	if got != nil {
		t.Errorf("RefreshToken() returned non-nil token: %v", got)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("expected ErrUnsupported, got %v", err)
	}
	var ae *AuthError
	if errors.As(err, &ae) {
		if ae.Provider != "wechat_mini" {
			t.Errorf("Provider = %q, want %q", ae.Provider, "wechat_mini")
		}
	}
}

// ---------------------------------------------------------------------------
// Interface compliance
// ---------------------------------------------------------------------------

func TestWechatMiniProvider_ImplementsProvider(t *testing.T) {
	var _ Provider = (*wechatMiniProvider)(nil)
}

// ---------------------------------------------------------------------------
// ExchangeCode — error code 42001 (token expired)
// ---------------------------------------------------------------------------

func TestWechatMiniProvider_ExchangeCode_TokenExpired(t *testing.T) {
	resp := map[string]any{
		"errcode": 42001,
		"errmsg":  "access_token expired",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	p := &wechatMiniProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:      "appid",
			secret:     "secret",
			httpClient: ts.Client(),
			logger:     &noopLogger{},
		},
		apiBase: ts.URL,
	}

	_, err := p.ExchangeCode(context.Background(), "some_code")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Concurrency safety
// ---------------------------------------------------------------------------

func TestWechatMiniProvider_Concurrency(t *testing.T) {
	resp := map[string]any{
		"openid":      "oMiniOpenID",
		"session_key": "sk_value",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	p := &wechatMiniProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:      "appid",
			secret:     "secret",
			httpClient: ts.Client(),
			logger:     &noopLogger{},
		},
		apiBase: ts.URL,
	}

	const goroutines = 10
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*2)

	for i := 0; i < goroutines; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := p.ExchangeCode(context.Background(), "code")
			if err != nil {
				errCh <- err
			}
		}()
		go func() {
			defer wg.Done()
			_, err := p.GetUserInfo(context.Background(), &Token{OpenID: "oid"})
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent call failed: %v", err)
	}
}
