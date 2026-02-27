package authhub

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// Compile-time interface compliance check.
var _ Provider = (*wechatMPProvider)(nil)

// ---------------------------------------------------------------------------
// NewWechatMP — constructor validation
// ---------------------------------------------------------------------------

func TestNewWechatMP_Success(t *testing.T) {
	p, err := NewWechatMP("appid", "secret", "https://example.com/callback")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.Name() != "wechat_mp" {
		t.Errorf("Name() = %q, want %q", p.Name(), "wechat_mp")
	}
}

func TestNewWechatMP_WithOptions(t *testing.T) {
	client := &http.Client{}
	logger := &noopLogger{}
	p, err := NewWechatMP("appid", "secret", "https://example.com/callback",
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

func TestNewWechatMP_EmptyAppID(t *testing.T) {
	_, err := NewWechatMP("", "secret", "https://example.com/callback")
	if err == nil {
		t.Fatal("expected error for empty appID")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewWechatMP_EmptySecret(t *testing.T) {
	_, err := NewWechatMP("appid", "", "https://example.com/callback")
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewWechatMP_EmptyRedirectURL(t *testing.T) {
	_, err := NewWechatMP("appid", "secret", "")
	if err == nil {
		t.Fatal("expected error for empty redirectURL")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Name
// ---------------------------------------------------------------------------

func TestWechatMPProvider_Name(t *testing.T) {
	p, _ := NewWechatMP("appid", "secret", "https://example.com/callback")
	if p.Name() != "wechat_mp" {
		t.Errorf("Name() = %q, want %q", p.Name(), "wechat_mp")
	}
}

// ---------------------------------------------------------------------------
// AuthURL
// ---------------------------------------------------------------------------

func TestWechatMPProvider_AuthURL_Success(t *testing.T) {
	p, _ := NewWechatMP("test_appid", "secret", "https://example.com/callback")

	got, err := p.AuthURL("test_state")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, err := url.Parse(strings.TrimSuffix(got, "#wechat_redirect"))
	if err != nil {
		t.Fatalf("invalid URL: %v", err)
	}

	if u.Scheme != "https" || u.Host != "open.weixin.qq.com" || u.Path != "/connect/oauth2/authorize" {
		t.Errorf("unexpected base URL: %s", got)
	}

	q := u.Query()
	if q.Get("appid") != "test_appid" {
		t.Errorf("appid = %q, want %q", q.Get("appid"), "test_appid")
	}
	if q.Get("redirect_uri") != "https://example.com/callback" {
		t.Errorf("redirect_uri = %q, want %q", q.Get("redirect_uri"), "https://example.com/callback")
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want %q", q.Get("response_type"), "code")
	}
	if q.Get("scope") != "snsapi_userinfo" {
		t.Errorf("scope = %q, want %q", q.Get("scope"), "snsapi_userinfo")
	}
	if q.Get("state") != "test_state" {
		t.Errorf("state = %q, want %q", q.Get("state"), "test_state")
	}

	if !strings.HasSuffix(got, "#wechat_redirect") {
		t.Errorf("URL should end with #wechat_redirect, got %q", got)
	}
}

func TestWechatMPProvider_AuthURL_WithScopeBase(t *testing.T) {
	p, _ := NewWechatMP("test_appid", "secret", "https://example.com/callback")

	got, err := p.AuthURL("test_state", WithScope("snsapi_base"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, err := url.Parse(strings.TrimSuffix(got, "#wechat_redirect"))
	if err != nil {
		t.Fatalf("invalid URL: %v", err)
	}

	q := u.Query()
	if q.Get("scope") != "snsapi_base" {
		t.Errorf("scope = %q, want %q", q.Get("scope"), "snsapi_base")
	}
}

func TestWechatMPProvider_AuthURL_EmptyState(t *testing.T) {
	p, _ := NewWechatMP("appid", "secret", "https://example.com/callback")

	_, err := p.AuthURL("")
	if err == nil {
		t.Fatal("expected error for empty state")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestWechatMPProvider_AuthURL_RedirectURIEncoded(t *testing.T) {
	p, _ := NewWechatMP("appid", "secret", "https://example.com/callback?foo=bar&baz=1")

	got, err := p.AuthURL("state123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The redirect_uri should be URL-encoded in the query string
	if !strings.Contains(got, "redirect_uri="+url.QueryEscape("https://example.com/callback?foo=bar&baz=1")) {
		t.Errorf("redirect_uri not properly encoded in URL: %s", got)
	}
}

func TestWechatMPProvider_AuthURL_StateEncoded(t *testing.T) {
	p, _ := NewWechatMP("appid", "secret", "https://example.com/callback")

	state := "val with spaces&special=chars#frag"
	got, err := p.AuthURL(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse URL (strip fragment) and verify state survived encoding round-trip
	u, err := url.Parse(strings.TrimSuffix(got, "#wechat_redirect"))
	if err != nil {
		t.Fatalf("invalid URL: %v", err)
	}
	if u.Query().Get("state") != state {
		t.Errorf("state = %q, want %q", u.Query().Get("state"), state)
	}
}

// ---------------------------------------------------------------------------
// ExchangeCode
// ---------------------------------------------------------------------------

func TestWechatMPProvider_ExchangeCode_EmptyCode(t *testing.T) {
	p := &wechatMPProvider{
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

func TestWechatMPProvider_ExchangeCode_Success(t *testing.T) {
	resp := map[string]any{
		"access_token":  "test_access_token",
		"expires_in":    7200.0,
		"refresh_token": "test_refresh_token",
		"openid":        "oTestOpenID",
		"unionid":       "oTestUnionID",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/sns/oauth2/access_token") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("appid") != "test_appid" {
			t.Errorf("appid = %q, want %q", q.Get("appid"), "test_appid")
		}
		if q.Get("secret") != "test_secret" {
			t.Errorf("secret = %q, want %q", q.Get("secret"), "test_secret")
		}
		if q.Get("code") != "test_code" {
			t.Errorf("code = %q, want %q", q.Get("code"), "test_code")
		}
		if q.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q, want %q", q.Get("grant_type"), "authorization_code")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	p := &wechatMPProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:       "test_appid",
			secret:      "test_secret",
			redirectURL: "https://example.com/callback",
			httpClient:  ts.Client(),
			logger:      &noopLogger{},
		},
		apiBase: ts.URL,
	}

	token, err := p.ExchangeCode(context.Background(), "test_code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.AccessToken != "test_access_token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "test_access_token")
	}
	if token.OpenID != "oTestOpenID" {
		t.Errorf("OpenID = %q, want %q", token.OpenID, "oTestOpenID")
	}
}

func TestWechatMPProvider_ExchangeCode_APIError(t *testing.T) {
	resp := map[string]any{
		"errcode": 40029,
		"errmsg":  "invalid code",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	p := &wechatMPProvider{
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

// ---------------------------------------------------------------------------
// GetUserInfo
// ---------------------------------------------------------------------------

func TestWechatMPProvider_GetUserInfo_Success(t *testing.T) {
	resp := map[string]any{
		"openid":     "oTestOpenID",
		"unionid":    "oTestUnionID",
		"nickname":   "TestUser",
		"headimgurl": "https://example.com/avatar.jpg",
		"sex":        1.0,
		"province":   "Guangdong",
		"city":       "Shenzhen",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("access_token") != "test_token" {
			t.Errorf("access_token = %q, want %q", q.Get("access_token"), "test_token")
		}
		if q.Get("openid") != "oTestOpenID" {
			t.Errorf("openid = %q, want %q", q.Get("openid"), "oTestOpenID")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	p := &wechatMPProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:      "appid",
			secret:     "secret",
			httpClient: ts.Client(),
			logger:     &noopLogger{},
		},
		apiBase: ts.URL,
	}

	token := &Token{
		AccessToken: "test_token",
		OpenID:      "oTestOpenID",
	}

	info, err := p.GetUserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OpenID != "oTestOpenID" {
		t.Errorf("OpenID = %q, want %q", info.OpenID, "oTestOpenID")
	}
	if info.Nickname != "TestUser" {
		t.Errorf("Nickname = %q, want %q", info.Nickname, "TestUser")
	}
	if info.Gender != GenderMale {
		t.Errorf("Gender = %v, want %v", info.Gender, GenderMale)
	}
}

func TestWechatMPProvider_GetUserInfo_APIError(t *testing.T) {
	resp := map[string]any{
		"errcode": 42001,
		"errmsg":  "access_token expired",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	p := &wechatMPProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:      "appid",
			secret:     "secret",
			httpClient: ts.Client(),
			logger:     &noopLogger{},
		},
		apiBase: ts.URL,
	}

	token := &Token{AccessToken: "expired", OpenID: "oid"}
	_, err := p.GetUserInfo(context.Background(), token)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// RefreshToken
// ---------------------------------------------------------------------------

func TestWechatMPProvider_RefreshToken_Success(t *testing.T) {
	resp := map[string]any{
		"access_token":  "new_access_token",
		"expires_in":    7200.0,
		"refresh_token": "new_refresh_token",
		"openid":        "oTestOpenID",
		"unionid":       "oTestUnionID",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/sns/oauth2/refresh_token") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("appid") != "test_appid" {
			t.Errorf("appid = %q, want %q", q.Get("appid"), "test_appid")
		}
		if q.Get("refresh_token") != "old_refresh_token" {
			t.Errorf("refresh_token = %q, want %q", q.Get("refresh_token"), "old_refresh_token")
		}
		if q.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q, want %q", q.Get("grant_type"), "refresh_token")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	p := &wechatMPProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:      "test_appid",
			secret:     "test_secret",
			httpClient: ts.Client(),
			logger:     &noopLogger{},
		},
		apiBase: ts.URL,
	}

	refreshToken := "old_refresh_token"

	token, err := p.RefreshToken(context.Background(), refreshToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.AccessToken != "new_access_token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "new_access_token")
	}
	if token.RefreshToken != "new_refresh_token" {
		t.Errorf("RefreshToken = %q, want %q", token.RefreshToken, "new_refresh_token")
	}
}

func TestWechatMPProvider_RefreshToken_APIError(t *testing.T) {
	resp := map[string]any{
		"errcode": 42002,
		"errmsg":  "refresh_token expired",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	p := &wechatMPProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:      "appid",
			secret:     "secret",
			httpClient: ts.Client(),
			logger:     &noopLogger{},
		},
		apiBase: ts.URL,
	}

	_, err := p.RefreshToken(context.Background(), "expired_token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestWechatMPProvider_GetUserInfo_NilToken(t *testing.T) {
	p := &wechatMPProvider{
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

func TestWechatMPProvider_RefreshToken_EmptyRefreshToken(t *testing.T) {
	p := &wechatMPProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:  "appid",
			secret: "secret",
			logger: &noopLogger{},
		},
		apiBase: "http://localhost",
	}

	_, err := p.RefreshToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty refresh token")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Provider interface compliance
// ---------------------------------------------------------------------------

func TestWechatMPProvider_ImplementsProvider(t *testing.T) {
	var _ Provider = (*wechatMPProvider)(nil)
}

// ---------------------------------------------------------------------------
// ExchangeCode — error code 42001 (token expired)
// ---------------------------------------------------------------------------

func TestWechatMPProvider_ExchangeCode_TokenExpired(t *testing.T) {
	resp := map[string]any{
		"errcode": 42001,
		"errmsg":  "access_token expired",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	p := &wechatMPProvider{
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

func TestWechatMPProvider_Concurrency(t *testing.T) {
	resp := map[string]any{
		"access_token":  "test_token",
		"expires_in":    7200.0,
		"refresh_token": "test_refresh",
		"openid":        "oTestOpenID",
	}
	userResp := map[string]any{
		"openid":     "oTestOpenID",
		"nickname":   "User",
		"headimgurl": "https://example.com/a.jpg",
		"sex":        1.0,
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "userinfo") {
			_ = json.NewEncoder(w).Encode(userResp)
		} else {
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer ts.Close()

	p := &wechatMPProvider{
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
			_, err := p.GetUserInfo(context.Background(), &Token{AccessToken: "tok", OpenID: "oid"})
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
