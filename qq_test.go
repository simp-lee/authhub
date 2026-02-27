package authhub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Compile-time interface compliance check.
var _ Provider = (*qqProvider)(nil)

// ---------------------------------------------------------------------------
// NewQQ — constructor validation
// ---------------------------------------------------------------------------

func TestNewQQ_Success(t *testing.T) {
	p, err := NewQQ("appid", "appkey", "https://example.com/callback")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.Name() != "qq" {
		t.Errorf("Name() = %q, want %q", p.Name(), "qq")
	}
}

func TestNewQQ_WithOptions(t *testing.T) {
	client := &http.Client{}
	logger := &noopLogger{}
	p, err := NewQQ("appid", "appkey", "https://example.com/callback",
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

func TestNewQQ_EmptyAppID(t *testing.T) {
	_, err := NewQQ("", "appkey", "https://example.com/callback")
	if err == nil {
		t.Fatal("expected error for empty appID")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewQQ_EmptyAppKey(t *testing.T) {
	_, err := NewQQ("appid", "", "https://example.com/callback")
	if err == nil {
		t.Fatal("expected error for empty appKey")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewQQ_EmptyRedirectURL(t *testing.T) {
	_, err := NewQQ("appid", "appkey", "")
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

func TestQQProvider_Name(t *testing.T) {
	p, _ := NewQQ("appid", "appkey", "https://example.com/callback")
	if p.Name() != "qq" {
		t.Errorf("Name() = %q, want %q", p.Name(), "qq")
	}
}

// ---------------------------------------------------------------------------
// AuthURL
// ---------------------------------------------------------------------------

func TestQQProvider_AuthURL_Success(t *testing.T) {
	p, _ := NewQQ("test_appid", "appkey", "https://example.com/callback")

	got, err := p.AuthURL("test_state")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("invalid URL: %v", err)
	}

	if u.Scheme != "https" || u.Host != "graph.qq.com" || u.Path != "/oauth2.0/authorize" {
		t.Errorf("unexpected base URL: %s", got)
	}

	q := u.Query()
	if q.Get("client_id") != "test_appid" {
		t.Errorf("client_id = %q, want %q", q.Get("client_id"), "test_appid")
	}
	if q.Get("redirect_uri") != "https://example.com/callback" {
		t.Errorf("redirect_uri = %q, want %q", q.Get("redirect_uri"), "https://example.com/callback")
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want %q", q.Get("response_type"), "code")
	}
	if q.Get("scope") != "get_user_info" {
		t.Errorf("scope = %q, want %q", q.Get("scope"), "get_user_info")
	}
	if q.Get("state") != "test_state" {
		t.Errorf("state = %q, want %q", q.Get("state"), "test_state")
	}
}

func TestQQProvider_AuthURL_EmptyState(t *testing.T) {
	p, _ := NewQQ("appid", "appkey", "https://example.com/callback")

	_, err := p.AuthURL("")
	if err == nil {
		t.Fatal("expected error for empty state")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestQQProvider_AuthURL_RedirectURIEncoded(t *testing.T) {
	p, _ := NewQQ("appid", "appkey", "https://example.com/callback?foo=bar&baz=1")

	got, err := p.AuthURL("state123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(got, "redirect_uri="+url.QueryEscape("https://example.com/callback?foo=bar&baz=1")) {
		t.Errorf("redirect_uri not properly encoded in URL: %s", got)
	}
}

func TestQQProvider_AuthURL_StateEncoded(t *testing.T) {
	p, _ := NewQQ("appid", "appkey", "https://example.com/callback")

	state := "val with spaces&special=chars"
	got, err := p.AuthURL(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, err := url.Parse(got)
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

func TestQQProvider_ExchangeCode_EmptyCode(t *testing.T) {
	p := &qqProvider{
		appID:  "appid",
		appKey: "appkey",
		logger: &noopLogger{},
	}

	_, err := p.ExchangeCode(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty code")
	}
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

// qqURLEncodedExchangeHandler returns an HTTP handler for QQ's OAuth endpoints
// that responds with URL-encoded token responses for testing.
func qqURLEncodedExchangeHandler(t *testing.T, callCount *int) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		*callCount++
		switch {
		case strings.Contains(r.URL.Path, "/oauth2.0/token"):
			q := r.URL.Query()
			if q.Get("client_id") != "test_appid" {
				t.Errorf("client_id = %q, want %q", q.Get("client_id"), "test_appid")
			}
			if q.Get("client_secret") != "test_appkey" {
				t.Errorf("client_secret = %q, want %q", q.Get("client_secret"), "test_appkey")
			}
			if q.Get("code") != "test_code" {
				t.Errorf("code = %q, want %q", q.Get("code"), "test_code")
			}
			if q.Get("grant_type") != "authorization_code" {
				t.Errorf("grant_type = %q, want %q", q.Get("grant_type"), "authorization_code")
			}
			// QQ returns URL-encoded format
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "access_token=test_access_token&expires_in=7776000&refresh_token=test_refresh_token")

		case strings.Contains(r.URL.Path, "/oauth2.0/me"):
			q := r.URL.Query()
			if q.Get("access_token") != "test_access_token" {
				t.Errorf("access_token = %q, want %q", q.Get("access_token"), "test_access_token")
			}
			if q.Get("fmt") != "json" {
				t.Errorf("fmt = %q, want %q", q.Get("fmt"), "json")
			}
			if q.Get("unionid") != "1" {
				t.Errorf("unionid = %q, want %q", q.Get("unionid"), "1")
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id": "test_appid",
				"openid":    "test_openid",
				"unionid":   "test_unionid",
			})

		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
	}
}

func TestQQProvider_ExchangeCode_Success_URLEncoded(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(qqURLEncodedExchangeHandler(t, &callCount))
	defer ts.Close()

	p := &qqProvider{
		appID:       "test_appid",
		appKey:      "test_appkey",
		redirectURL: "https://example.com/callback",
		httpClient:  ts.Client(),
		logger:      &noopLogger{},
		oauthBase:   ts.URL,
	}

	token, err := p.ExchangeCode(context.Background(), "test_code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.AccessToken != "test_access_token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "test_access_token")
	}
	if token.RefreshToken != "test_refresh_token" {
		t.Errorf("RefreshToken = %q, want %q", token.RefreshToken, "test_refresh_token")
	}
	if token.ExpiresIn != 7776000 {
		t.Errorf("ExpiresIn = %d, want %d", token.ExpiresIn, 7776000)
	}
	if token.OpenID != "test_openid" {
		t.Errorf("OpenID = %q, want %q", token.OpenID, "test_openid")
	}
	if token.UnionID != "test_unionid" {
		t.Errorf("UnionID = %q, want %q", token.UnionID, "test_unionid")
	}
	if callCount != 2 {
		t.Errorf("expected 2 HTTP calls, got %d", callCount)
	}
	// Token.Raw should be populated from URL-encoded response.
	if token.Raw == nil {
		t.Fatal("expected non-nil Raw")
	}
	if token.Raw["access_token"] != "test_access_token" {
		t.Errorf("Raw[access_token] = %v, want %q", token.Raw["access_token"], "test_access_token")
	}
}

func TestQQProvider_ExchangeCode_Success_JSONFallback(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch {
		case strings.Contains(r.URL.Path, "/oauth2.0/token"):
			// QQ returns JSON format (some newer responses)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "json_access_token",
				"expires_in":    7200,
				"refresh_token": "json_refresh_token",
			})

		case strings.Contains(r.URL.Path, "/oauth2.0/me"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id": "test_appid",
				"openid":    "json_openid",
				"unionid":   "json_unionid",
			})

		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:       "test_appid",
		appKey:      "test_appkey",
		redirectURL: "https://example.com/callback",
		httpClient:  ts.Client(),
		logger:      &noopLogger{},
		oauthBase:   ts.URL,
	}

	token, err := p.ExchangeCode(context.Background(), "test_code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.AccessToken != "json_access_token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "json_access_token")
	}
	if token.OpenID != "json_openid" {
		t.Errorf("OpenID = %q, want %q", token.OpenID, "json_openid")
	}
	// Token.Raw should be populated from JSON response.
	if token.Raw == nil {
		t.Fatal("expected non-nil Raw")
	}
	if token.Raw["access_token"] != "json_access_token" {
		t.Errorf("Raw[access_token] = %v, want %q", token.Raw["access_token"], "json_access_token")
	}
}

func TestQQProvider_ExchangeCode_MeEndpoint_EmptyOpenID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2.0/token"):
			_, _ = fmt.Fprint(w, "access_token=tok&expires_in=7200&refresh_token=rtok")
		case strings.Contains(r.URL.Path, "/oauth2.0/me"):
			w.Header().Set("Content-Type", "application/json")
			// Success response but missing openid field.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id": "appid",
			})
		}
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:       "appid",
		appKey:      "appkey",
		redirectURL: "https://example.com/callback",
		httpClient:  ts.Client(),
		logger:      &noopLogger{},
		oauthBase:   ts.URL,
	}

	_, err := p.ExchangeCode(context.Background(), "code123")
	if err == nil {
		t.Fatal("expected error for empty openid, got nil")
	}
	if !errors.Is(err, ErrPlatform) {
		t.Errorf("expected ErrPlatform, got %v", err)
	}
}

func TestQQProvider_ExchangeCode_TokenError_URLEncoded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "error=100030&error_description=invalid+code")
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:      "appid",
		appKey:     "appkey",
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		oauthBase:  ts.URL,
	}

	_, err := p.ExchangeCode(context.Background(), "bad_code")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrPlatform) {
		t.Errorf("expected ErrPlatform, got %v", err)
	}
	var ae *AuthError
	if errors.As(err, &ae) {
		if ae.Provider != "qq" {
			t.Errorf("Provider = %q, want %q", ae.Provider, "qq")
		}
	}
}

func TestQQProvider_ExchangeCode_TokenError_JSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":             100030,
			"error_description": "invalid code",
		})
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:      "appid",
		appKey:     "appkey",
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		oauthBase:  ts.URL,
	}

	_, err := p.ExchangeCode(context.Background(), "bad_code")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrPlatform) {
		t.Errorf("expected ErrPlatform, got %v", err)
	}
}

func TestQQProvider_ExchangeCode_TokenMalformedExpiresIn_URLEncoded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2.0/token"):
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "access_token=tok&expires_in=notanum&refresh_token=rtok")
		case strings.Contains(r.URL.Path, "/oauth2.0/me"):
			t.Fatal("/oauth2.0/me should not be called when token response is invalid")
		}
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:       "appid",
		appKey:      "appkey",
		redirectURL: "https://example.com/callback",
		httpClient:  ts.Client(),
		logger:      &noopLogger{},
		oauthBase:   ts.URL,
	}

	_, err := p.ExchangeCode(context.Background(), "code123")
	if err == nil {
		t.Fatal("expected error for malformed expires_in, got nil")
	}
	if !errors.Is(err, ErrPlatform) {
		t.Errorf("expected ErrPlatform, got %v", err)
	}
}

func TestQQProvider_ExchangeCode_TokenMalformedExpiresIn_JSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2.0/token"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "tok",
				"expires_in":    "notanum",
				"refresh_token": "rtok",
			})
		case strings.Contains(r.URL.Path, "/oauth2.0/me"):
			t.Fatal("/oauth2.0/me should not be called when token response is invalid")
		}
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:       "appid",
		appKey:      "appkey",
		redirectURL: "https://example.com/callback",
		httpClient:  ts.Client(),
		logger:      &noopLogger{},
		oauthBase:   ts.URL,
	}

	_, err := p.ExchangeCode(context.Background(), "code123")
	if err == nil {
		t.Fatal("expected error for malformed expires_in, got nil")
	}
	if !errors.Is(err, ErrPlatform) {
		t.Errorf("expected ErrPlatform, got %v", err)
	}
}

func TestQQProvider_ExchangeCode_MeEndpoint_JSONP(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch {
		case strings.Contains(r.URL.Path, "/oauth2.0/token"):
			_, _ = fmt.Fprint(w, "access_token=tok&expires_in=7200&refresh_token=rtok")
		case strings.Contains(r.URL.Path, "/oauth2.0/me"):
			// JSONP callback response
			_, _ = fmt.Fprint(w, `callback({"client_id":"appid","openid":"jsonp_openid","unionid":"jsonp_unionid"});`)
		}
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:       "appid",
		appKey:      "appkey",
		redirectURL: "https://example.com/callback",
		httpClient:  ts.Client(),
		logger:      &noopLogger{},
		oauthBase:   ts.URL,
	}

	token, err := p.ExchangeCode(context.Background(), "code123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.OpenID != "jsonp_openid" {
		t.Errorf("OpenID = %q, want %q", token.OpenID, "jsonp_openid")
	}
	if token.UnionID != "jsonp_unionid" {
		t.Errorf("UnionID = %q, want %q", token.UnionID, "jsonp_unionid")
	}
}

func TestQQProvider_ExchangeCode_MeEndpoint_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2.0/token"):
			_, _ = fmt.Fprint(w, "access_token=tok&expires_in=7200&refresh_token=rtok")
		case strings.Contains(r.URL.Path, "/oauth2.0/me"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":             100016,
				"error_description": "access token expired",
			})
		}
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:       "appid",
		appKey:      "appkey",
		redirectURL: "https://example.com/callback",
		httpClient:  ts.Client(),
		logger:      &noopLogger{},
		oauthBase:   ts.URL,
	}

	_, err := p.ExchangeCode(context.Background(), "code123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestQQProvider_ExchangeCode_MeEndpoint_OtherError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2.0/token"):
			_, _ = fmt.Fprint(w, "access_token=tok&expires_in=7200&refresh_token=rtok")
		case strings.Contains(r.URL.Path, "/oauth2.0/me"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":             100048,
				"error_description": "some error",
			})
		}
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:       "appid",
		appKey:      "appkey",
		redirectURL: "https://example.com/callback",
		httpClient:  ts.Client(),
		logger:      &noopLogger{},
		oauthBase:   ts.URL,
	}

	_, err := p.ExchangeCode(context.Background(), "code123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrPlatform) {
		t.Errorf("expected ErrPlatform, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetUserInfo
// ---------------------------------------------------------------------------

func TestQQProvider_GetUserInfo_NilToken(t *testing.T) {
	p := &qqProvider{
		appID:  "appid",
		appKey: "appkey",
		logger: &noopLogger{},
	}

	_, err := p.GetUserInfo(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil token")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestQQProvider_GetUserInfo_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("access_token") != "test_token" {
			t.Errorf("access_token = %q, want %q", q.Get("access_token"), "test_token")
		}
		if q.Get("oauth_consumer_key") != "test_appid" {
			t.Errorf("oauth_consumer_key = %q, want %q", q.Get("oauth_consumer_key"), "test_appid")
		}
		if q.Get("openid") != "test_openid" {
			t.Errorf("openid = %q, want %q", q.Get("openid"), "test_openid")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ret":            0,
			"msg":            "",
			"nickname":       "TestQQUser",
			"figureurl_qq_2": "https://example.com/avatar_qq.jpg",
			"gender":         "男",
			"province":       "广东",
			"city":           "深圳",
		})
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:      "test_appid",
		appKey:     "test_appkey",
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		apiBase:    ts.URL,
	}

	token := &Token{
		AccessToken: "test_token",
		OpenID:      "test_openid",
	}

	info, err := p.GetUserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OpenID != "test_openid" {
		t.Errorf("OpenID = %q, want %q", info.OpenID, "test_openid")
	}
	if info.Nickname != "TestQQUser" {
		t.Errorf("Nickname = %q, want %q", info.Nickname, "TestQQUser")
	}
	if info.Avatar != "https://example.com/avatar_qq.jpg" {
		t.Errorf("Avatar = %q, want %q", info.Avatar, "https://example.com/avatar_qq.jpg")
	}
	if info.Gender != GenderMale {
		t.Errorf("Gender = %v, want %v", info.Gender, GenderMale)
	}
	if info.Province != "广东" {
		t.Errorf("Province = %q, want %q", info.Province, "广东")
	}
	if info.City != "深圳" {
		t.Errorf("City = %q, want %q", info.City, "深圳")
	}
	if info.Raw == nil {
		t.Error("Raw should not be nil")
	}
}

func TestQQProvider_GetUserInfo_Female(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ret":      0,
			"msg":      "",
			"nickname": "FemaleUser",
			"gender":   "女",
		})
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:      "appid",
		appKey:     "appkey",
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		apiBase:    ts.URL,
	}

	info, err := p.GetUserInfo(context.Background(), &Token{AccessToken: "tok", OpenID: "oid"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Gender != GenderFemale {
		t.Errorf("Gender = %v, want %v", info.Gender, GenderFemale)
	}
}

func TestQQProvider_GetUserInfo_UnknownGender(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ret":      0,
			"msg":      "",
			"nickname": "UnknownGenderUser",
			"gender":   "",
		})
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:      "appid",
		appKey:     "appkey",
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		apiBase:    ts.URL,
	}

	info, err := p.GetUserInfo(context.Background(), &Token{AccessToken: "tok", OpenID: "oid"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Gender != GenderUnknown {
		t.Errorf("Gender = %v, want %v", info.Gender, GenderUnknown)
	}
}

func TestQQProvider_GetUserInfo_APIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ret": 1002,
			"msg": "invalid openid",
		})
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:      "appid",
		appKey:     "appkey",
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		apiBase:    ts.URL,
	}

	_, err := p.GetUserInfo(context.Background(), &Token{AccessToken: "tok", OpenID: "oid"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrPlatform) {
		t.Errorf("expected ErrPlatform, got %v", err)
	}
	var ae *AuthError
	if errors.As(err, &ae) {
		if ae.Code != "1002" {
			t.Errorf("Code = %q, want %q", ae.Code, "1002")
		}
	}
}

func TestQQProvider_GetUserInfo_TokenExpired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ret": 100016,
			"msg": "access token expired",
		})
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:      "appid",
		appKey:     "appkey",
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		apiBase:    ts.URL,
	}

	_, err := p.GetUserInfo(context.Background(), &Token{AccessToken: "tok", OpenID: "oid"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
	var ae *AuthError
	if errors.As(err, &ae) {
		if ae.Code != "100016" {
			t.Errorf("Code = %q, want %q", ae.Code, "100016")
		}
	}
}

func TestQQProvider_FillOpenID_ClientIDMismatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2.0/token"):
			_, _ = fmt.Fprint(w, "access_token=tok&expires_in=7200&refresh_token=rtok")
		case strings.Contains(r.URL.Path, "/oauth2.0/me"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id": "wrong_appid",
				"openid":    "test_openid",
				"unionid":   "test_unionid",
			})
		}
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:       "correct_appid",
		appKey:      "appkey",
		redirectURL: "https://example.com/callback",
		httpClient:  ts.Client(),
		logger:      &noopLogger{},
		oauthBase:   ts.URL,
	}

	_, err := p.ExchangeCode(context.Background(), "code123")
	if err == nil {
		t.Fatal("expected error for client_id mismatch, got nil")
	}
	if !errors.Is(err, ErrPlatform) {
		t.Errorf("expected ErrPlatform, got %v", err)
	}
	var ae *AuthError
	if errors.As(err, &ae) {
		if !strings.Contains(ae.Message, "client_id mismatch") {
			t.Errorf("expected message to contain 'client_id mismatch', got %q", ae.Message)
		}
	}
}

// ---------------------------------------------------------------------------
// RefreshToken
// ---------------------------------------------------------------------------

func TestQQProvider_RefreshToken_EmptyRefreshToken(t *testing.T) {
	p := &qqProvider{
		appID:  "appid",
		appKey: "appkey",
		logger: &noopLogger{},
	}

	_, err := p.RefreshToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty refresh token")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestQQProvider_RefreshToken_Success(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch {
		case strings.Contains(r.URL.Path, "/oauth2.0/token"):
			q := r.URL.Query()
			if q.Get("grant_type") != "refresh_token" {
				t.Errorf("grant_type = %q, want %q", q.Get("grant_type"), "refresh_token")
			}
			if q.Get("client_id") != "test_appid" {
				t.Errorf("client_id = %q, want %q", q.Get("client_id"), "test_appid")
			}
			if q.Get("client_secret") != "test_appkey" {
				t.Errorf("client_secret = %q, want %q", q.Get("client_secret"), "test_appkey")
			}
			if q.Get("refresh_token") != "old_refresh_token" {
				t.Errorf("refresh_token = %q, want %q", q.Get("refresh_token"), "old_refresh_token")
			}
			_, _ = fmt.Fprint(w, "access_token=new_access_token&expires_in=7776000&refresh_token=new_refresh_token")

		case strings.Contains(r.URL.Path, "/oauth2.0/me"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id": "test_appid",
				"openid":    "refreshed_openid",
				"unionid":   "refreshed_unionid",
			})

		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:       "test_appid",
		appKey:      "test_appkey",
		redirectURL: "https://example.com/callback",
		httpClient:  ts.Client(),
		logger:      &noopLogger{},
		oauthBase:   ts.URL,
	}

	newToken, err := p.RefreshToken(context.Background(), "old_refresh_token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if newToken.AccessToken != "new_access_token" {
		t.Errorf("AccessToken = %q, want %q", newToken.AccessToken, "new_access_token")
	}
	if newToken.RefreshToken != "new_refresh_token" {
		t.Errorf("RefreshToken = %q, want %q", newToken.RefreshToken, "new_refresh_token")
	}
	if newToken.OpenID != "refreshed_openid" {
		t.Errorf("OpenID = %q, want %q", newToken.OpenID, "refreshed_openid")
	}
	if newToken.UnionID != "refreshed_unionid" {
		t.Errorf("UnionID = %q, want %q", newToken.UnionID, "refreshed_unionid")
	}
	if callCount != 2 {
		t.Errorf("expected 2 HTTP calls, got %d", callCount)
	}
}

// ---------------------------------------------------------------------------
// parseQQCallback
// ---------------------------------------------------------------------------

func TestParseQQCallback_RegularJSON(t *testing.T) {
	body := []byte(`{"client_id":"appid","openid":"oid","unionid":"uid"}`)
	m, err := parseQQCallback(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m["openid"] != "oid" {
		t.Errorf("openid = %v, want %q", m["openid"], "oid")
	}
}

func TestParseQQCallback_JSONP_WithSemicolon(t *testing.T) {
	body := []byte(`callback({"client_id":"appid","openid":"oid","unionid":"uid"});`)
	m, err := parseQQCallback(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m["openid"] != "oid" {
		t.Errorf("openid = %v, want %q", m["openid"], "oid")
	}
}

func TestParseQQCallback_JSONP_WithoutSemicolon(t *testing.T) {
	body := []byte(`callback({"client_id":"appid","openid":"oid"})`)
	m, err := parseQQCallback(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m["openid"] != "oid" {
		t.Errorf("openid = %v, want %q", m["openid"], "oid")
	}
}

func TestParseQQCallback_JSONP_WithSpaces(t *testing.T) {
	body := []byte(`callback( {"client_id":"appid","openid":"oid"} );`)
	m, err := parseQQCallback(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m["openid"] != "oid" {
		t.Errorf("openid = %v, want %q", m["openid"], "oid")
	}
}

func TestParseQQCallback_InvalidJSON(t *testing.T) {
	body := []byte(`not valid json`)
	_, err := parseQQCallback(body)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseQQCallback_JSONP_InvalidInner(t *testing.T) {
	body := []byte(`callback(not json);`)
	_, err := parseQQCallback(body)
	if err == nil {
		t.Fatal("expected error for invalid inner JSON")
	}
}

// ---------------------------------------------------------------------------
// toInt
// ---------------------------------------------------------------------------

func TestToInt(t *testing.T) {
	tests := []struct {
		in   any
		want int
	}{
		{float64(42), 42},
		{json.Number("99"), 99},
		{int(7), 7},
		{"123", 123},
		{"notanum", 0},
		{nil, 0},
		{true, 0},
	}
	for _, tt := range tests {
		if got := toInt(tt.in); got != tt.want {
			t.Errorf("toInt(%v) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ExchangeCode — network error
// ---------------------------------------------------------------------------

func TestQQProvider_ExchangeCode_NetworkError(t *testing.T) {
	p := &qqProvider{
		appID:       "appid",
		appKey:      "appkey",
		redirectURL: "https://example.com/callback",
		httpClient:  &http.Client{},
		logger:      &noopLogger{},
		oauthBase:   "http://127.0.0.1:1", // should fail to connect
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
// GetUserInfo — gender with non-standard value
// ---------------------------------------------------------------------------

func TestQQProvider_GetUserInfo_OtherGender(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ret":      0,
			"msg":      "",
			"nickname": "OtherGenderUser",
			"gender":   "其他",
		})
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:      "appid",
		appKey:     "appkey",
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		apiBase:    ts.URL,
	}

	info, err := p.GetUserInfo(context.Background(), &Token{AccessToken: "tok", OpenID: "oid"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Gender != GenderUnknown {
		t.Errorf("Gender = %v, want %v (GenderUnknown)", info.Gender, GenderUnknown)
	}
}

// ---------------------------------------------------------------------------
// Concurrency safety
// ---------------------------------------------------------------------------

func TestQQProvider_ConcurrentAccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2.0/token"):
			_, _ = fmt.Fprint(w, "access_token=tok&expires_in=7200&refresh_token=rtok")
		case strings.Contains(r.URL.Path, "/oauth2.0/me"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id": "appid",
				"openid":    "oid",
				"unionid":   "uid",
			})
		case strings.Contains(r.URL.Path, "/user/get_user_info"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ret":      0,
				"msg":      "",
				"nickname": "ConcurrentUser",
				"gender":   "男",
			})
		}
	}))
	defer ts.Close()

	p := &qqProvider{
		appID:       "appid",
		appKey:      "appkey",
		redirectURL: "https://example.com/callback",
		httpClient:  ts.Client(),
		logger:      &noopLogger{},
		oauthBase:   ts.URL,
		apiBase:     ts.URL,
	}

	const goroutines = 10
	errs := make(chan error, goroutines*3)

	for i := 0; i < goroutines; i++ {
		go func() {
			_, err := p.AuthURL("state")
			errs <- err
		}()
		go func() {
			_, err := p.ExchangeCode(context.Background(), "code")
			errs <- err
		}()
		go func() {
			_, err := p.GetUserInfo(context.Background(), &Token{AccessToken: "tok", OpenID: "oid"})
			errs <- err
		}()
	}

	for i := 0; i < goroutines*3; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent call %d returned error: %v", i, err)
		}
	}
}
