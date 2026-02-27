package authhub

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// mapWechatError
// ---------------------------------------------------------------------------

func TestMapWechatError(t *testing.T) {
	tests := []struct {
		name     string
		errcode  int
		errmsg   string
		wantKind ErrorKind
		wantCode string
		wantIs   error
	}{
		{"40029 invalid code", 40029, "invalid code", ErrKindInvalidCode, "40029", ErrInvalidCode},
		{"40163 code used", 40163, "code been used", ErrKindInvalidCode, "40163", ErrInvalidCode},
		{"41008 missing code", 41008, "missing code", ErrKindInvalidCode, "41008", ErrInvalidCode},
		{"42001 access_token expired", 42001, "access_token expired", ErrKindTokenExpired, "42001", ErrTokenExpired},
		{"42002 refresh_token expired", 42002, "refresh_token expired", ErrKindTokenExpired, "42002", ErrTokenExpired},
		{"40030 invalid refresh_token", 40030, "invalid refresh_token", ErrKindTokenExpired, "40030", ErrTokenExpired},
		{"42003 code expired", 42003, "code expired", ErrKindTokenExpired, "42003", ErrTokenExpired},
		{"40001 invalid AppSecret", 40001, "invalid credential", ErrKindPlatform, "40001", ErrPlatform},
		{"40226 high risk", 40226, "high risk operation", ErrKindPlatform, "40226", ErrPlatform},
		{"99999 unknown", 99999, "unknown error", ErrKindPlatform, "99999", ErrPlatform},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapWechatError("wechat_web", tt.errcode, tt.errmsg)
			if err.Kind != tt.wantKind {
				t.Errorf("Kind = %v, want %v", err.Kind, tt.wantKind)
			}
			if err.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", err.Code, tt.wantCode)
			}
			if err.Provider != "wechat_web" {
				t.Errorf("Provider = %q, want %q", err.Provider, "wechat_web")
			}
			if !errors.Is(err, tt.wantIs) {
				t.Errorf("errors.Is(err, %v) = false", tt.wantIs)
			}
		})
	}
}

func TestMapWechatError_SentinelMatch(t *testing.T) {
	err := mapWechatError("wechat_web", 40029, "invalid code")
	if !errors.Is(err, ErrInvalidCode) {
		t.Error("expected errors.Is(err, ErrInvalidCode) to be true")
	}

	err = mapWechatError("wechat_web", 42001, "expired")
	if !errors.Is(err, ErrTokenExpired) {
		t.Error("expected errors.Is(err, ErrTokenExpired) to be true")
	}

	err = mapWechatError("wechat_web", 40030, "invalid refresh_token")
	if !errors.Is(err, ErrTokenExpired) {
		t.Error("expected errors.Is(err, ErrTokenExpired) to be true")
	}

	err = mapWechatError("wechat_web", 40226, "high risk")
	if !errors.Is(err, ErrPlatform) {
		t.Error("expected errors.Is(err, ErrPlatform) to be true")
	}
}

// ---------------------------------------------------------------------------
// wechatExchangeToken
// ---------------------------------------------------------------------------

func TestWechatExchangeToken_Success(t *testing.T) {
	resp := map[string]any{
		"access_token":  "test_access_token",
		"expires_in":    7200.0,
		"refresh_token": "test_refresh_token",
		"openid":        "oTestOpenID",
		"unionid":       "oTestUnionID",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	before := time.Now()
	token, err := wechatExchangeToken(context.Background(), ts.Client(), &noopLogger{}, "wechat_web", ts.URL+"/sns/oauth2/access_token?appid=test")
	after := time.Now()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token.AccessToken != "test_access_token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "test_access_token")
	}
	if token.RefreshToken != "test_refresh_token" {
		t.Errorf("RefreshToken = %q, want %q", token.RefreshToken, "test_refresh_token")
	}
	if token.ExpiresIn != 7200 {
		t.Errorf("ExpiresIn = %d, want %d", token.ExpiresIn, 7200)
	}
	if token.OpenID != "oTestOpenID" {
		t.Errorf("OpenID = %q, want %q", token.OpenID, "oTestOpenID")
	}
	if token.UnionID != "oTestUnionID" {
		t.Errorf("UnionID = %q, want %q", token.UnionID, "oTestUnionID")
	}

	// ExpiresAt should be approximately now + 7200s
	expectedExpiry := before.Add(7200 * time.Second)
	if token.ExpiresAt.Before(before.Add(7199*time.Second)) || token.ExpiresAt.After(after.Add(7201*time.Second)) {
		t.Errorf("ExpiresAt = %v, expected near %v", token.ExpiresAt, expectedExpiry)
	}

	// Raw should contain full response
	if token.Raw == nil {
		t.Fatal("Raw should not be nil")
	}
	if token.Raw["openid"] != "oTestOpenID" {
		t.Errorf("Raw[openid] = %v, want %q", token.Raw["openid"], "oTestOpenID")
	}
}

func TestWechatExchangeToken_APIError(t *testing.T) {
	resp := map[string]any{
		"errcode": 40029,
		"errmsg":  "invalid code",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	_, err := wechatExchangeToken(context.Background(), ts.Client(), &noopLogger{}, "wechat_web", ts.URL+"/token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

func TestWechatExchangeToken_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer ts.Close()

	_, err := wechatExchangeToken(context.Background(), ts.Client(), &noopLogger{}, "wechat_web", ts.URL+"/token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestWechatExchangeToken_ContextCancel(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := wechatExchangeToken(ctx, ts.Client(), &noopLogger{}, "wechat_web", ts.URL+"/token")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

// ---------------------------------------------------------------------------
// wechatGetUserInfo
// ---------------------------------------------------------------------------

func TestWechatGetUserInfo_Success(t *testing.T) {
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
		// Verify query parameters
		q := r.URL.Query()
		if q.Get("access_token") != "test_token" {
			t.Errorf("access_token = %q, want %q", q.Get("access_token"), "test_token")
		}
		if q.Get("openid") != "oTestOpenID" {
			t.Errorf("openid = %q, want %q", q.Get("openid"), "oTestOpenID")
		}
		if q.Get("lang") != "zh_CN" {
			t.Errorf("lang = %q, want %q", q.Get("lang"), "zh_CN")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	// Override the wechatAPIBase for testing is not possible since it's a const,
	// so we test via the full function by providing a mock server.
	// We need to test using the actual function which builds the URL from wechatAPIBase.
	// For proper unit testing, we'll call wechatGetUserInfo with the mock base URL.
	info, err := wechatGetUserInfo(context.Background(), ts.Client(), &noopLogger{}, "wechat_web", ts.URL, "test_token", "oTestOpenID", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.OpenID != "oTestOpenID" {
		t.Errorf("OpenID = %q, want %q", info.OpenID, "oTestOpenID")
	}
	if info.UnionID != "oTestUnionID" {
		t.Errorf("UnionID = %q, want %q", info.UnionID, "oTestUnionID")
	}
	if info.Nickname != "TestUser" {
		t.Errorf("Nickname = %q, want %q", info.Nickname, "TestUser")
	}
	if info.Avatar != "https://example.com/avatar.jpg" {
		t.Errorf("Avatar = %q, want %q", info.Avatar, "https://example.com/avatar.jpg")
	}
	if info.Gender != GenderMale {
		t.Errorf("Gender = %v, want %v", info.Gender, GenderMale)
	}
	if info.Province != "Guangdong" {
		t.Errorf("Province = %q, want %q", info.Province, "Guangdong")
	}
	if info.City != "Shenzhen" {
		t.Errorf("City = %q, want %q", info.City, "Shenzhen")
	}
	if info.Raw == nil {
		t.Fatal("Raw should not be nil")
	}
}

func TestWechatGetUserInfo_GenderNormalization(t *testing.T) {
	tests := []struct {
		name string
		sex  float64
		want Gender
	}{
		{"male", 1, GenderMale},
		{"female", 2, GenderFemale},
		{"unknown zero", 0, GenderUnknown},
		{"unknown three", 3, GenderUnknown},
		{"unknown other", 99, GenderUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := map[string]any{
				"openid":     "oTestOpenID",
				"nickname":   "Test",
				"headimgurl": "",
				"sex":        tt.sex,
			}
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer ts.Close()

			info, err := wechatGetUserInfo(context.Background(), ts.Client(), &noopLogger{}, "wechat_web", ts.URL, "token", "oTestOpenID", "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.Gender != tt.want {
				t.Errorf("Gender = %v, want %v", info.Gender, tt.want)
			}
		})
	}
}

func TestWechatGetUserInfo_APIError(t *testing.T) {
	resp := map[string]any{
		"errcode": 42001,
		"errmsg":  "access_token expired",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	_, err := wechatGetUserInfo(context.Background(), ts.Client(), &noopLogger{}, "wechat_web", ts.URL, "expired_token", "oTestOpenID", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestWechatGetUserInfo_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer ts.Close()

	_, err := wechatGetUserInfo(context.Background(), ts.Client(), &noopLogger{}, "wechat_web", ts.URL, "token", "openid", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestWechatGetUserInfo_CustomLang(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("lang") != "en" {
			t.Errorf("lang = %q, want %q", q.Get("lang"), "en")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"openid":     "oTestOpenID",
			"nickname":   "TestUser",
			"headimgurl": "",
			"sex":        0,
		})
	}))
	defer ts.Close()

	info, err := wechatGetUserInfo(context.Background(), ts.Client(), &noopLogger{}, "wechat_web", ts.URL, "token", "oTestOpenID", "en")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OpenID != "oTestOpenID" {
		t.Errorf("OpenID = %q, want %q", info.OpenID, "oTestOpenID")
	}
}

func TestWechatGetUserInfo_EmptyLangDefaultsToZhCN(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("lang") != "zh_CN" {
			t.Errorf("lang = %q, want %q", q.Get("lang"), "zh_CN")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"openid":     "oTestOpenID",
			"nickname":   "TestUser",
			"headimgurl": "",
			"sex":        0,
		})
	}))
	defer ts.Close()

	_, err := wechatGetUserInfo(context.Background(), ts.Client(), &noopLogger{}, "wechat_web", ts.URL, "token", "oTestOpenID", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// wechatBaseProvider
// ---------------------------------------------------------------------------

func TestWechatBaseProvider_Fields(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	logger := &noopLogger{}

	bp := wechatBaseProvider{
		appID:       "test_app_id",
		secret:      "test_secret",
		redirectURL: "https://example.com/callback",
		httpClient:  client,
		logger:      logger,
	}

	if bp.appID != "test_app_id" {
		t.Errorf("appID = %q, want %q", bp.appID, "test_app_id")
	}
	if bp.secret != "test_secret" {
		t.Errorf("secret = %q, want %q", bp.secret, "test_secret")
	}
	if bp.redirectURL != "https://example.com/callback" {
		t.Errorf("redirectURL = %q, want %q", bp.redirectURL, "https://example.com/callback")
	}
	if bp.httpClient != client {
		t.Error("httpClient not set correctly")
	}
	if bp.logger != logger {
		t.Error("logger not set correctly")
	}
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

func TestWechatConstants(t *testing.T) {
	if wechatAPIBase != "https://api.weixin.qq.com" {
		t.Errorf("wechatAPIBase = %q", wechatAPIBase)
	}
	if wechatQRConnectURL != "https://open.weixin.qq.com/connect/qrconnect" {
		t.Errorf("wechatQRConnectURL = %q", wechatQRConnectURL)
	}
	if wechatOAuth2AuthorizeURL != "https://open.weixin.qq.com/connect/oauth2/authorize" {
		t.Errorf("wechatOAuth2AuthorizeURL = %q", wechatOAuth2AuthorizeURL)
	}
}
