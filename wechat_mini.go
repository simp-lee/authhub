package authhub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// wechatMiniProvider implements the Provider interface for WeChat Mini Program login.
// Unlike web/MP providers, mini programs do not use browser redirect flow and have
// no access_token in the code exchange response (jscode2session).
type wechatMiniProvider struct {
	wechatBaseProvider
	apiBase string // overridable for testing; defaults to wechatAPIBase
}

// NewWechatMini creates a new WeChat Mini Program login provider.
// Only appID and secret are required; mini programs do not use a redirect URL.
func NewWechatMini(appID, secret string, opts ...Option) (Provider, error) {
	if appID == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "wechat_mini", "", "appID must not be empty", nil)
	}
	if secret == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "wechat_mini", "", "secret must not be empty", nil)
	}

	cfg := newProviderConfig(opts...)

	return &wechatMiniProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:      appID,
			secret:     secret,
			httpClient: cfg.httpClient,
			logger:     cfg.logger,
			lang:       cfg.lang,
		},
		apiBase: wechatAPIBase,
	}, nil
}

// Name returns "wechat_mini".
func (p *wechatMiniProvider) Name() string {
	return "wechat_mini"
}

// AuthURL is not supported for mini programs.
// Mini programs obtain a code via wx.login() on the client side, not through a browser redirect.
func (p *wechatMiniProvider) AuthURL(state string, opts ...AuthOption) (string, error) {
	return "", newAuthError(ErrKindUnsupported, "wechat_mini", "", "mini programs do not support AuthURL, use wx.login() in the client", nil)
}

// wechatMiniSessionResponse represents the JSON response from jscode2session.
type wechatMiniSessionResponse struct {
	wechatError
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid"`
}

// ExchangeCode exchanges a wx.login() code for a session via jscode2session.
// The returned Token has an empty AccessToken and a zero ExpiresAt (IsExpired() returns true).
// The session_key is stored in Token.Raw["session_key"].
func (p *wechatMiniProvider) ExchangeCode(ctx context.Context, code string) (*Token, error) {
	if code == "" {
		return nil, newAuthError(ErrKindInvalidCode, "wechat_mini", "", "code must not be empty", nil)
	}
	reqURL := fmt.Sprintf("%s/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code",
		p.apiBase, url.QueryEscape(p.appID), url.QueryEscape(p.secret), url.QueryEscape(code))

	body, err := doGet(ctx, p.httpClient, reqURL, p.logger)
	if err != nil {
		if ae, ok := err.(*AuthError); ok && ae.Provider == "" {
			ae.Provider = "wechat_mini"
		}
		return nil, err
	}

	var resp wechatMiniSessionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newAuthError(ErrKindPlatform, "wechat_mini", "", fmt.Sprintf("parse jscode2session response: %v", err), err)
	}

	if resp.Errcode != 0 {
		return nil, mapWechatError("wechat_mini", resp.Errcode, resp.Errmsg)
	}

	// Build the raw map from the full response.
	var raw map[string]any
	_ = json.Unmarshal(body, &raw)

	token := &Token{
		OpenID:  resp.OpenID,
		UnionID: resp.UnionID,
		Raw:     raw,
	}

	p.logger.Debug("wechat mini session exchanged",
		"provider", "wechat_mini",
		"openid", token.OpenID,
	)

	return token, nil
}

// GetUserInfo returns user information derived from the token.
// WeChat deprecated server-side userinfo retrieval for mini programs,
// so only OpenID and UnionID (from the token) are returned.
func (p *wechatMiniProvider) GetUserInfo(ctx context.Context, token *Token) (*UserInfo, error) {
	if token == nil {
		return nil, newAuthError(ErrKindInvalidConfig, "wechat_mini", "", "token must not be nil", nil)
	}
	return &UserInfo{
		OpenID:  token.OpenID,
		UnionID: token.UnionID,
	}, nil
}

// RefreshToken is not supported for mini programs.
func (p *wechatMiniProvider) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	return nil, newAuthError(ErrKindUnsupported, "wechat_mini", "", "mini programs do not support RefreshToken", nil)
}
