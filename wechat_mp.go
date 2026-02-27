package authhub

import (
	"context"
	"fmt"
	"net/url"
)

// wechatMPProvider implements the Provider interface for WeChat Official Account
// (MP) OAuth login (public account web authorization).
type wechatMPProvider struct {
	wechatBaseProvider
	apiBase string // overridable for testing; defaults to wechatAPIBase
}

// NewWechatMP creates a new WeChat Official Account (MP) login provider.
// appID, secret, and redirectURL must be non-empty.
func NewWechatMP(appID, secret, redirectURL string, opts ...Option) (Provider, error) {
	if appID == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "wechat_mp", "", "appID must not be empty", nil)
	}
	if secret == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "wechat_mp", "", "secret must not be empty", nil)
	}
	if redirectURL == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "wechat_mp", "", "redirectURL must not be empty", nil)
	}

	cfg := newProviderConfig(opts...)

	return &wechatMPProvider{
		wechatBaseProvider: wechatBaseProvider{
			appID:       appID,
			secret:      secret,
			redirectURL: redirectURL,
			httpClient:  cfg.httpClient,
			logger:      cfg.logger,
			lang:        cfg.lang,
		},
		apiBase: wechatAPIBase,
	}, nil
}

// Name returns "wechat_mp".
func (p *wechatMPProvider) Name() string {
	return "wechat_mp"
}

// AuthURL constructs the WeChat Official Account OAuth2 authorization URL.
// state must be non-empty.
// The default scope is "snsapi_userinfo"; use WithScope("snsapi_base") for silent authorization.
func (p *wechatMPProvider) AuthURL(state string, opts ...AuthOption) (string, error) {
	if state == "" {
		return "", newAuthError(ErrKindInvalidConfig, "wechat_mp", "", "state must not be empty", nil)
	}

	scope := "snsapi_userinfo"
	ac := newAuthConfig(opts...)
	if ac.scope != "" {
		scope = ac.scope
	}

	u := fmt.Sprintf("%s?appid=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s#wechat_redirect",
		wechatOAuth2AuthorizeURL,
		url.QueryEscape(p.appID),
		url.QueryEscape(p.redirectURL),
		url.QueryEscape(scope),
		url.QueryEscape(state),
	)

	return u, nil
}

// ExchangeCode exchanges an authorization code for an access token.
func (p *wechatMPProvider) ExchangeCode(ctx context.Context, code string) (*Token, error) {
	if code == "" {
		return nil, newAuthError(ErrKindInvalidCode, "wechat_mp", "", "code must not be empty", nil)
	}
	tokenURL := fmt.Sprintf("%s/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code",
		p.apiBase, url.QueryEscape(p.appID), url.QueryEscape(p.secret), url.QueryEscape(code))

	return wechatExchangeToken(ctx, p.httpClient, p.logger, "wechat_mp", tokenURL)
}

// GetUserInfo retrieves the user's profile information using the provided token.
func (p *wechatMPProvider) GetUserInfo(ctx context.Context, token *Token) (*UserInfo, error) {
	if token == nil {
		return nil, newAuthError(ErrKindInvalidConfig, "wechat_mp", "", "token must not be nil", nil)
	}
	return wechatGetUserInfo(ctx, p.httpClient, p.logger, "wechat_mp", p.apiBase, token.AccessToken, token.OpenID, p.lang)
}

// RefreshToken refreshes an expired token and returns a new token.
func (p *wechatMPProvider) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	if refreshToken == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "wechat_mp", "", "refreshToken must not be empty", nil)
	}
	refreshURL := fmt.Sprintf("%s/sns/oauth2/refresh_token?appid=%s&refresh_token=%s&grant_type=refresh_token",
		p.apiBase, url.QueryEscape(p.appID), url.QueryEscape(refreshToken))

	return wechatExchangeToken(ctx, p.httpClient, p.logger, "wechat_mp", refreshURL)
}
