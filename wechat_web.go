package authhub

import (
	"context"
	"fmt"
	"net/url"
)

// wechatWebProvider implements the Provider interface for WeChat PC QR code login
// (open platform web application).
type wechatWebProvider struct {
	wechatBaseProvider
	apiBase string // overridable for testing; defaults to wechatAPIBase
}

// NewWechatWeb creates a new WeChat PC QR code login provider.
// appID, secret, and redirectURL must be non-empty.
func NewWechatWeb(appID, secret, redirectURL string, opts ...Option) (Provider, error) {
	if appID == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "wechat_web", "", "appID must not be empty", nil)
	}
	if secret == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "wechat_web", "", "secret must not be empty", nil)
	}
	if redirectURL == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "wechat_web", "", "redirectURL must not be empty", nil)
	}

	cfg := newProviderConfig(opts...)

	return &wechatWebProvider{
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

// Name returns "wechat_web".
func (p *wechatWebProvider) Name() string {
	return "wechat_web"
}

// AuthURL constructs the WeChat PC QR code authorization URL.
// state must be non-empty.
func (p *wechatWebProvider) AuthURL(state string, opts ...AuthOption) (string, error) {
	if state == "" {
		return "", newAuthError(ErrKindInvalidConfig, "wechat_web", "", "state must not be empty", nil)
	}

	u := fmt.Sprintf("%s?appid=%s&redirect_uri=%s&response_type=code&scope=snsapi_login&state=%s#wechat_redirect",
		wechatQRConnectURL,
		url.QueryEscape(p.appID),
		url.QueryEscape(p.redirectURL),
		url.QueryEscape(state),
	)

	return u, nil
}

// ExchangeCode exchanges an authorization code for an access token.
func (p *wechatWebProvider) ExchangeCode(ctx context.Context, code string) (*Token, error) {
	if code == "" {
		return nil, newAuthError(ErrKindInvalidCode, "wechat_web", "", "code must not be empty", nil)
	}
	tokenURL := fmt.Sprintf("%s/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code",
		p.apiBase, url.QueryEscape(p.appID), url.QueryEscape(p.secret), url.QueryEscape(code))

	return wechatExchangeToken(ctx, p.httpClient, p.logger, "wechat_web", tokenURL)
}

// GetUserInfo retrieves the user's profile information using the provided token.
func (p *wechatWebProvider) GetUserInfo(ctx context.Context, token *Token) (*UserInfo, error) {
	if token == nil {
		return nil, newAuthError(ErrKindInvalidConfig, "wechat_web", "", "token must not be nil", nil)
	}
	return wechatGetUserInfo(ctx, p.httpClient, p.logger, "wechat_web", p.apiBase, token.AccessToken, token.OpenID, p.lang)
}

// RefreshToken refreshes an expired token and returns a new token.
func (p *wechatWebProvider) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	if refreshToken == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "wechat_web", "", "refreshToken must not be empty", nil)
	}
	refreshURL := fmt.Sprintf("%s/sns/oauth2/refresh_token?appid=%s&refresh_token=%s&grant_type=refresh_token",
		p.apiBase, url.QueryEscape(p.appID), url.QueryEscape(refreshToken))

	return wechatExchangeToken(ctx, p.httpClient, p.logger, "wechat_web", refreshURL)
}
