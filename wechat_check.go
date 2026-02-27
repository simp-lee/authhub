package authhub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// CheckWechatToken checks whether a WeChat access token is still valid by calling
// the WeChat token verification endpoint (sns/auth). It returns true if the token
// is valid (errcode == 0), false if the token is invalid or expired, and an error
// only when an actual network or transport failure occurs.
//
// opts can include WithHTTPClient and WithLogger to customize the HTTP client and logger.
func CheckWechatToken(ctx context.Context, accessToken, openID string, opts ...Option) (bool, error) {
	const providerName = "wechat_check"

	if accessToken == "" {
		return false, newAuthError(ErrKindInvalidConfig, providerName, "", "access token must not be empty", nil)
	}
	if openID == "" {
		return false, newAuthError(ErrKindInvalidConfig, providerName, "", "open id must not be empty", nil)
	}

	cfg := newProviderConfig(opts...)

	baseURL := wechatAPIBase
	if cfg.wechatCheckBaseURL != "" {
		baseURL = cfg.wechatCheckBaseURL
	}

	reqURL := fmt.Sprintf("%s/sns/auth?access_token=%s&openid=%s", baseURL, url.QueryEscape(accessToken), url.QueryEscape(openID))

	body, err := doGet(ctx, cfg.httpClient, reqURL, cfg.logger)
	if err != nil {
		if ae, ok := err.(*AuthError); ok && ae.Provider == "" {
			ae.Provider = providerName
		}
		return false, err
	}

	var resp wechatError
	if err := json.Unmarshal(body, &resp); err != nil {
		return false, newAuthError(ErrKindPlatform, providerName, "", fmt.Sprintf("parse auth response: %v", err), err)
	}

	return resp.Errcode == 0, nil
}

// withWechatCheckBaseURL is an internal Option used only in tests to override
// the WeChat API base URL for CheckWechatToken.
func withWechatCheckBaseURL(baseURL string) Option {
	return func(cfg *providerConfig) {
		cfg.wechatCheckBaseURL = baseURL
	}
}
