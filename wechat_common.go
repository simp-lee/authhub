package authhub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// WeChat API endpoint constants.
const (
	wechatAPIBase            = "https://api.weixin.qq.com"
	wechatQRConnectURL       = "https://open.weixin.qq.com/connect/qrconnect"
	wechatOAuth2AuthorizeURL = "https://open.weixin.qq.com/connect/oauth2/authorize"
)

// wechatError represents an error response from the WeChat API.
type wechatError struct {
	Errcode int    `json:"errcode"`
	Errmsg  string `json:"errmsg"`
}

// mapWechatError maps a WeChat error code to an *AuthError with the appropriate ErrorKind.
func mapWechatError(providerName string, errcode int, errmsg string) *AuthError {
	code := strconv.Itoa(errcode)
	var kind ErrorKind
	switch errcode {
	case 40029: // invalid code
		kind = ErrKindInvalidCode
	case 40163: // code already used
		kind = ErrKindInvalidCode
	case 41008: // missing code
		kind = ErrKindInvalidCode
	case 42001: // access_token expired
		kind = ErrKindTokenExpired
	case 42002: // refresh_token expired
		kind = ErrKindTokenExpired
	case 40030: // invalid refresh_token
		kind = ErrKindTokenExpired
	case 42003: // code expired
		kind = ErrKindTokenExpired
	case 40001: // invalid AppSecret
		kind = ErrKindPlatform
	case 40226: // high risk operation blocked
		kind = ErrKindPlatform
	default:
		kind = ErrKindPlatform
	}
	return newAuthError(kind, providerName, code, errmsg, nil)
}

// wechatTokenResponse is used to parse the WeChat token exchange JSON response.
type wechatTokenResponse struct {
	wechatError
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenID       string `json:"openid"`
	UnionID      string `json:"unionid"`
	Scope        string `json:"scope"`
}

// wechatExchangeToken performs the common token exchange logic for all WeChat variants.
// It sends a GET request to tokenURL, parses the JSON response, checks for errors,
// and fills a Token struct including ExpiresAt calculation.
func wechatExchangeToken(ctx context.Context, client *http.Client, logger Logger, providerName string, tokenURL string) (*Token, error) {
	body, err := doGet(ctx, client, tokenURL, logger)
	if err != nil {
		// Set the provider on network errors from doGet.
		if ae, ok := err.(*AuthError); ok && ae.Provider == "" {
			ae.Provider = providerName
		}
		return nil, err
	}

	var resp wechatTokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newAuthError(ErrKindPlatform, providerName, "", fmt.Sprintf("parse token response: %v", err), err)
	}

	if resp.Errcode != 0 {
		return nil, mapWechatError(providerName, resp.Errcode, resp.Errmsg)
	}

	// Build the raw map from the full response.
	var raw map[string]any
	_ = json.Unmarshal(body, &raw)

	token := &Token{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.ExpiresIn,
		ExpiresAt:    time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second),
		OpenID:       resp.OpenID,
		UnionID:      resp.UnionID,
		Raw:          raw,
	}

	logger.Debug("wechat token exchanged",
		"provider", providerName,
		"openid", token.OpenID,
		"expires_in", token.ExpiresIn,
	)

	return token, nil
}

// wechatUserInfoResponse is used to parse the WeChat userinfo JSON response.
type wechatUserInfoResponse struct {
	wechatError
	OpenID     string `json:"openid"`
	UnionID    string `json:"unionid"`
	Nickname   string `json:"nickname"`
	HeadImgURL string `json:"headimgurl"`
	Sex        int    `json:"sex"`
	Province   string `json:"province"`
	City       string `json:"city"`
}

// wechatGetUserInfo retrieves user profile information from the WeChat API.
// apiBase is the base URL (e.g. wechatAPIBase) to allow testing with httptest.
// lang controls the language for returned fields (e.g. "zh_CN", "en", "zh_TW");
// if empty it defaults to "zh_CN" for backward compatibility.
func wechatGetUserInfo(ctx context.Context, client *http.Client, logger Logger, providerName string, apiBase string, accessToken, openID, lang string) (*UserInfo, error) {
	if lang == "" {
		lang = "zh_CN"
	}
	reqURL := fmt.Sprintf("%s/sns/userinfo?access_token=%s&openid=%s&lang=%s", apiBase, url.QueryEscape(accessToken), url.QueryEscape(openID), url.QueryEscape(lang))

	body, err := doGet(ctx, client, reqURL, logger)
	if err != nil {
		if ae, ok := err.(*AuthError); ok && ae.Provider == "" {
			ae.Provider = providerName
		}
		return nil, err
	}

	var resp wechatUserInfoResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, newAuthError(ErrKindPlatform, providerName, "", fmt.Sprintf("parse userinfo response: %v", err), err)
	}

	if resp.Errcode != 0 {
		return nil, mapWechatError(providerName, resp.Errcode, resp.Errmsg)
	}

	// Build the raw map from the full response.
	var raw map[string]any
	_ = json.Unmarshal(body, &raw)

	// Normalize gender: 1→Male, 2→Female, else→Unknown.
	var gender Gender
	switch resp.Sex {
	case 1:
		gender = GenderMale
	case 2:
		gender = GenderFemale
	default:
		gender = GenderUnknown
	}

	info := &UserInfo{
		OpenID:   resp.OpenID,
		UnionID:  resp.UnionID,
		Nickname: resp.Nickname,
		Avatar:   resp.HeadImgURL,
		Gender:   gender,
		Province: resp.Province,
		City:     resp.City,
		Raw:      raw,
	}

	logger.Debug("wechat userinfo retrieved",
		"provider", providerName,
		"openid", info.OpenID,
		"nickname", info.Nickname,
	)

	return info, nil
}

// wechatBaseProvider holds common configuration shared by all WeChat provider variants.
// It is intended to be embedded by wechatWebProvider, wechatMPProvider, and wechatMiniProvider.
type wechatBaseProvider struct {
	appID       string
	secret      string
	redirectURL string
	httpClient  *http.Client
	logger      Logger
	lang        string // language for userinfo API; defaults to "zh_CN" when empty
}
