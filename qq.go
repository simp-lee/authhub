package authhub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

// QQ API endpoint constants.
const (
	qqDefaultBase = "https://graph.qq.com"
)

// qqProvider implements the Provider interface for QQ OAuth login.
type qqProvider struct {
	appID       string
	appKey      string
	redirectURL string
	httpClient  *http.Client
	logger      Logger
	apiBase     string // overridable for testing; defaults to qqDefaultBase
	oauthBase   string // overridable for testing; defaults to qqDefaultBase
}

// NewQQ creates a new QQ OAuth login provider.
// appID, appKey, and redirectURL must be non-empty.
func NewQQ(appID, appKey, redirectURL string, opts ...Option) (Provider, error) {
	if appID == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "qq", "", "appID must not be empty", nil)
	}
	if appKey == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "qq", "", "appKey must not be empty", nil)
	}
	if redirectURL == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "qq", "", "redirectURL must not be empty", nil)
	}

	cfg := newProviderConfig(opts...)

	return &qqProvider{
		appID:       appID,
		appKey:      appKey,
		redirectURL: redirectURL,
		httpClient:  cfg.httpClient,
		logger:      cfg.logger,
		apiBase:     qqDefaultBase,
		oauthBase:   qqDefaultBase,
	}, nil
}

// Name returns "qq".
func (p *qqProvider) Name() string {
	return "qq"
}

// AuthURL constructs the QQ OAuth authorization URL.
// state must be non-empty.
// opts are accepted for Provider interface compliance but are not applicable;
// QQ's authorize endpoint uses a fixed scope (get_user_info).
func (p *qqProvider) AuthURL(state string, opts ...AuthOption) (string, error) {
	if state == "" {
		return "", newAuthError(ErrKindInvalidConfig, "qq", "", "state must not be empty", nil)
	}

	u := fmt.Sprintf("%s/oauth2.0/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=get_user_info&state=%s",
		p.oauthBase,
		url.QueryEscape(p.appID),
		url.QueryEscape(p.redirectURL),
		url.QueryEscape(state),
	)

	return u, nil
}

// ExchangeCode exchanges an authorization code for an access token.
// It performs two steps: (1) get the token, (2) get the OpenID/UnionID.
func (p *qqProvider) ExchangeCode(ctx context.Context, code string) (*Token, error) {
	if code == "" {
		return nil, newAuthError(ErrKindInvalidCode, "qq", "", "code must not be empty", nil)
	}

	// Step 1: Get token.
	token, err := p.getToken(ctx, fmt.Sprintf(
		"%s/oauth2.0/token?grant_type=authorization_code&client_id=%s&client_secret=%s&code=%s&redirect_uri=%s",
		p.oauthBase, url.QueryEscape(p.appID), url.QueryEscape(p.appKey), url.QueryEscape(code), url.QueryEscape(p.redirectURL),
	))
	if err != nil {
		return nil, err
	}

	// Step 2: Get OpenID/UnionID.
	if err := p.fillOpenID(ctx, token); err != nil {
		return nil, err
	}

	return token, nil
}

// GetUserInfo retrieves the user's profile information using the provided token.
func (p *qqProvider) GetUserInfo(ctx context.Context, token *Token) (*UserInfo, error) {
	if token == nil {
		return nil, newAuthError(ErrKindInvalidConfig, "qq", "", "token must not be nil", nil)
	}

	reqURL := fmt.Sprintf("%s/user/get_user_info?access_token=%s&oauth_consumer_key=%s&openid=%s",
		p.apiBase, url.QueryEscape(token.AccessToken), url.QueryEscape(p.appID), url.QueryEscape(token.OpenID))

	body, err := doGet(ctx, p.httpClient, reqURL, p.logger)
	if err != nil {
		if ae, ok := err.(*AuthError); ok && ae.Provider == "" {
			ae.Provider = "qq"
		}
		return nil, err
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, newAuthError(ErrKindPlatform, "qq", "", fmt.Sprintf("parse userinfo response: %v", err), err)
	}

	// Check for error response: ret != 0.
	if ret, ok := raw["ret"]; ok {
		retVal := toInt(ret)
		if retVal != 0 {
			msg, _ := raw["msg"].(string)
			kind := ErrKindPlatform
			if retVal == 100016 {
				kind = ErrKindTokenExpired
			}
			return nil, newAuthError(kind, "qq", strconv.Itoa(retVal), msg, nil)
		}
	}

	// Map gender.
	var gender Gender
	switch raw["gender"] {
	case "男":
		gender = GenderMale
	case "女":
		gender = GenderFemale
	default:
		gender = GenderUnknown
	}

	nickname, _ := raw["nickname"].(string)
	avatar, _ := raw["figureurl_qq_2"].(string)
	province, _ := raw["province"].(string)
	city, _ := raw["city"].(string)

	info := &UserInfo{
		OpenID:   token.OpenID,
		UnionID:  token.UnionID,
		Nickname: nickname,
		Avatar:   avatar,
		Gender:   gender,
		Province: province,
		City:     city,
		Raw:      raw,
	}

	p.logger.Debug("qq userinfo retrieved",
		"provider", "qq",
		"openid", info.OpenID,
		"nickname", info.Nickname,
	)

	return info, nil
}

// RefreshToken refreshes an expired token and returns a new token.
func (p *qqProvider) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	if refreshToken == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "qq", "", "refreshToken must not be empty", nil)
	}

	// Step 1: Refresh the token.
	newToken, err := p.getToken(ctx, fmt.Sprintf(
		"%s/oauth2.0/token?grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s",
		p.oauthBase, url.QueryEscape(p.appID), url.QueryEscape(p.appKey), url.QueryEscape(refreshToken),
	))
	if err != nil {
		return nil, err
	}

	// Step 2: Get OpenID/UnionID.
	if err := p.fillOpenID(ctx, newToken); err != nil {
		return nil, err
	}

	return newToken, nil
}

// getToken sends a GET request to the given tokenURL and parses the response.
// QQ's token endpoint may return URL-encoded or JSON format.
func (p *qqProvider) getToken(ctx context.Context, tokenURL string) (*Token, error) {
	body, err := doGet(ctx, p.httpClient, tokenURL, p.logger)
	if err != nil {
		if ae, ok := err.(*AuthError); ok && ae.Provider == "" {
			ae.Provider = "qq"
		}
		return nil, err
	}

	// Try URL-encoded format first (QQ's default).
	values, urlErr := url.ParseQuery(string(body))
	if urlErr == nil && values.Get("access_token") != "" {
		return p.parseURLEncodedToken(values)
	}

	// Check for error in URL-encoded response even without access_token.
	if urlErr == nil {
		if errParam := values.Get("error"); errParam != "" {
			desc := values.Get("error_description")
			return nil, newAuthError(ErrKindPlatform, "qq", errParam, desc, nil)
		}
	}

	// Try JSON fallback.
	return p.parseJSONToken(body)
}

// parseURLEncodedToken parses a URL-encoded token response from QQ.
func (p *qqProvider) parseURLEncodedToken(values url.Values) (*Token, error) {
	if errParam := values.Get("error"); errParam != "" {
		desc := values.Get("error_description")
		return nil, newAuthError(ErrKindPlatform, "qq", errParam, desc, nil)
	}

	expiresInRaw := values.Get("expires_in")
	expiresIn, convErr := strconv.Atoi(expiresInRaw)
	if convErr != nil || expiresIn <= 0 {
		return nil, newAuthError(ErrKindPlatform, "qq", "", fmt.Sprintf("invalid expires_in in token response: %q", expiresInRaw), nil)
	}

	raw := make(map[string]any, len(values))
	for k := range values {
		raw[k] = values.Get(k)
	}

	token := &Token{
		AccessToken:  values.Get("access_token"),
		RefreshToken: values.Get("refresh_token"),
		ExpiresIn:    expiresIn,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second),
		Raw:          raw,
	}

	p.logger.Debug("qq token exchanged (url-encoded)",
		"provider", "qq",
		"expires_in", token.ExpiresIn,
	)

	return token, nil
}

// parseJSONToken parses a JSON token response from QQ.
func (p *qqProvider) parseJSONToken(body []byte) (*Token, error) {
	var jsonResp map[string]any
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return nil, newAuthError(ErrKindPlatform, "qq", "", fmt.Sprintf("parse token response: %v", err), err)
	}

	if errField, ok := jsonResp["error"]; ok {
		errCode := fmt.Sprintf("%v", errField)
		desc, _ := jsonResp["error_description"].(string)
		return nil, newAuthError(ErrKindPlatform, "qq", errCode, desc, nil)
	}

	accessToken, _ := jsonResp["access_token"].(string)
	if accessToken == "" {
		return nil, newAuthError(ErrKindPlatform, "qq", "", "empty access_token in JSON response", nil)
	}
	refreshToken, _ := jsonResp["refresh_token"].(string)
	expiresInRaw, ok := jsonResp["expires_in"]
	if !ok {
		return nil, newAuthError(ErrKindPlatform, "qq", "", "missing expires_in in JSON response", nil)
	}
	expiresIn := toInt(expiresInRaw)
	if expiresIn <= 0 {
		return nil, newAuthError(ErrKindPlatform, "qq", "", fmt.Sprintf("invalid expires_in in JSON response: %v", expiresInRaw), nil)
	}

	token := &Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second),
		Raw:          jsonResp,
	}

	p.logger.Debug("qq token exchanged (json)",
		"provider", "qq",
		"expires_in", token.ExpiresIn,
	)

	return token, nil
}

// fillOpenID calls the /oauth2.0/me endpoint to get the OpenID and UnionID,
// then fills them into the token.
func (p *qqProvider) fillOpenID(ctx context.Context, token *Token) error {
	meURL := fmt.Sprintf("%s/oauth2.0/me?access_token=%s&fmt=json&unionid=1",
		p.oauthBase, url.QueryEscape(token.AccessToken))

	body, err := doGet(ctx, p.httpClient, meURL, p.logger)
	if err != nil {
		if ae, ok := err.(*AuthError); ok && ae.Provider == "" {
			ae.Provider = "qq"
		}
		return err
	}

	data, err := parseQQCallback(body)
	if err != nil {
		return newAuthError(ErrKindPlatform, "qq", "", fmt.Sprintf("parse /me response: %v", err), err)
	}

	// Check for error in response.
	if errField, ok := data["error"]; ok {
		errCode := toInt(errField)
		if errCode != 0 {
			desc, _ := data["error_description"].(string)
			code := strconv.Itoa(errCode)
			var kind ErrorKind
			switch errCode {
			case 100016:
				kind = ErrKindTokenExpired
			default:
				kind = ErrKindPlatform
			}
			return newAuthError(kind, "qq", code, desc, nil)
		}
	}

	// Validate that the client_id in the response matches the configured appID.
	if clientID, ok := data["client_id"].(string); ok && clientID != p.appID {
		return newAuthError(ErrKindPlatform, "qq", "",
			fmt.Sprintf("client_id mismatch: got %q, want %q", clientID, p.appID), nil)
	}

	if openID, ok := data["openid"].(string); ok {
		token.OpenID = openID
	}
	if unionID, ok := data["unionid"].(string); ok {
		token.UnionID = unionID
	}

	if token.OpenID == "" {
		return newAuthError(ErrKindPlatform, "qq", "", "missing openid in /me response", nil)
	}

	p.logger.Debug("qq openid retrieved",
		"provider", "qq",
		"openid", token.OpenID,
	)

	return nil
}

// callbackRegexp matches the JSONP callback wrapper: callback(...) or callback(...);
var callbackRegexp = regexp.MustCompile(`(?s)^callback\s*\(\s*(.*?)\s*\)\s*;?\s*$`)

// parseQQCallback parses a QQ API response that may be wrapped in a JSONP callback.
// If the response starts with "callback(", the wrapper is stripped and the inner JSON is parsed.
// Otherwise, it is treated as regular JSON.
func parseQQCallback(body []byte) (map[string]any, error) {
	s := bytes.TrimSpace(body)

	if bytes.HasPrefix(s, []byte("callback")) {
		matches := callbackRegexp.FindSubmatch(s)
		if len(matches) > 1 {
			s = matches[1]
		}
	}

	var result map[string]any
	if err := json.Unmarshal(s, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return result, nil
}

// toInt converts a value (float64 or json.Number) to int.
func toInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case int:
		return n
	case string:
		i, _ := strconv.Atoi(n)
		return i
	default:
		return 0
	}
}
