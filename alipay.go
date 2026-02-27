package authhub

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Alipay gateway and auth URL constants.
const (
	alipayGatewayProduction = "https://openapi.alipay.com/gateway.do"
	alipayGatewaySandbox    = "https://openapi-sandbox.dl.alipaydev.com/gateway.do"
	alipayAuthURL           = "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm"
	alipayAuthTypeDefault   = "AUTHACCOUNT"
)

// alipayProvider implements the Provider interface for Alipay OAuth login.
type alipayProvider struct {
	appID       string
	privateKey  *rsa.PrivateKey
	redirectURL string
	httpClient  *http.Client
	logger      Logger
	gateway     string
	credentials alipayCredentials
	isSandbox   bool
}

// WithAlipayPublicKey returns an Option that sets the Alipay public key
// for signature verification in non-certificate mode.
func WithAlipayPublicKey(publicKey string) Option {
	return func(cfg *providerConfig) {
		cfg.alipayPublicKey = publicKey
	}
}

// WithCertMode returns an Option that enables certificate mode for Alipay.
// appCert is the application certificate, alipayCert is the Alipay public
// key certificate, and rootCert is the Alipay root certificate.
func WithCertMode(appCert, alipayCert, rootCert string) Option {
	return func(cfg *providerConfig) {
		cfg.alipayAppCert = appCert
		cfg.alipayCert = alipayCert
		cfg.alipayRootCert = rootCert
		cfg.alipayCertMode = true
	}
}

// WithSandbox returns an Option that sets the Alipay gateway to the sandbox
// environment for testing.
func WithSandbox() Option {
	return func(cfg *providerConfig) {
		cfg.alipaySandbox = true
	}
}

// NewAlipay creates a new Alipay OAuth login provider.
// appID, privateKeyStr, and redirectURL must be non-empty.
// Exactly one of WithAlipayPublicKey or WithCertMode must be provided.
func NewAlipay(appID, privateKeyStr, redirectURL string, opts ...Option) (Provider, error) {
	if appID == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "appID must not be empty", nil)
	}
	if privateKeyStr == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "privateKey must not be empty", nil)
	}
	if redirectURL == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "redirectURL must not be empty", nil)
	}

	privKey, err := parsePrivateKey(privateKeyStr)
	if err != nil {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "invalid private key: "+err.Error(), err)
	}

	cfg := newProviderConfig(opts...)

	// Validate: must provide exactly one of public key or cert mode
	hasPublicKey := cfg.alipayPublicKey != ""
	hasCertMode := cfg.alipayCertMode

	if !hasPublicKey && !hasCertMode {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "must provide either WithAlipayPublicKey or WithCertMode", nil)
	}
	if hasPublicKey && hasCertMode {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "must provide either WithAlipayPublicKey or WithCertMode, not both", nil)
	}

	var creds alipayCredentials

	if hasPublicKey {
		pubKey, err := parsePublicKey(cfg.alipayPublicKey)
		if err != nil {
			return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "invalid alipay public key: "+err.Error(), err)
		}
		creds.alipayPublicKey = pubKey
	}

	if hasCertMode {
		c, err := initCertCredentials(cfg)
		if err != nil {
			return nil, err
		}
		creds = c
	}

	gateway := alipayGatewayProduction
	if cfg.alipaySandbox {
		gateway = alipayGatewaySandbox
	}

	return &alipayProvider{
		appID:       appID,
		privateKey:  privKey,
		redirectURL: redirectURL,
		httpClient:  cfg.httpClient,
		logger:      cfg.logger,
		gateway:     gateway,
		credentials: creds,
		isSandbox:   cfg.alipaySandbox,
	}, nil
}

// initCertCredentials initializes alipayCredentials from certificate PEM data
// in the provider config. It calculates SNs and extracts public keys.
func initCertCredentials(cfg *providerConfig) (alipayCredentials, error) {
	appCertSN, err := calculateCertSN(cfg.alipayAppCert)
	if err != nil {
		return alipayCredentials{}, newAuthError(ErrKindInvalidConfig, "alipay", "", "invalid app certificate: "+err.Error(), err)
	}
	if appCertSN == "" {
		return alipayCredentials{}, newAuthError(ErrKindInvalidConfig, "alipay", "", "appCertSN is empty", nil)
	}

	rootCertSN, err := calculateRootCertSN(cfg.alipayRootCert)
	if err != nil {
		return alipayCredentials{}, newAuthError(ErrKindInvalidConfig, "alipay", "", "invalid root certificate: "+err.Error(), err)
	}
	if rootCertSN == "" {
		return alipayCredentials{}, newAuthError(ErrKindInvalidConfig, "alipay", "", "alipayRootCertSN is empty", nil)
	}

	pubKey, err := extractPublicKeyFromCert(cfg.alipayCert)
	if err != nil {
		return alipayCredentials{}, newAuthError(ErrKindInvalidConfig, "alipay", "", "invalid alipay certificate: "+err.Error(), err)
	}

	alipayCertSN, err := calculateCertSN(cfg.alipayCert)
	if err != nil {
		return alipayCredentials{}, newAuthError(ErrKindInvalidConfig, "alipay", "", "invalid alipay certificate SN: "+err.Error(), err)
	}

	return alipayCredentials{
		appCertSN:        appCertSN,
		alipayRootCertSN: rootCertSN,
		isCertMode:       true,
		certPublicKeys: map[string]*rsa.PublicKey{
			alipayCertSN: pubKey,
		},
	}, nil
}

// Name returns "alipay".
func (p *alipayProvider) Name() string {
	return "alipay"
}

// AuthURL constructs the Alipay OAuth authorization URL.
// state must be non-empty.
// Supported AuthOption: WithScope (defaults to "auth_user"; Alipay also supports "auth_base").
func (p *alipayProvider) AuthURL(state string, opts ...AuthOption) (string, error) {
	if state == "" {
		return "", newAuthError(ErrKindInvalidConfig, "alipay", "", "state must not be empty", nil)
	}

	cfg := newAuthConfig(opts...)

	scope := cfg.scope
	if scope == "" {
		scope = "auth_user"
	}

	u, _ := url.Parse(alipayAuthURL)
	q := u.Query()
	q.Set("app_id", p.appID)
	q.Set("auth_type", alipayAuthTypeDefault)
	q.Set("scope", scope)
	q.Set("redirect_uri", p.redirectURL)
	q.Set("state", state)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// ExchangeCode exchanges an authorization code for an access token.
func (p *alipayProvider) ExchangeCode(ctx context.Context, code string) (*Token, error) {
	if code == "" {
		return nil, newAuthError(ErrKindInvalidCode, "alipay", "", "code must not be empty", nil)
	}

	bizParams := map[string]string{
		"grant_type": "authorization_code",
		"code":       code,
	}

	data, err := p.callAlipayAPI(ctx, "alipay.system.oauth.token", bizParams, "alipay_system_oauth_token_response")
	if err != nil {
		return nil, err
	}

	return p.parseTokenResponse(data)
}

// GetUserInfo retrieves the user's profile information using the provided token.
func (p *alipayProvider) GetUserInfo(ctx context.Context, token *Token) (*UserInfo, error) {
	if token == nil {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "token must not be nil", nil)
	}

	bizParams := map[string]string{
		"auth_token": token.AccessToken,
	}

	data, err := p.callAlipayAPI(ctx, "alipay.user.info.share", bizParams, "alipay_user_info_share_response")
	if err != nil {
		return nil, err
	}

	openID, _ := data["open_id"].(string)
	unionID, _ := data["union_id"].(string)
	nickname, _ := data["nick_name"].(string)
	avatar, _ := data["avatar"].(string)
	genderStr, _ := data["gender"].(string)
	province, _ := data["province"].(string)
	city, _ := data["city"].(string)

	var gender Gender
	switch genderStr {
	case "m":
		gender = GenderMale
	case "f":
		gender = GenderFemale
	default:
		gender = GenderUnknown
	}

	// Build raw map — copy all response fields not already mapped to UserInfo
	mapped := map[string]bool{
		"code": true, "msg": true, "open_id": true, "union_id": true,
		"nick_name": true, "avatar": true, "gender": true,
		"province": true, "city": true,
	}
	raw := make(map[string]any)
	for k, v := range data {
		if !mapped[k] {
			raw[k] = v
		}
	}

	info := &UserInfo{
		OpenID:   openID,
		UnionID:  unionID,
		Nickname: nickname,
		Avatar:   avatar,
		Gender:   gender,
		Province: province,
		City:     city,
		Raw:      raw,
	}

	p.logger.Debug("alipay userinfo retrieved",
		"provider", "alipay",
		"openid", info.OpenID,
		"nickname", info.Nickname,
	)

	return info, nil
}

// RefreshToken refreshes an expired token and returns a new token.
func (p *alipayProvider) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	if refreshToken == "" {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "refreshToken must not be empty", nil)
	}

	bizParams := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}

	data, err := p.callAlipayAPI(ctx, "alipay.system.oauth.token", bizParams, "alipay_system_oauth_token_response")
	if err != nil {
		return nil, err
	}

	return p.parseTokenResponse(data)
}

// buildCommonParams builds the common system parameters for an Alipay API call.
func (p *alipayProvider) buildCommonParams(method string) map[string]string {
	params := map[string]string{
		"app_id":    p.appID,
		"method":    method,
		"charset":   "utf-8",
		"sign_type": "RSA2",
		"timestamp": time.Now().Format("2006-01-02 15:04:05"),
		"version":   "1.0",
		"format":    "JSON",
	}

	if p.credentials.isCertMode {
		params["app_cert_sn"] = p.credentials.appCertSN
		params["alipay_root_cert_sn"] = p.credentials.alipayRootCertSN
	}

	return params
}

// callAlipayAPI performs a complete Alipay API call: builds params, signs,
// sends POST request, verifies response signature, and extracts the response node.
func (p *alipayProvider) callAlipayAPI(ctx context.Context, method string, bizParams map[string]string, nodeName string) (map[string]any, error) {
	commonParams := p.buildCommonParams(method)

	values, err := buildAlipayRequestParams(bizParams, commonParams, p.privateKey)
	if err != nil {
		return nil, err
	}

	body, err := doPostForm(ctx, p.httpClient, p.gateway, values, p.logger)
	if err != nil {
		if ae, ok := err.(*AuthError); ok && ae.Provider == "" {
			ae.Provider = "alipay"
		}
		return nil, err
	}

	p.logger.Debug("alipay API response",
		"provider", "alipay",
		"method", method,
		"body_length", len(body),
	)

	// Verify signature
	if err := p.verifyResponse(body, nodeName); err != nil {
		return nil, err
	}

	// Parse the response node
	data, err := p.extractResponseNode(body, nodeName)
	if err != nil {
		return nil, err
	}

	// Check for error response
	if errCode, ok := data["code"].(string); ok && errCode != "10000" {
		msg, _ := data["msg"].(string)
		subCode, _ := data["sub_code"].(string)
		subMsg, _ := data["sub_msg"].(string)

		errMessage := msg
		if subMsg != "" {
			errMessage = subMsg
		}

		code := errCode
		if subCode != "" {
			code = subCode
		}

		kind := mapAlipayErrorKind(subCode)
		return nil, newAuthError(kind, "alipay", code, errMessage, nil)
	}

	return data, nil
}

// verifyResponse verifies the signature of an Alipay API response.
func (p *alipayProvider) verifyResponse(body []byte, nodeName string) error {
	if p.credentials.isCertMode {
		content, sign, certSN, err := extractSignContent(body, nodeName)
		if err != nil {
			return err
		}

		// Look up public key by cert SN
		pubKey, ok := p.credentials.certPublicKeys[certSN]
		if !ok {
			// Cert SN mismatch — reject verification in cert mode.
			var knownSNs []string
			for sn := range p.credentials.certPublicKeys {
				knownSNs = append(knownSNs, sn)
			}
			p.logger.Warn("alipay cert SN mismatch, verification rejected",
				"provider", "alipay",
				"response_cert_sn", certSN,
				"known_cert_sns", strings.Join(knownSNs, ","),
			)
			return newAuthError(ErrKindSignature, "alipay", "", "alipay_cert_sn not found in configured certs, please update alipay public certificate", nil)
		}

		return verifyRSA2Signature(pubKey, content, sign)
	}

	return verifyAlipayResponse(body, nodeName, p.credentials.alipayPublicKey)
}

// extractResponseNode parses the JSON response body and extracts the specified node.
func (p *alipayProvider) extractResponseNode(body []byte, nodeName string) (map[string]any, error) {
	var fullResp map[string]any
	if err := json.Unmarshal(body, &fullResp); err != nil {
		return nil, newAuthError(ErrKindPlatform, "alipay", "", fmt.Sprintf("parse response: %v", err), err)
	}

	nodeRaw, ok := fullResp[nodeName]
	if !ok {
		return nil, newAuthError(ErrKindPlatform, "alipay", "", "response node not found: "+nodeName, nil)
	}

	node, ok := nodeRaw.(map[string]any)
	if !ok {
		return nil, newAuthError(ErrKindPlatform, "alipay", "", "response node is not an object: "+nodeName, nil)
	}

	return node, nil
}

// parseTokenResponse parses the token-related fields from an Alipay API response node.
func (p *alipayProvider) parseTokenResponse(data map[string]any) (*Token, error) {
	accessToken, ok := data["access_token"].(string)
	if !ok || accessToken == "" {
		return nil, newAuthError(ErrKindPlatform, "alipay", "", "invalid token response: missing or non-string access_token", nil)
	}
	refreshToken, _ := data["refresh_token"].(string)
	openID, _ := data["open_id"].(string)
	unionID, _ := data["union_id"].(string)

	// expires_in may be a string in Alipay's response
	var expiresIn int
	switch v := data["expires_in"].(type) {
	case string:
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return nil, newAuthError(ErrKindPlatform, "alipay", "", fmt.Sprintf("invalid token response: expires_in is not a valid integer: %q", v), err)
		}
		expiresIn = parsed
	case float64:
		expiresIn = int(v)
	case nil:
		// optional field in some responses
	default:
		return nil, newAuthError(ErrKindPlatform, "alipay", "", fmt.Sprintf("invalid token response: unsupported expires_in type %T", v), nil)
	}

	// Build raw map — copy all response fields not already mapped to Token
	mapped := map[string]bool{
		"code": true, "msg": true, "sub_code": true, "sub_msg": true,
		"access_token": true, "refresh_token": true, "expires_in": true,
		"open_id": true, "union_id": true,
	}
	raw := make(map[string]any)
	for k, v := range data {
		if !mapped[k] {
			raw[k] = v
		}
	}

	token := &Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second),
		OpenID:       openID,
		UnionID:      unionID,
		Raw:          raw,
	}

	p.logger.Debug("alipay token exchanged",
		"provider", "alipay",
		"openid", token.OpenID,
		"expires_in", token.ExpiresIn,
	)

	return token, nil
}

// mapAlipayErrorKind maps Alipay sub_code to ErrorKind.
func mapAlipayErrorKind(subCode string) ErrorKind {
	switch subCode {
	case "isv.invalid-auth-code":
		return ErrKindInvalidCode
	case "isv.code-expired":
		return ErrKindInvalidCode
	case "isv.code-is-reused":
		return ErrKindInvalidCode
	case "isv.code-is-used":
		return ErrKindInvalidCode
	case "isv.invalid-app-id":
		return ErrKindInvalidConfig
	case "isv.invalid-refresh-token":
		return ErrKindTokenExpired
	case "isv.invalid-auth-token":
		return ErrKindTokenExpired
	case "isv.insufficient-isv-permissions":
		return ErrKindInvalidConfig
	case "isv.invalid-signature":
		return ErrKindSignature
	default:
		return ErrKindPlatform
	}
}
