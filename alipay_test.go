package authhub

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

// Compile-time interface compliance check.
var _ Provider = (*alipayProvider)(nil)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// testAlipayKeyPair holds a key pair for testing.
type testAlipayKeyPair struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	privatePEM string
	publicPEM  string
}

type testWarnLogger struct {
	warnMessages []string
	warnArgs     [][]any
}

func (l *testWarnLogger) Debug(msg string, args ...any) {}
func (l *testWarnLogger) Info(msg string, args ...any)  {}
func (l *testWarnLogger) Error(msg string, args ...any) {}
func (l *testWarnLogger) Warn(msg string, args ...any) {
	l.warnMessages = append(l.warnMessages, msg)
	l.warnArgs = append(l.warnArgs, args)
}

// testNewAlipayKeyPair generates a new RSA key pair for testing.
func testNewAlipayKeyPair(t *testing.T) *testAlipayKeyPair {
	t.Helper()
	key := testGenerateRSAKey(t)
	return &testAlipayKeyPair{
		privateKey: key,
		publicKey:  &key.PublicKey,
		privatePEM: testEncodePKCS1PEM(t, key),
		publicPEM:  testEncodePKIXPublicKeyPEM(t, &key.PublicKey),
	}
}

// testAlipaySignResponse signs an Alipay response node and returns the complete response JSON.
func testAlipaySignResponse(t *testing.T, key *rsa.PrivateKey, nodeName string, nodeData map[string]any) []byte {
	t.Helper()
	nodeJSON, err := json.Marshal(nodeData)
	if err != nil {
		t.Fatalf("marshal node data: %v", err)
	}

	h := sha256.Sum256(nodeJSON)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("sign response: %v", err)
	}
	sign := base64.StdEncoding.EncodeToString(sig)

	resp := map[string]any{
		nodeName: json.RawMessage(nodeJSON),
		"sign":   sign,
	}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return body
}

// testAlipaySignResponseWithCertSN signs a response and includes alipay_cert_sn.
func testAlipaySignResponseWithCertSN(t *testing.T, key *rsa.PrivateKey, nodeName string, nodeData map[string]any, certSN string) []byte {
	t.Helper()
	nodeJSON, err := json.Marshal(nodeData)
	if err != nil {
		t.Fatalf("marshal node data: %v", err)
	}

	h := sha256.Sum256(nodeJSON)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("sign response: %v", err)
	}
	sign := base64.StdEncoding.EncodeToString(sig)

	resp := map[string]any{
		nodeName:         json.RawMessage(nodeJSON),
		"sign":           sign,
		"alipay_cert_sn": certSN,
	}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return body
}

// testAlipayVerifyRequest verifies that an Alipay request has the expected common parameters.
func testAlipayVerifyRequest(t *testing.T, values url.Values, expectedMethod string, publicKey *rsa.PublicKey) {
	t.Helper()

	if values.Get("app_id") == "" {
		t.Error("missing app_id")
	}
	if values.Get("method") != expectedMethod {
		t.Errorf("method = %q, want %q", values.Get("method"), expectedMethod)
	}
	if values.Get("charset") != "utf-8" {
		t.Errorf("charset = %q, want %q", values.Get("charset"), "utf-8")
	}
	if values.Get("sign_type") != "RSA2" {
		t.Errorf("sign_type = %q, want %q", values.Get("sign_type"), "RSA2")
	}
	if values.Get("version") != "1.0" {
		t.Errorf("version = %q, want %q", values.Get("version"), "1.0")
	}
	if values.Get("format") != "JSON" {
		t.Errorf("format = %q, want %q", values.Get("format"), "JSON")
	}
	if values.Get("timestamp") == "" {
		t.Error("missing timestamp")
	}
	if values.Get("sign") == "" {
		t.Error("missing sign")
	}

	// Verify signature
	sign := values.Get("sign")
	params := make(map[string]string)
	for k := range values {
		if k == "sign" {
			continue
		}
		params[k] = values.Get(k)
	}
	content := buildTestSignContent(params)
	h := sha256.Sum256([]byte(content))
	sigBytes, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		t.Fatalf("decode sign base64: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, h[:], sigBytes); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

// buildTestSignContent builds sign content for verification in tests.
func buildTestSignContent(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf strings.Builder
	first := true
	for _, k := range keys {
		v := params[k]
		if v == "" {
			continue
		}
		if !first {
			buf.WriteByte('&')
		}
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(v)
		first = false
	}
	return buf.String()
}

// testAssertRawFields checks that the given keys in raw match expected string values.
func testAssertRawFields(t *testing.T, raw map[string]any, expected map[string]string) {
	t.Helper()
	for k, want := range expected {
		if raw[k] != want {
			t.Errorf("Raw[%s] = %v, want %q", k, raw[k], want)
		}
	}
}

// testAlipayNewCertSuite generates a full certificate suite for testing.
type testAlipayCertSuite struct {
	keyPair     *testAlipayKeyPair
	appCertPEM  string
	appCertSN   string
	aliCertPEM  string
	aliCertSN   string
	rootCertPEM string
	rootCertSN  string
}

func testNewAlipayCertSuite(t *testing.T) *testAlipayCertSuite {
	t.Helper()
	kp := testNewAlipayKeyPair(t)

	appSubject := pkix.Name{
		CommonName:   "App Cert",
		Organization: []string{"Test App"},
		Country:      []string{"CN"},
	}
	appCertPEM := testGenerateSelfSignedCert(t, kp.privateKey, appSubject, x509.SHA256WithRSA)

	aliSubject := pkix.Name{
		CommonName:   "Alipay Cert",
		Organization: []string{"Alipay"},
		Country:      []string{"CN"},
	}
	aliCertPEM := testGenerateSelfSignedCertWithSerial(t, kp.privateKey, aliSubject, big.NewInt(987654321), x509.SHA256WithRSA)

	rootSubject := pkix.Name{
		CommonName:   "Root CA",
		Organization: []string{"Root Org"},
		Country:      []string{"CN"},
	}
	rootCertPEM := testGenerateSelfSignedCertWithSerial(t, kp.privateKey, rootSubject, big.NewInt(111111111), x509.SHA256WithRSA)

	appSN, err := calculateCertSN(appCertPEM)
	if err != nil {
		t.Fatalf("calculateCertSN(app): %v", err)
	}
	aliSN, err := calculateCertSN(aliCertPEM)
	if err != nil {
		t.Fatalf("calculateCertSN(ali): %v", err)
	}
	rootSN, err := calculateRootCertSN(rootCertPEM)
	if err != nil {
		t.Fatalf("calculateRootCertSN: %v", err)
	}

	return &testAlipayCertSuite{
		keyPair:     kp,
		appCertPEM:  appCertPEM,
		appCertSN:   appSN,
		aliCertPEM:  aliCertPEM,
		aliCertSN:   aliSN,
		rootCertPEM: rootCertPEM,
		rootCertSN:  rootSN,
	}
}

// ---------------------------------------------------------------------------
// NewAlipay — constructor validation
// ---------------------------------------------------------------------------

func TestNewAlipay_PublicKeyMode_Success(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	p, err := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.Name() != "alipay" {
		t.Errorf("Name() = %q, want %q", p.Name(), "alipay")
	}
}

func TestNewAlipay_CertMode_Success(t *testing.T) {
	cs := testNewAlipayCertSuite(t)
	p, err := NewAlipay("app123", cs.keyPair.privatePEM, "https://example.com/callback",
		WithCertMode(cs.appCertPEM, cs.aliCertPEM, cs.rootCertPEM),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.Name() != "alipay" {
		t.Errorf("Name() = %q, want %q", p.Name(), "alipay")
	}

	// Verify cert mode was correctly set
	ap := p.(*alipayProvider)
	if !ap.credentials.isCertMode {
		t.Error("expected cert mode to be true")
	}
	if ap.credentials.appCertSN == "" {
		t.Error("expected non-empty appCertSN")
	}
	if ap.credentials.alipayRootCertSN == "" {
		t.Error("expected non-empty alipayRootCertSN")
	}
}

func TestNewAlipay_EmptyAppID(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	_, err := NewAlipay("", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
	)
	if err == nil {
		t.Fatal("expected error for empty appID")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewAlipay_EmptyPrivateKey(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	_, err := NewAlipay("app123", "", "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
	)
	if err == nil {
		t.Fatal("expected error for empty privateKey")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewAlipay_EmptyRedirectURL(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	_, err := NewAlipay("app123", kp.privatePEM, "",
		WithAlipayPublicKey(kp.publicPEM),
	)
	if err == nil {
		t.Fatal("expected error for empty redirectURL")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewAlipay_InvalidPrivateKey(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	_, err := NewAlipay("app123", "invalid-key", "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
	)
	if err == nil {
		t.Fatal("expected error for invalid private key")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewAlipay_NeitherPublicKeyNorCertMode(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	_, err := NewAlipay("app123", kp.privatePEM, "https://example.com/callback")
	if err == nil {
		t.Fatal("expected error for missing credential mode")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
	ae := err.(*AuthError)
	if !strings.Contains(ae.Message, "must provide either") {
		t.Errorf("unexpected error message: %s", ae.Message)
	}
}

func TestNewAlipay_BothPublicKeyAndCertMode(t *testing.T) {
	cs := testNewAlipayCertSuite(t)
	_, err := NewAlipay("app123", cs.keyPair.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(cs.keyPair.publicPEM),
		WithCertMode(cs.appCertPEM, cs.aliCertPEM, cs.rootCertPEM),
	)
	if err == nil {
		t.Fatal("expected error for both public key and cert mode")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
	ae := err.(*AuthError)
	if !strings.Contains(ae.Message, "not both") {
		t.Errorf("unexpected error message: %s", ae.Message)
	}
}

func TestNewAlipay_InvalidAlipayPublicKey(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	_, err := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey("invalid-public-key"),
	)
	if err == nil {
		t.Fatal("expected error for invalid alipay public key")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewAlipay_InvalidAppCert(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	_, err := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithCertMode("invalid-cert", "invalid-cert", "invalid-cert"),
	)
	if err == nil {
		t.Fatal("expected error for invalid certificates")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewAlipay_WithSandbox(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	p, err := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
		WithSandbox(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ap := p.(*alipayProvider)
	if ap.gateway != alipayGatewaySandbox {
		t.Errorf("gateway = %q, want %q", ap.gateway, alipayGatewaySandbox)
	}
	if !ap.isSandbox {
		t.Error("expected isSandbox to be true")
	}
}

func TestNewAlipay_WithOptions(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	client := &http.Client{Timeout: 30 * time.Second}
	logger := &noopLogger{}
	p, err := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
		WithHTTPClient(client),
		WithLogger(logger),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ap := p.(*alipayProvider)
	if ap.httpClient != client {
		t.Error("custom HTTP client not set")
	}
}

func TestNewAlipay_DefaultGateway(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	p, err := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ap := p.(*alipayProvider)
	if ap.gateway != alipayGatewayProduction {
		t.Errorf("gateway = %q, want %q", ap.gateway, alipayGatewayProduction)
	}
}

// ---------------------------------------------------------------------------
// Name
// ---------------------------------------------------------------------------

func TestAlipayProvider_Name(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	p, _ := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
	)
	if p.Name() != "alipay" {
		t.Errorf("Name() = %q, want %q", p.Name(), "alipay")
	}
}

// ---------------------------------------------------------------------------
// AuthURL
// ---------------------------------------------------------------------------

func TestAlipayProvider_AuthURL_Success(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	p, _ := NewAlipay("test_appid", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
	)

	got, err := p.AuthURL("test_state")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("invalid URL: %v", err)
	}

	if u.Scheme != "https" || u.Host != "openauth.alipay.com" {
		t.Errorf("unexpected base URL: %s", got)
	}
	if u.Path != "/oauth2/publicAppAuthorize.htm" {
		t.Errorf("unexpected path: %s", u.Path)
	}

	q := u.Query()
	if q.Get("app_id") != "test_appid" {
		t.Errorf("app_id = %q, want %q", q.Get("app_id"), "test_appid")
	}
	if q.Get("auth_type") != alipayAuthTypeDefault {
		t.Errorf("auth_type = %q, want %q", q.Get("auth_type"), alipayAuthTypeDefault)
	}
	if q.Get("scope") != "auth_user" {
		t.Errorf("scope = %q, want %q", q.Get("scope"), "auth_user")
	}
	if q.Get("redirect_uri") != "https://example.com/callback" {
		t.Errorf("redirect_uri = %q, want %q", q.Get("redirect_uri"), "https://example.com/callback")
	}
	if q.Get("state") != "test_state" {
		t.Errorf("state = %q, want %q", q.Get("state"), "test_state")
	}
}

func TestAlipayProvider_AuthURL_EmptyState(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	p, _ := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
	)

	_, err := p.AuthURL("")
	if err == nil {
		t.Fatal("expected error for empty state")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestAlipayProvider_AuthURL_StateEncoded(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	p, _ := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
	)

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

func TestAlipayProvider_AuthURL_WithScope(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	p, _ := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
	)

	got, err := p.AuthURL("state123", WithScope("auth_base"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("invalid URL: %v", err)
	}
	if u.Query().Get("auth_type") != alipayAuthTypeDefault {
		t.Errorf("auth_type = %q, want %q", u.Query().Get("auth_type"), alipayAuthTypeDefault)
	}
	if u.Query().Get("scope") != "auth_base" {
		t.Errorf("scope = %q, want %q", u.Query().Get("scope"), "auth_base")
	}
}

func TestAlipayProvider_AuthURL_DefaultScope(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	p, _ := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
	)

	got, err := p.AuthURL("state123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("invalid URL: %v", err)
	}
	if u.Query().Get("auth_type") != alipayAuthTypeDefault {
		t.Errorf("auth_type = %q, want %q", u.Query().Get("auth_type"), alipayAuthTypeDefault)
	}
	if u.Query().Get("scope") != "auth_user" {
		t.Errorf("scope = %q, want %q", u.Query().Get("scope"), "auth_user")
	}
}

func TestAlipayProvider_AuthURL_RedirectURIEncoded(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	p, _ := NewAlipay("app123", kp.privatePEM, "https://example.com/callback?foo=bar",
		WithAlipayPublicKey(kp.publicPEM),
	)

	got, err := p.AuthURL("state123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(got, "redirect_uri="+url.QueryEscape("https://example.com/callback?foo=bar")) {
		t.Errorf("redirect_uri not properly encoded in URL: %s", got)
	}
}

// ---------------------------------------------------------------------------
// ExchangeCode — Public Key Mode
// ---------------------------------------------------------------------------

func TestAlipayProvider_ExchangeCode_EmptyCode(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	p, _ := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
	)

	_, err := p.ExchangeCode(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty code")
	}
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

func TestAlipayProvider_ExchangeCode_Success(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	tokenResp := map[string]any{
		"code":          "10000",
		"msg":           "Success",
		"access_token":  "access_token_value",
		"refresh_token": "refresh_token_value",
		"expires_in":    "3600",
		"open_id":       "openid_123",
		"user_id":       "userid_456",
		"union_id":      "unionid_789",
		"auth_start":    "2026-01-01 00:00:00",
		"re_expires_in": "86400",
		"extra_field":   "kept_in_raw",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify it's a POST
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		// Parse form
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}

		// Verify common params
		testAlipayVerifyRequest(t, r.Form, "alipay.system.oauth.token", &kp.privateKey.PublicKey)

		// Verify biz params
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q, want %q", r.Form.Get("grant_type"), "authorization_code")
		}
		if r.Form.Get("code") != "test_code" {
			t.Errorf("code = %q, want %q", r.Form.Get("code"), "test_code")
		}

		body := testAlipaySignResponse(t, kp.privateKey, "alipay_system_oauth_token_response", tokenResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	token, err := p.ExchangeCode(context.Background(), "test_code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token.AccessToken != "access_token_value" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "access_token_value")
	}
	if token.RefreshToken != "refresh_token_value" {
		t.Errorf("RefreshToken = %q, want %q", token.RefreshToken, "refresh_token_value")
	}
	if token.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want %d", token.ExpiresIn, 3600)
	}
	if token.OpenID != "openid_123" {
		t.Errorf("OpenID = %q, want %q", token.OpenID, "openid_123")
	}
	if token.UnionID != "unionid_789" {
		t.Errorf("UnionID = %q, want %q", token.UnionID, "unionid_789")
	}
	if token.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt should be in the future")
	}
	testAssertRawFields(t, token.Raw, map[string]string{
		"user_id":       "userid_456",
		"auth_start":    "2026-01-01 00:00:00",
		"re_expires_in": "86400",
		"extra_field":   "kept_in_raw",
	})
}

func TestAlipayProvider_ExchangeCode_ErrorResponse(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	errorResp := map[string]any{
		"code":     "40004",
		"msg":      "Business Failed",
		"sub_code": "isv.invalid-auth-code",
		"sub_msg":  "无效的授权码",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := testAlipaySignResponse(t, kp.privateKey, "alipay_system_oauth_token_response", errorResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	_, err := p.ExchangeCode(context.Background(), "bad_code")
	if err == nil {
		t.Fatal("expected error for invalid code")
	}
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
	ae := err.(*AuthError)
	if ae.Code != "isv.invalid-auth-code" {
		t.Errorf("Code = %q, want %q", ae.Code, "isv.invalid-auth-code")
	}
}

func TestAlipayProvider_ExchangeCode_CodeExpired(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	errorResp := map[string]any{
		"code":     "40004",
		"msg":      "Business Failed",
		"sub_code": "isv.code-expired",
		"sub_msg":  "授权码已过期",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := testAlipaySignResponse(t, kp.privateKey, "alipay_system_oauth_token_response", errorResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	_, err := p.ExchangeCode(context.Background(), "expired_code")
	if err == nil {
		t.Fatal("expected error for expired code")
	}
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

func TestAlipayProvider_ExchangeCode_InvalidAppID(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	errorResp := map[string]any{
		"code":     "40004",
		"msg":      "Business Failed",
		"sub_code": "isv.invalid-app-id",
		"sub_msg":  "无效的AppID",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := testAlipaySignResponse(t, kp.privateKey, "alipay_system_oauth_token_response", errorResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	_, err := p.ExchangeCode(context.Background(), "some_code")
	if err == nil {
		t.Fatal("expected error for invalid app id")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestAlipayProvider_ExchangeCode_PlatformError(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	errorResp := map[string]any{
		"code":     "40004",
		"msg":      "Business Failed",
		"sub_code": "isv.some-other-error",
		"sub_msg":  "其他错误",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := testAlipaySignResponse(t, kp.privateKey, "alipay_system_oauth_token_response", errorResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	_, err := p.ExchangeCode(context.Background(), "some_code")
	if err == nil {
		t.Fatal("expected error for platform error")
	}
	if !errors.Is(err, ErrPlatform) {
		t.Errorf("expected ErrPlatform, got %v", err)
	}
}

func TestAlipayProvider_ExchangeCode_NetworkError(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: &http.Client{Timeout: 1 * time.Millisecond},
		logger:     &noopLogger{},
		gateway:    "http://192.0.2.1:1/gateway.do", // unreachable
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	_, err := p.ExchangeCode(context.Background(), "test_code")
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !errors.Is(err, ErrNetwork) {
		t.Errorf("expected ErrNetwork, got %v", err)
	}
	// Verify provider is set
	ae := err.(*AuthError)
	if ae.Provider != "alipay" {
		t.Errorf("Provider = %q, want %q", ae.Provider, "alipay")
	}
}

func TestAlipayProvider_ExchangeCode_SignatureVerificationFailed(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	otherKey := testGenerateRSAKey(t)

	tokenResp := map[string]any{
		"code":         "10000",
		"msg":          "Success",
		"access_token": "access_token_value",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sign with a different key
		body := testAlipaySignResponse(t, otherKey, "alipay_system_oauth_token_response", tokenResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	_, err := p.ExchangeCode(context.Background(), "test_code")
	if err == nil {
		t.Fatal("expected error for signature verification failure")
	}
	if !errors.Is(err, ErrSignature) {
		t.Errorf("expected ErrSignature, got %v", err)
	}
}

func TestAlipayProvider_ExchangeCode_ExpiresInAsFloat(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	// Test with expires_in as a number (float64 from JSON)
	tokenResp := map[string]any{
		"code":          "10000",
		"msg":           "Success",
		"access_token":  "access_token_value",
		"refresh_token": "refresh_token_value",
		"expires_in":    float64(7200),
		"open_id":       "openid_123",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := testAlipaySignResponse(t, kp.privateKey, "alipay_system_oauth_token_response", tokenResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	token, err := p.ExchangeCode(context.Background(), "test_code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.ExpiresIn != 7200 {
		t.Errorf("ExpiresIn = %d, want %d", token.ExpiresIn, 7200)
	}
}

// ---------------------------------------------------------------------------
// ExchangeCode — Certificate Mode
// ---------------------------------------------------------------------------

func TestAlipayProvider_ExchangeCode_CertMode_Success(t *testing.T) {
	cs := testNewAlipayCertSuite(t)

	tokenResp := map[string]any{
		"code":          "10000",
		"msg":           "Success",
		"access_token":  "cert_access_token",
		"refresh_token": "cert_refresh_token",
		"expires_in":    "3600",
		"open_id":       "cert_openid",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}

		// Verify cert mode params
		if r.Form.Get("app_cert_sn") != cs.appCertSN {
			t.Errorf("app_cert_sn = %q, want %q", r.Form.Get("app_cert_sn"), cs.appCertSN)
		}
		if r.Form.Get("alipay_root_cert_sn") != cs.rootCertSN {
			t.Errorf("alipay_root_cert_sn = %q, want %q", r.Form.Get("alipay_root_cert_sn"), cs.rootCertSN)
		}

		body := testAlipaySignResponseWithCertSN(t, cs.keyPair.privateKey, "alipay_system_oauth_token_response", tokenResp, cs.aliCertSN)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: cs.keyPair.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			appCertSN:        cs.appCertSN,
			alipayRootCertSN: cs.rootCertSN,
			isCertMode:       true,
			certPublicKeys: map[string]*rsa.PublicKey{
				cs.aliCertSN: &cs.keyPair.privateKey.PublicKey,
			},
		},
	}

	token, err := p.ExchangeCode(context.Background(), "test_code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token.AccessToken != "cert_access_token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "cert_access_token")
	}
}

func TestAlipayProvider_ExchangeCode_CertMode_CertSNMismatch(t *testing.T) {
	cs := testNewAlipayCertSuite(t)
	logger := &testWarnLogger{}

	tokenResp := map[string]any{
		"code":          "10000",
		"msg":           "Success",
		"access_token":  "cert_access_token",
		"refresh_token": "cert_refresh_token",
		"expires_in":    "3600",
		"open_id":       "cert_openid",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a different cert SN (simulating cert rotation)
		body := testAlipaySignResponseWithCertSN(t, cs.keyPair.privateKey, "alipay_system_oauth_token_response", tokenResp, "unknown_cert_sn")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: cs.keyPair.privateKey,
		httpClient: ts.Client(),
		logger:     logger,
		gateway:    ts.URL,
		credentials: alipayCredentials{
			appCertSN:        cs.appCertSN,
			alipayRootCertSN: cs.rootCertSN,
			isCertMode:       true,
			certPublicKeys: map[string]*rsa.PublicKey{
				cs.aliCertSN: &cs.keyPair.privateKey.PublicKey,
			},
		},
	}

	token, err := p.ExchangeCode(context.Background(), "test_code")
	if err == nil {
		t.Fatal("expected error for cert SN mismatch")
	}
	if token != nil {
		t.Fatalf("token = %#v, want nil", token)
	}
	if !errors.Is(err, ErrSignature) {
		t.Errorf("expected ErrSignature, got %v", err)
	}

	if len(logger.warnMessages) == 0 {
		t.Fatal("expected cert SN mismatch warning log")
	}
	if logger.warnMessages[0] != "alipay cert SN mismatch, verification rejected" {
		t.Errorf("Warn message = %q, want %q", logger.warnMessages[0], "alipay cert SN mismatch, verification rejected")
	}
	if len(logger.warnArgs[0]) == 0 {
		t.Fatal("expected warning log args")
	}
	warnKV := map[string]any{}
	for i := 0; i+1 < len(logger.warnArgs[0]); i += 2 {
		k, ok := logger.warnArgs[0][i].(string)
		if !ok {
			continue
		}
		warnKV[k] = logger.warnArgs[0][i+1]
	}
	if warnKV["response_cert_sn"] != "unknown_cert_sn" {
		t.Errorf("Warn response_cert_sn = %v, want %q", warnKV["response_cert_sn"], "unknown_cert_sn")
	}
	knownSN, ok := warnKV["known_cert_sns"].(string)
	if !ok || !strings.Contains(knownSN, cs.aliCertSN) {
		t.Errorf("Warn known_cert_sns = %v, want to contain %q", warnKV["known_cert_sns"], cs.aliCertSN)
	}
}

func TestAlipayProvider_ExchangeCode_MissingAccessToken_FailFast(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	tokenResp := map[string]any{
		"code":       "10000",
		"msg":        "Success",
		"expires_in": "3600",
		"open_id":    "openid_123",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := testAlipaySignResponse(t, kp.privateKey, "alipay_system_oauth_token_response", tokenResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	_, err := p.ExchangeCode(context.Background(), "test_code")
	if err == nil {
		t.Fatal("expected error for missing access_token")
	}
	if !errors.Is(err, ErrPlatform) {
		t.Errorf("expected ErrPlatform, got %v", err)
	}
}

func TestAlipayProvider_ExchangeCode_InvalidExpiresIn_FailFast(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	tokenResp := map[string]any{
		"code":         "10000",
		"msg":          "Success",
		"access_token": "access_token_value",
		"expires_in":   "not_a_number",
		"open_id":      "openid_123",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := testAlipaySignResponse(t, kp.privateKey, "alipay_system_oauth_token_response", tokenResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	_, err := p.ExchangeCode(context.Background(), "test_code")
	if err == nil {
		t.Fatal("expected error for invalid expires_in")
	}
	if !errors.Is(err, ErrPlatform) {
		t.Errorf("expected ErrPlatform, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetUserInfo
// ---------------------------------------------------------------------------

func TestAlipayProvider_GetUserInfo_NilToken(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	p, _ := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
	)

	_, err := p.GetUserInfo(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil token")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestAlipayProvider_GetUserInfo_Success(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	userResp := map[string]any{
		"code":      "10000",
		"msg":       "Success",
		"open_id":   "openid_123",
		"union_id":  "unionid_789",
		"nick_name": "张三",
		"avatar":    "https://example.com/avatar.jpg",
		"gender":    "m",
		"province":  "浙江省",
		"city":      "杭州市",
		"user_id":   "userid_456",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}

		testAlipayVerifyRequest(t, r.Form, "alipay.user.info.share", &kp.privateKey.PublicKey)

		if r.Form.Get("auth_token") != "my_access_token" {
			t.Errorf("auth_token = %q, want %q", r.Form.Get("auth_token"), "my_access_token")
		}

		body := testAlipaySignResponse(t, kp.privateKey, "alipay_user_info_share_response", userResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	token := &Token{AccessToken: "my_access_token"}
	info, err := p.GetUserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.OpenID != "openid_123" {
		t.Errorf("OpenID = %q, want %q", info.OpenID, "openid_123")
	}
	if info.UnionID != "unionid_789" {
		t.Errorf("UnionID = %q, want %q", info.UnionID, "unionid_789")
	}
	if info.Nickname != "张三" {
		t.Errorf("Nickname = %q, want %q", info.Nickname, "张三")
	}
	if info.Avatar != "https://example.com/avatar.jpg" {
		t.Errorf("Avatar = %q, want %q", info.Avatar, "https://example.com/avatar.jpg")
	}
	if info.Gender != GenderMale {
		t.Errorf("Gender = %v, want %v", info.Gender, GenderMale)
	}
	if info.Province != "浙江省" {
		t.Errorf("Province = %q, want %q", info.Province, "浙江省")
	}
	if info.City != "杭州市" {
		t.Errorf("City = %q, want %q", info.City, "杭州市")
	}
	if info.Raw["user_id"] != "userid_456" {
		t.Errorf("Raw[user_id] = %v, want %q", info.Raw["user_id"], "userid_456")
	}
}

func TestAlipayProvider_GetUserInfo_GenderFemale(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	userResp := map[string]any{
		"code":      "10000",
		"msg":       "Success",
		"open_id":   "openid_f",
		"nick_name": "李四",
		"gender":    "f",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := testAlipaySignResponse(t, kp.privateKey, "alipay_user_info_share_response", userResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	token := &Token{AccessToken: "test_token"}
	info, err := p.GetUserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Gender != GenderFemale {
		t.Errorf("Gender = %v, want %v", info.Gender, GenderFemale)
	}
}

func TestAlipayProvider_GetUserInfo_GenderUnknown(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	userResp := map[string]any{
		"code":      "10000",
		"msg":       "Success",
		"open_id":   "openid_u",
		"nick_name": "王五",
		"gender":    "",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := testAlipaySignResponse(t, kp.privateKey, "alipay_user_info_share_response", userResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	token := &Token{AccessToken: "test_token"}
	info, err := p.GetUserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Gender != GenderUnknown {
		t.Errorf("Gender = %v, want %v", info.Gender, GenderUnknown)
	}
}

func TestAlipayProvider_GetUserInfo_ErrorResponse(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	errorResp := map[string]any{
		"code":     "40004",
		"msg":      "Business Failed",
		"sub_code": "isv.invalid-auth-token",
		"sub_msg":  "无效的授权令牌",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := testAlipaySignResponse(t, kp.privateKey, "alipay_user_info_share_response", errorResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	token := &Token{AccessToken: "bad_token"}
	_, err := p.GetUserInfo(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for error response")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// RefreshToken
// ---------------------------------------------------------------------------

func TestAlipayProvider_RefreshToken_EmptyRefreshToken(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	p, _ := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
	)

	_, err := p.RefreshToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty refresh token")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestAlipayProvider_RefreshToken_Success(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	tokenResp := map[string]any{
		"code":          "10000",
		"msg":           "Success",
		"access_token":  "new_access_token",
		"refresh_token": "new_refresh_token",
		"expires_in":    "3600",
		"open_id":       "openid_123",
		"union_id":      "unionid_789",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}

		testAlipayVerifyRequest(t, r.Form, "alipay.system.oauth.token", &kp.privateKey.PublicKey)

		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q, want %q", r.Form.Get("grant_type"), "refresh_token")
		}
		if r.Form.Get("refresh_token") != "old_refresh_token" {
			t.Errorf("refresh_token = %q, want %q", r.Form.Get("refresh_token"), "old_refresh_token")
		}

		body := testAlipaySignResponse(t, kp.privateKey, "alipay_system_oauth_token_response", tokenResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	token, err := p.RefreshToken(context.Background(), "old_refresh_token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token.AccessToken != "new_access_token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "new_access_token")
	}
	if token.RefreshToken != "new_refresh_token" {
		t.Errorf("RefreshToken = %q, want %q", token.RefreshToken, "new_refresh_token")
	}
	if token.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want %d", token.ExpiresIn, 3600)
	}
	if token.OpenID != "openid_123" {
		t.Errorf("OpenID = %q, want %q", token.OpenID, "openid_123")
	}
}

func TestAlipayProvider_RefreshToken_ErrorResponse(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	errorResp := map[string]any{
		"code":     "40004",
		"msg":      "Business Failed",
		"sub_code": "isv.invalid-refresh-token",
		"sub_msg":  "刷新令牌无效",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := testAlipaySignResponse(t, kp.privateKey, "alipay_system_oauth_token_response", errorResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	_, err := p.RefreshToken(context.Background(), "bad_refresh_token")
	if err == nil {
		t.Fatal("expected error for refresh error")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// buildCommonParams
// ---------------------------------------------------------------------------

func TestAlipayProvider_BuildCommonParams_NonCertMode(t *testing.T) {
	p := &alipayProvider{
		appID: "test_app_id",
		credentials: alipayCredentials{
			isCertMode: false,
		},
	}

	params := p.buildCommonParams("alipay.system.oauth.token")

	if params["app_id"] != "test_app_id" {
		t.Errorf("app_id = %q, want %q", params["app_id"], "test_app_id")
	}
	if params["method"] != "alipay.system.oauth.token" {
		t.Errorf("method = %q, want %q", params["method"], "alipay.system.oauth.token")
	}
	if params["charset"] != "utf-8" {
		t.Errorf("charset = %q, want %q", params["charset"], "utf-8")
	}
	if params["sign_type"] != "RSA2" {
		t.Errorf("sign_type = %q, want %q", params["sign_type"], "RSA2")
	}
	if params["version"] != "1.0" {
		t.Errorf("version = %q, want %q", params["version"], "1.0")
	}
	if params["format"] != "JSON" {
		t.Errorf("format = %q, want %q", params["format"], "JSON")
	}
	if params["timestamp"] == "" {
		t.Error("timestamp should not be empty")
	}

	// Should NOT have cert params
	if _, ok := params["app_cert_sn"]; ok {
		t.Error("non-cert mode should not have app_cert_sn")
	}
	if _, ok := params["alipay_root_cert_sn"]; ok {
		t.Error("non-cert mode should not have alipay_root_cert_sn")
	}
}

func TestAlipayProvider_BuildCommonParams_CertMode(t *testing.T) {
	p := &alipayProvider{
		appID: "test_app_id",
		credentials: alipayCredentials{
			isCertMode:       true,
			appCertSN:        "app_cert_sn_123",
			alipayRootCertSN: "root_cert_sn_456",
		},
	}

	params := p.buildCommonParams("alipay.user.info.share")

	if params["app_cert_sn"] != "app_cert_sn_123" {
		t.Errorf("app_cert_sn = %q, want %q", params["app_cert_sn"], "app_cert_sn_123")
	}
	if params["alipay_root_cert_sn"] != "root_cert_sn_456" {
		t.Errorf("alipay_root_cert_sn = %q, want %q", params["alipay_root_cert_sn"], "root_cert_sn_456")
	}
}

// ---------------------------------------------------------------------------
// mapAlipayErrorKind
// ---------------------------------------------------------------------------

func TestMapAlipayErrorKind(t *testing.T) {
	tests := []struct {
		subCode string
		want    ErrorKind
	}{
		{"isv.invalid-auth-code", ErrKindInvalidCode},
		{"isv.code-expired", ErrKindInvalidCode},
		{"isv.code-is-reused", ErrKindInvalidCode},
		{"isv.code-is-used", ErrKindInvalidCode},
		{"isv.invalid-app-id", ErrKindInvalidConfig},
		{"isv.invalid-refresh-token", ErrKindTokenExpired},
		{"isv.invalid-auth-token", ErrKindTokenExpired},
		{"isv.insufficient-isv-permissions", ErrKindInvalidConfig},
		{"isv.invalid-signature", ErrKindSignature},
		{"isv.unknown-error", ErrKindPlatform},
		{"", ErrKindPlatform},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("subCode=%q", tt.subCode), func(t *testing.T) {
			got := mapAlipayErrorKind(tt.subCode)
			if got != tt.want {
				t.Errorf("mapAlipayErrorKind(%q) = %q, want %q", tt.subCode, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// WithAlipayPublicKey Option
// ---------------------------------------------------------------------------

func TestWithAlipayPublicKey(t *testing.T) {
	kp := testNewAlipayKeyPair(t)
	cfg := newProviderConfig(WithAlipayPublicKey(kp.publicPEM))
	if cfg.alipayPublicKey != kp.publicPEM {
		t.Error("WithAlipayPublicKey did not set the public key")
	}
}

// ---------------------------------------------------------------------------
// WithCertMode Option
// ---------------------------------------------------------------------------

func TestWithCertMode(t *testing.T) {
	cfg := newProviderConfig(WithCertMode("app_cert", "alipay_cert", "root_cert"))
	if cfg.alipayAppCert != "app_cert" {
		t.Errorf("alipayAppCert = %q, want %q", cfg.alipayAppCert, "app_cert")
	}
	if cfg.alipayCert != "alipay_cert" {
		t.Errorf("alipayCert = %q, want %q", cfg.alipayCert, "alipay_cert")
	}
	if cfg.alipayRootCert != "root_cert" {
		t.Errorf("alipayRootCert = %q, want %q", cfg.alipayRootCert, "root_cert")
	}
	if !cfg.alipayCertMode {
		t.Error("alipayCertMode should be true")
	}
}

// ---------------------------------------------------------------------------
// WithSandbox Option
// ---------------------------------------------------------------------------

func TestWithSandbox(t *testing.T) {
	cfg := newProviderConfig(WithSandbox())
	if !cfg.alipaySandbox {
		t.Error("alipaySandbox should be true")
	}
}

// ---------------------------------------------------------------------------
// Integration: Full ExchangeCode + GetUserInfo + RefreshToken flow
// ---------------------------------------------------------------------------

func TestAlipayProvider_FullFlow_PublicKeyMode(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}

		method := r.Form.Get("method")
		w.Header().Set("Content-Type", "application/json")

		switch method {
		case "alipay.system.oauth.token":
			var resp map[string]any
			switch r.Form.Get("grant_type") {
			case "authorization_code":
				resp = map[string]any{
					"code":          "10000",
					"msg":           "Success",
					"access_token":  "flow_access_token",
					"refresh_token": "flow_refresh_token",
					"expires_in":    "3600",
					"open_id":       "flow_openid",
					"union_id":      "flow_unionid",
				}
			case "refresh_token":
				resp = map[string]any{
					"code":          "10000",
					"msg":           "Success",
					"access_token":  "refreshed_access_token",
					"refresh_token": "refreshed_refresh_token",
					"expires_in":    "3600",
					"open_id":       "flow_openid",
					"union_id":      "flow_unionid",
				}
			}
			body := testAlipaySignResponse(t, kp.privateKey, "alipay_system_oauth_token_response", resp)
			_, _ = w.Write(body)

		case "alipay.user.info.share":
			resp := map[string]any{
				"code":      "10000",
				"msg":       "Success",
				"open_id":   "flow_openid",
				"union_id":  "flow_unionid",
				"nick_name": "Flow User",
				"avatar":    "https://example.com/avatar.jpg",
				"gender":    "f",
				"province":  "北京市",
				"city":      "北京市",
			}
			body := testAlipaySignResponse(t, kp.privateKey, "alipay_user_info_share_response", resp)
			_, _ = w.Write(body)

		default:
			t.Errorf("unexpected method: %s", method)
		}
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	// Step 1: ExchangeCode
	token, err := p.ExchangeCode(context.Background(), "auth_code_123")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if token.AccessToken != "flow_access_token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "flow_access_token")
	}

	// Step 2: GetUserInfo
	info, err := p.GetUserInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("GetUserInfo: %v", err)
	}
	if info.Nickname != "Flow User" {
		t.Errorf("Nickname = %q, want %q", info.Nickname, "Flow User")
	}
	if info.Gender != GenderFemale {
		t.Errorf("Gender = %v, want %v", info.Gender, GenderFemale)
	}

	// Step 3: RefreshToken
	newToken, err := p.RefreshToken(context.Background(), token.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if newToken.AccessToken != "refreshed_access_token" {
		t.Errorf("AccessToken = %q, want %q", newToken.AccessToken, "refreshed_access_token")
	}

	if callCount != 3 {
		t.Errorf("expected 3 API calls, got %d", callCount)
	}
}

// ---------------------------------------------------------------------------
// Error response with only code+msg (no sub_code)
// ---------------------------------------------------------------------------

func TestAlipayProvider_ExchangeCode_ErrorWithoutSubCode(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	errorResp := map[string]any{
		"code": "20000",
		"msg":  "Service Currently Unavailable",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := testAlipaySignResponse(t, kp.privateKey, "alipay_system_oauth_token_response", errorResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	_, err := p.ExchangeCode(context.Background(), "some_code")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrPlatform) {
		t.Errorf("expected ErrPlatform, got %v", err)
	}
	ae := err.(*AuthError)
	if ae.Code != "20000" {
		t.Errorf("Code = %q, want %q", ae.Code, "20000")
	}
	if ae.Message != "Service Currently Unavailable" {
		t.Errorf("Message = %q, want %q", ae.Message, "Service Currently Unavailable")
	}
}

// ---------------------------------------------------------------------------
// Constructor via NewAlipay then ExchangeCode (end-to-end through constructor)
// ---------------------------------------------------------------------------

func TestAlipayProvider_ViaConstructor_ExchangeCode(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	tokenResp := map[string]any{
		"code":          "10000",
		"msg":           "Success",
		"access_token":  "ctor_access_token",
		"refresh_token": "ctor_refresh_token",
		"expires_in":    "1800",
		"open_id":       "ctor_openid",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := testAlipaySignResponse(t, kp.privateKey, "alipay_system_oauth_token_response", tokenResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	p, err := NewAlipay("app123", kp.privatePEM, "https://example.com/callback",
		WithAlipayPublicKey(kp.publicPEM),
		WithHTTPClient(ts.Client()),
	)
	if err != nil {
		t.Fatalf("NewAlipay: %v", err)
	}

	// Override gateway for test
	ap := p.(*alipayProvider)
	ap.gateway = ts.URL

	token, err := ap.ExchangeCode(context.Background(), "test_code")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if token.AccessToken != "ctor_access_token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "ctor_access_token")
	}
	if token.ExpiresIn != 1800 {
		t.Errorf("ExpiresIn = %d, want %d", token.ExpiresIn, 1800)
	}
}

// ---------------------------------------------------------------------------
// Concurrency test: multiple goroutines calling the same provider
// ---------------------------------------------------------------------------

// testAlipayConcurrencyHandler returns an HTTP handler that simulates
// Alipay's OAuth and user info endpoints for concurrent access testing.
func testAlipayConcurrencyHandler(t *testing.T, privateKey *rsa.PrivateKey) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		method := r.Form.Get("method")
		w.Header().Set("Content-Type", "application/json")

		switch method {
		case "alipay.system.oauth.token":
			grantType := r.Form.Get("grant_type")
			var resp map[string]any
			if grantType == "authorization_code" {
				resp = map[string]any{
					"code":          "10000",
					"msg":           "Success",
					"access_token":  "concurrent_access_token",
					"refresh_token": "concurrent_refresh_token",
					"expires_in":    "3600",
					"open_id":       "concurrent_openid",
				}
			} else {
				resp = map[string]any{
					"code":          "10000",
					"msg":           "Success",
					"access_token":  "refreshed_concurrent_token",
					"refresh_token": "refreshed_concurrent_rt",
					"expires_in":    "3600",
					"open_id":       "concurrent_openid",
				}
			}
			body := testAlipaySignResponse(t, privateKey, "alipay_system_oauth_token_response", resp)
			_, _ = w.Write(body)

		case "alipay.user.info.share":
			resp := map[string]any{
				"code":      "10000",
				"msg":       "Success",
				"open_id":   "concurrent_openid",
				"nick_name": "ConcurrentUser",
				"gender":    "m",
			}
			body := testAlipaySignResponse(t, privateKey, "alipay_user_info_share_response", resp)
			_, _ = w.Write(body)

		default:
			http.Error(w, "unknown method", http.StatusBadRequest)
		}
	}
}

func TestAlipayProvider_Concurrency(t *testing.T) {
	kp := testNewAlipayKeyPair(t)

	ts := httptest.NewServer(testAlipayConcurrencyHandler(t, kp.privateKey))
	defer ts.Close()

	p := &alipayProvider{
		appID:      "app123",
		privateKey: kp.privateKey,
		httpClient: ts.Client(),
		logger:     &noopLogger{},
		gateway:    ts.URL,
		credentials: alipayCredentials{
			alipayPublicKey: &kp.privateKey.PublicKey,
		},
	}

	const goroutines = 10
	errs := make(chan error, goroutines*3)

	// Launch concurrent ExchangeCode calls
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			token, err := p.ExchangeCode(context.Background(), fmt.Sprintf("code_%d", idx))
			if err != nil {
				errs <- fmt.Errorf("ExchangeCode: %w", err)
				return
			}
			if token.AccessToken != "concurrent_access_token" {
				errs <- fmt.Errorf("ExchangeCode: AccessToken = %q", token.AccessToken)
				return
			}
			errs <- nil
		}(i)
	}

	// Launch concurrent GetUserInfo calls
	testToken := &Token{AccessToken: "test_token"}
	for i := 0; i < goroutines; i++ {
		go func() {
			info, err := p.GetUserInfo(context.Background(), testToken)
			if err != nil {
				errs <- fmt.Errorf("GetUserInfo: %w", err)
				return
			}
			if info.Nickname != "ConcurrentUser" {
				errs <- fmt.Errorf("GetUserInfo: Nickname = %q", info.Nickname)
				return
			}
			errs <- nil
		}()
	}

	// Launch concurrent RefreshToken calls
	refreshToken := "refresh_token"
	for i := 0; i < goroutines; i++ {
		go func() {
			token, err := p.RefreshToken(context.Background(), refreshToken)
			if err != nil {
				errs <- fmt.Errorf("RefreshToken: %w", err)
				return
			}
			if token.AccessToken != "refreshed_concurrent_token" {
				errs <- fmt.Errorf("RefreshToken: AccessToken = %q", token.AccessToken)
				return
			}
			errs <- nil
		}()
	}

	// Collect results
	for i := 0; i < goroutines*3; i++ {
		if err := <-errs; err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}
