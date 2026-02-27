package authhub

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
)

// --- test helpers for public keys ---

// testEncodePKIXPublicKeyPEM encodes an RSA public key as PKIX PEM.
func testEncodePKIXPublicKeyPEM(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshal PKIX public key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}
	return string(pem.EncodeToMemory(block))
}

// testEncodePKCS1PublicKeyPEM encodes an RSA public key as PKCS1 PEM.
func testEncodePKCS1PublicKeyPEM(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	derBytes := x509.MarshalPKCS1PublicKey(key)
	block := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: derBytes}
	return string(pem.EncodeToMemory(block))
}

// testEncodeRawBase64PKIXPublicKey encodes an RSA public key as raw base64 (no PEM headers).
func testEncodeRawBase64PKIXPublicKey(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshal PKIX public key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(derBytes)
}

// testSignContent signs content with a private key and returns the base64 signature.
func testSignContent(t *testing.T, key *rsa.PrivateKey, content string) string {
	t.Helper()
	h := sha256.Sum256([]byte(content))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("sign content: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// --- parsePublicKey ---

func TestParsePublicKey_PKIX(t *testing.T) {
	key := testGenerateRSAKey(t)
	pemData := testEncodePKIXPublicKeyPEM(t, &key.PublicKey)

	parsed, err := parsePublicKey(pemData)
	if err != nil {
		t.Fatalf("parsePublicKey(PKIX): unexpected error: %v", err)
	}
	if parsed.N.Cmp(key.N) != 0 || parsed.E != key.E {
		t.Error("parsePublicKey(PKIX): parsed key does not match original")
	}
}

func TestParsePublicKey_PKCS1(t *testing.T) {
	key := testGenerateRSAKey(t)
	pemData := testEncodePKCS1PublicKeyPEM(t, &key.PublicKey)

	parsed, err := parsePublicKey(pemData)
	if err != nil {
		t.Fatalf("parsePublicKey(PKCS1): unexpected error: %v", err)
	}
	if parsed.N.Cmp(key.N) != 0 || parsed.E != key.E {
		t.Error("parsePublicKey(PKCS1): parsed key does not match original")
	}
}

func TestParsePublicKey_RawBase64(t *testing.T) {
	key := testGenerateRSAKey(t)
	rawBase64 := testEncodeRawBase64PKIXPublicKey(t, &key.PublicKey)

	parsed, err := parsePublicKey(rawBase64)
	if err != nil {
		t.Fatalf("parsePublicKey(raw base64): unexpected error: %v", err)
	}
	if parsed.N.Cmp(key.N) != 0 || parsed.E != key.E {
		t.Error("parsePublicKey(raw base64): parsed key does not match original")
	}
}

func TestParsePublicKey_InvalidData(t *testing.T) {
	_, err := parsePublicKey("not-a-valid-key!!!")
	if err == nil {
		t.Fatal("parsePublicKey(invalid): expected error, got nil")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("parsePublicKey(invalid): error is not AuthError: %T", err)
	}
	if authErr.Kind != ErrKindInvalidConfig {
		t.Errorf("parsePublicKey(invalid): Kind = %q; want %q", authErr.Kind, ErrKindInvalidConfig)
	}
}

func TestParsePublicKey_EmptyString(t *testing.T) {
	_, err := parsePublicKey("")
	if err == nil {
		t.Fatal("parsePublicKey(empty): expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("parsePublicKey(empty): errors.Is(err, ErrInvalidConfig) = false")
	}
}

func TestParsePublicKey_InvalidPEM(t *testing.T) {
	invalidPEM := "-----BEGIN PUBLIC KEY-----\nnotvalidbase64!!!\n-----END PUBLIC KEY-----"
	_, err := parsePublicKey(invalidPEM)
	if err == nil {
		t.Fatal("parsePublicKey(invalidPEM): expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("parsePublicKey(invalidPEM): errors.Is(err, ErrInvalidConfig) = false")
	}
}

// --- verifyRSA2Signature ---

func TestVerifyRSA2Signature_Valid(t *testing.T) {
	key := testGenerateRSAKey(t)
	content := "app_id=2021001234567890&charset=utf-8&method=alipay.system.oauth.token"
	sig := testSignContent(t, key, content)

	if err := verifyRSA2Signature(&key.PublicKey, content, sig); err != nil {
		t.Errorf("verifyRSA2Signature(valid): unexpected error: %v", err)
	}
}

func TestVerifyRSA2Signature_TamperedContent(t *testing.T) {
	key := testGenerateRSAKey(t)
	content := "app_id=2021001234567890&charset=utf-8"
	sig := testSignContent(t, key, content)

	err := verifyRSA2Signature(&key.PublicKey, content+"&tampered=true", sig)
	if err == nil {
		t.Fatal("verifyRSA2Signature(tampered): expected error, got nil")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("verifyRSA2Signature(tampered): error is not AuthError: %T", err)
	}
	if authErr.Kind != ErrKindSignature {
		t.Errorf("verifyRSA2Signature(tampered): Kind = %q; want %q", authErr.Kind, ErrKindSignature)
	}
	if authErr.Provider != "alipay" {
		t.Errorf("verifyRSA2Signature(tampered): Provider = %q; want %q", authErr.Provider, "alipay")
	}
}

func TestVerifyRSA2Signature_WrongKey(t *testing.T) {
	key1 := testGenerateRSAKey(t)
	key2 := testGenerateRSAKey(t)
	content := "test content"
	sig := testSignContent(t, key1, content)

	err := verifyRSA2Signature(&key2.PublicKey, content, sig)
	if err == nil {
		t.Fatal("verifyRSA2Signature(wrong key): expected error, got nil")
	}
	if !errors.Is(err, ErrSignature) {
		t.Errorf("verifyRSA2Signature(wrong key): errors.Is(err, ErrSignature) = false")
	}
}

func TestVerifyRSA2Signature_InvalidBase64(t *testing.T) {
	key := testGenerateRSAKey(t)

	err := verifyRSA2Signature(&key.PublicKey, "content", "not!valid!base64!!!")
	if err == nil {
		t.Fatal("verifyRSA2Signature(invalid base64): expected error, got nil")
	}
	if !errors.Is(err, ErrSignature) {
		t.Errorf("verifyRSA2Signature(invalid base64): errors.Is(err, ErrSignature) = false")
	}
}

func TestVerifyRSA2Signature_SignAndVerifyRoundtrip(t *testing.T) {
	key := testGenerateRSAKey(t)
	content := `biz_content={"grant_type":"authorization_code","code":"abc123"}`

	// Sign using signWithRSA2 from alipay_sign.go
	sig, err := signWithRSA2(key, content)
	if err != nil {
		t.Fatalf("signWithRSA2: %v", err)
	}

	// Verify using verifyRSA2Signature
	if err := verifyRSA2Signature(&key.PublicKey, content, sig); err != nil {
		t.Errorf("verifyRSA2Signature(roundtrip): %v", err)
	}
}

// --- extractSignContent ---

func TestExtractSignContent_BasicResponse(t *testing.T) {
	body := []byte(`{"alipay_system_oauth_token_response":{"access_token":"20120823xxxxxxxx","user_id":"2088xxxxx"},"sign":"dGVzdHNpZw=="}`)

	content, sign, certSN, err := extractSignContent(body, "alipay_system_oauth_token_response")
	if err != nil {
		t.Fatalf("extractSignContent: unexpected error: %v", err)
	}

	wantContent := `{"access_token":"20120823xxxxxxxx","user_id":"2088xxxxx"}`
	if content != wantContent {
		t.Errorf("content = %q; want %q", content, wantContent)
	}
	if sign != "dGVzdHNpZw==" {
		t.Errorf("sign = %q; want %q", sign, "dGVzdHNpZw==")
	}
	if certSN != "" {
		t.Errorf("certSN = %q; want empty", certSN)
	}
}

func TestExtractSignContent_WithCertSN(t *testing.T) {
	body := []byte(`{"alipay_system_oauth_token_response":{"access_token":"xxx"},"sign":"c2lnbmF0dXJl","alipay_cert_sn":"abc123def456"}`)

	content, sign, certSN, err := extractSignContent(body, "alipay_system_oauth_token_response")
	if err != nil {
		t.Fatalf("extractSignContent: %v", err)
	}

	if content != `{"access_token":"xxx"}` {
		t.Errorf("content = %q; want %q", content, `{"access_token":"xxx"}`)
	}
	if sign != "c2lnbmF0dXJl" {
		t.Errorf("sign = %q; want %q", sign, "c2lnbmF0dXJl")
	}
	if certSN != "abc123def456" {
		t.Errorf("certSN = %q; want %q", certSN, "abc123def456")
	}
}

func TestExtractSignContent_SignBeforeResponse(t *testing.T) {
	body := []byte(`{"sign":"c2lnbmF0dXJl","alipay_system_oauth_token_response":{"access_token":"xxx"}}`)

	content, sign, certSN, err := extractSignContent(body, "alipay_system_oauth_token_response")
	if err != nil {
		t.Fatalf("extractSignContent(sign before response): %v", err)
	}

	if content != `{"access_token":"xxx"}` {
		t.Errorf("content = %q; want %q", content, `{"access_token":"xxx"}`)
	}
	if sign != "c2lnbmF0dXJl" {
		t.Errorf("sign = %q; want %q", sign, "c2lnbmF0dXJl")
	}
	if certSN != "" {
		t.Errorf("certSN = %q; want empty", certSN)
	}
}

func TestExtractSignContent_UnescapesSignValue(t *testing.T) {
	body := []byte(`{"alipay_system_oauth_token_response":{"access_token":"xxx"},"sign":"abc\/def"}`)

	_, sign, _, err := extractSignContent(body, "alipay_system_oauth_token_response")
	if err != nil {
		t.Fatalf("extractSignContent(unescape sign): %v", err)
	}
	if sign != "abc/def" {
		t.Errorf("sign = %q; want %q", sign, "abc/def")
	}
}

func TestExtractSignContent_NestedObjects(t *testing.T) {
	body := []byte(`{"alipay_trade_query_response":{"out_trade_no":"123","fund_bill_list":[{"amount":"10.00","fund_channel":"ALIPAYACCOUNT"}],"detail":{"key":"val"}},"sign":"c2ln"}`)

	content, sign, _, err := extractSignContent(body, "alipay_trade_query_response")
	if err != nil {
		t.Fatalf("extractSignContent(nested): %v", err)
	}

	wantContent := `{"out_trade_no":"123","fund_bill_list":[{"amount":"10.00","fund_channel":"ALIPAYACCOUNT"}],"detail":{"key":"val"}}`
	if content != wantContent {
		t.Errorf("content = %q;\n  want %q", content, wantContent)
	}
	if sign != "c2ln" {
		t.Errorf("sign = %q; want %q", sign, "c2ln")
	}
}

func TestExtractSignContent_WithWhitespace(t *testing.T) {
	body := []byte(`{
  "alipay_system_oauth_token_response": {"access_token": "xxx"},
  "sign": "c2ln"
}`)

	content, sign, _, err := extractSignContent(body, "alipay_system_oauth_token_response")
	if err != nil {
		t.Fatalf("extractSignContent(whitespace): %v", err)
	}

	if content != `{"access_token": "xxx"}` {
		t.Errorf("content = %q; want %q", content, `{"access_token": "xxx"}`)
	}
	if sign != "c2ln" {
		t.Errorf("sign = %q; want %q", sign, "c2ln")
	}
}

func TestExtractSignContent_NodeKeyWithSpaceBeforeColon(t *testing.T) {
	body := []byte(`{"alipay_system_oauth_token_response" : {"access_token":"xxx"},"sign":"c2ln"}`)

	content, sign, _, err := extractSignContent(body, "alipay_system_oauth_token_response")
	if err != nil {
		t.Fatalf("extractSignContent(space before colon): %v", err)
	}

	if content != `{"access_token":"xxx"}` {
		t.Errorf("content = %q; want %q", content, `{"access_token":"xxx"}`)
	}
	if sign != "c2ln" {
		t.Errorf("sign = %q; want %q", sign, "c2ln")
	}
}

func TestExtractSignContent_EscapedStrings(t *testing.T) {
	body := []byte(`{"alipay_response":{"msg":"hello \"world\"","data":"{\"nested\": true}"},"sign":"c2ln"}`)

	content, sign, _, err := extractSignContent(body, "alipay_response")
	if err != nil {
		t.Fatalf("extractSignContent(escaped): %v", err)
	}

	wantContent := `{"msg":"hello \"world\"","data":"{\"nested\": true}"}`
	if content != wantContent {
		t.Errorf("content = %q;\n  want %q", content, wantContent)
	}
	if sign != "c2ln" {
		t.Errorf("sign = %q; want %q", sign, "c2ln")
	}
}

func TestExtractSignContent_NodeNotFound(t *testing.T) {
	body := []byte(`{"alipay_system_oauth_token_response":{"access_token":"xxx"},"sign":"c2ln"}`)

	_, _, _, err := extractSignContent(body, "nonexistent_response")
	if err == nil {
		t.Fatal("extractSignContent(not found): expected error, got nil")
	}
	if !errors.Is(err, ErrSignature) {
		t.Errorf("extractSignContent(not found): errors.Is(err, ErrSignature) = false")
	}
}

func TestExtractSignContent_MissingSign(t *testing.T) {
	body := []byte(`{"alipay_system_oauth_token_response":{"access_token":"xxx"}}`)

	_, _, _, err := extractSignContent(body, "alipay_system_oauth_token_response")
	if err == nil {
		t.Fatal("extractSignContent(no sign): expected error, got nil")
	}
	if !errors.Is(err, ErrSignature) {
		t.Errorf("extractSignContent(no sign): errors.Is(err, ErrSignature) = false")
	}
}

func TestExtractSignContent_NonObjectValue(t *testing.T) {
	body := []byte(`{"alipay_response":"just_a_string","sign":"c2ln"}`)
	_, _, _, err := extractSignContent(body, "alipay_response")
	if err == nil {
		t.Fatal("expected error for non-object value")
	}
	if !errors.Is(err, ErrSignature) {
		t.Errorf("errors.Is(err, ErrSignature) = false")
	}
}

func TestExtractSignContent_IgnoresFakeNodeFragmentInString(t *testing.T) {
	body := []byte(`{"memo":"fake => \"alipay_system_oauth_token_response\":{\"x\":1}","alipay_system_oauth_token_response":{"access_token":"real"},"sign":"c2ln"}`)

	content, sign, _, err := extractSignContent(body, "alipay_system_oauth_token_response")
	if err != nil {
		t.Fatalf("extractSignContent(fake fragment in string): %v", err)
	}

	if content != `{"access_token":"real"}` {
		t.Errorf("content = %q; want %q", content, `{"access_token":"real"}`)
	}
	if sign != "c2ln" {
		t.Errorf("sign = %q; want %q", sign, "c2ln")
	}
}

func TestExtractSignContent_NestedArrayOfObjects(t *testing.T) {
	body := []byte(`{"alipay_response":{"items":[{"id":1},{"id":2}],"total":2},"sign":"c2ln"}`)

	content, _, _, err := extractSignContent(body, "alipay_response")
	if err != nil {
		t.Fatalf("extractSignContent(array of objects): %v", err)
	}

	wantContent := `{"items":[{"id":1},{"id":2}],"total":2}`
	if content != wantContent {
		t.Errorf("content = %q; want %q", content, wantContent)
	}
}

// --- verifyAlipayResponse ---

func TestVerifyAlipayResponse_Valid(t *testing.T) {
	key := testGenerateRSAKey(t)

	// Build a response with a valid signature
	responseContent := `{"access_token":"20120823xxx","user_id":"2088xxxxx"}`
	sig := testSignContent(t, key, responseContent)
	body := []byte(`{"alipay_system_oauth_token_response":` + responseContent + `,"sign":"` + sig + `"}`)

	if err := verifyAlipayResponse(body, "alipay_system_oauth_token_response", &key.PublicKey); err != nil {
		t.Errorf("verifyAlipayResponse(valid): %v", err)
	}
}

func TestVerifyAlipayResponse_TamperedResponse(t *testing.T) {
	key := testGenerateRSAKey(t)

	// Sign one content, put different content in response
	sig := testSignContent(t, key, `{"access_token":"original"}`)
	body := []byte(`{"alipay_system_oauth_token_response":{"access_token":"tampered"},"sign":"` + sig + `"}`)

	err := verifyAlipayResponse(body, "alipay_system_oauth_token_response", &key.PublicKey)
	if err == nil {
		t.Fatal("verifyAlipayResponse(tampered): expected error, got nil")
	}
	if !errors.Is(err, ErrSignature) {
		t.Errorf("verifyAlipayResponse(tampered): errors.Is(err, ErrSignature) = false")
	}
}

func TestVerifyAlipayResponse_WrongPublicKey(t *testing.T) {
	key1 := testGenerateRSAKey(t)
	key2 := testGenerateRSAKey(t)

	responseContent := `{"access_token":"xxx"}`
	sig := testSignContent(t, key1, responseContent)
	body := []byte(`{"alipay_system_oauth_token_response":` + responseContent + `,"sign":"` + sig + `"}`)

	err := verifyAlipayResponse(body, "alipay_system_oauth_token_response", &key2.PublicKey)
	if err == nil {
		t.Fatal("verifyAlipayResponse(wrong key): expected error, got nil")
	}
	if !errors.Is(err, ErrSignature) {
		t.Errorf("verifyAlipayResponse(wrong key): errors.Is(err, ErrSignature) = false")
	}
}

func TestVerifyAlipayResponse_MissingNode(t *testing.T) {
	key := testGenerateRSAKey(t)

	body := []byte(`{"other_response":{"data":"xxx"},"sign":"c2ln"}`)
	err := verifyAlipayResponse(body, "alipay_system_oauth_token_response", &key.PublicKey)
	if err == nil {
		t.Fatal("verifyAlipayResponse(missing node): expected error, got nil")
	}
	if !errors.Is(err, ErrSignature) {
		t.Errorf("verifyAlipayResponse(missing node): errors.Is(err, ErrSignature) = false")
	}
}

func TestVerifyAlipayResponse_WithNestedContent(t *testing.T) {
	key := testGenerateRSAKey(t)

	responseContent := `{"user_id":"2088","info":{"level":1},"tags":["vip","new"]}`
	sig := testSignContent(t, key, responseContent)
	body := []byte(`{"alipay_user_info_share_response":` + responseContent + `,"sign":"` + sig + `"}`)

	if err := verifyAlipayResponse(body, "alipay_user_info_share_response", &key.PublicKey); err != nil {
		t.Errorf("verifyAlipayResponse(nested): %v", err)
	}
}

// --- parsePublicKey + verifyRSA2Signature roundtrip ---

func TestParsePublicKeyAndVerify_Roundtrip(t *testing.T) {
	key := testGenerateRSAKey(t)
	pemData := testEncodePKIXPublicKeyPEM(t, &key.PublicKey)

	pubKey, err := parsePublicKey(pemData)
	if err != nil {
		t.Fatalf("parsePublicKey: %v", err)
	}

	content := "app_id=2021001234567890&charset=utf-8&method=alipay.system.oauth.token&sign_type=RSA2&timestamp=2025-01-01 00:00:00&version=1.0"
	sig, err := signWithRSA2(key, content)
	if err != nil {
		t.Fatalf("signWithRSA2: %v", err)
	}

	if err := verifyRSA2Signature(pubKey, content, sig); err != nil {
		t.Errorf("roundtrip verify failed: %v", err)
	}
}
