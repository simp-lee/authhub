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
	"net/url"
	"testing"
)

// testGenerateRSAKey generates a 2048-bit RSA key for testing.
func testGenerateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

// testEncodePKCS1PEM encodes an RSA private key as PKCS1 PEM.
func testEncodePKCS1PEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	derBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: derBytes}
	return string(pem.EncodeToMemory(block))
}

// testEncodePKCS8PEM encodes an RSA private key as PKCS8 PEM.
func testEncodePKCS8PEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	derBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: derBytes}
	return string(pem.EncodeToMemory(block))
}

// testEncodeRawBase64PKCS1 encodes an RSA private key as raw base64 (no PEM headers).
func testEncodeRawBase64PKCS1(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	derBytes := x509.MarshalPKCS1PrivateKey(key)
	return base64.StdEncoding.EncodeToString(derBytes)
}

// --- parsePrivateKey ---

func TestParsePrivateKey_PKCS1(t *testing.T) {
	key := testGenerateRSAKey(t)
	pemData := testEncodePKCS1PEM(t, key)

	parsed, err := parsePrivateKey(pemData)
	if err != nil {
		t.Fatalf("parsePrivateKey(PKCS1): unexpected error: %v", err)
	}
	if parsed.D.Cmp(key.D) != 0 {
		t.Error("parsePrivateKey(PKCS1): parsed key does not match original")
	}
}

func TestParsePrivateKey_PKCS8(t *testing.T) {
	key := testGenerateRSAKey(t)
	pemData := testEncodePKCS8PEM(t, key)

	parsed, err := parsePrivateKey(pemData)
	if err != nil {
		t.Fatalf("parsePrivateKey(PKCS8): unexpected error: %v", err)
	}
	if parsed.D.Cmp(key.D) != 0 {
		t.Error("parsePrivateKey(PKCS8): parsed key does not match original")
	}
}

func TestParsePrivateKey_RawBase64(t *testing.T) {
	key := testGenerateRSAKey(t)
	rawBase64 := testEncodeRawBase64PKCS1(t, key)

	parsed, err := parsePrivateKey(rawBase64)
	if err != nil {
		t.Fatalf("parsePrivateKey(raw base64): unexpected error: %v", err)
	}
	if parsed.D.Cmp(key.D) != 0 {
		t.Error("parsePrivateKey(raw base64): parsed key does not match original")
	}
}

func TestParsePrivateKey_RawBase64_PKCS8(t *testing.T) {
	key := testGenerateRSAKey(t)
	derBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	rawBase64 := base64.StdEncoding.EncodeToString(derBytes)

	parsed, err := parsePrivateKey(rawBase64)
	if err != nil {
		t.Fatalf("parsePrivateKey(raw base64 PKCS8): unexpected error: %v", err)
	}
	if parsed.D.Cmp(key.D) != 0 {
		t.Error("parsePrivateKey(raw base64 PKCS8): parsed key does not match original")
	}
}

func TestParsePrivateKey_InvalidData(t *testing.T) {
	_, err := parsePrivateKey("not-a-valid-key!!!")
	if err == nil {
		t.Fatal("parsePrivateKey(invalid): expected error, got nil")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("parsePrivateKey(invalid): error is not AuthError: %T", err)
	}
	if authErr.Kind != ErrKindInvalidConfig {
		t.Errorf("parsePrivateKey(invalid): Kind = %q; want %q", authErr.Kind, ErrKindInvalidConfig)
	}
}

func TestParsePrivateKey_EmptyString(t *testing.T) {
	_, err := parsePrivateKey("")
	if err == nil {
		t.Fatal("parsePrivateKey(empty): expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("parsePrivateKey(empty): errors.Is(err, ErrInvalidConfig) = false")
	}
}

func TestParsePrivateKey_InvalidPEM(t *testing.T) {
	invalidPEM := "-----BEGIN RSA PRIVATE KEY-----\nnotvalidbase64!!!\n-----END RSA PRIVATE KEY-----"
	_, err := parsePrivateKey(invalidPEM)
	if err == nil {
		t.Fatal("parsePrivateKey(invalidPEM): expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("parsePrivateKey(invalidPEM): errors.Is(err, ErrInvalidConfig) = false")
	}
}

// --- signWithRSA2 ---

func TestSignWithRSA2_Roundtrip(t *testing.T) {
	key := testGenerateRSAKey(t)
	content := "app_id=2021001234567890&charset=utf-8&method=alipay.system.oauth.token"

	sig, err := signWithRSA2(key, content)
	if err != nil {
		t.Fatalf("signWithRSA2: unexpected error: %v", err)
	}
	if sig == "" {
		t.Fatal("signWithRSA2: signature is empty")
	}

	// Verify the signature using the public key
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("decode base64 signature: %v", err)
	}
	h := sha256.Sum256([]byte(content))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h[:], sigBytes); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestSignWithRSA2_Deterministic(t *testing.T) {
	key := testGenerateRSAKey(t)
	content := "test_content_for_signing"

	sig1, err := signWithRSA2(key, content)
	if err != nil {
		t.Fatalf("signWithRSA2 first call: %v", err)
	}
	sig2, err := signWithRSA2(key, content)
	if err != nil {
		t.Fatalf("signWithRSA2 second call: %v", err)
	}

	// PKCS1v15 signing is deterministic
	if sig1 != sig2 {
		t.Errorf("signWithRSA2: not deterministic; sig1=%q, sig2=%q", sig1, sig2)
	}
}

func TestSignWithRSA2_DifferentContentDifferentSignature(t *testing.T) {
	key := testGenerateRSAKey(t)

	sig1, err := signWithRSA2(key, "content_a")
	if err != nil {
		t.Fatalf("signWithRSA2(a): %v", err)
	}
	sig2, err := signWithRSA2(key, "content_b")
	if err != nil {
		t.Fatalf("signWithRSA2(b): %v", err)
	}

	if sig1 == sig2 {
		t.Error("signWithRSA2: different content produced identical signatures")
	}
}

// --- buildSignContent ---

func TestBuildSignContent_SortedKeys(t *testing.T) {
	params := map[string]string{
		"method":    "alipay.system.oauth.token",
		"charset":   "utf-8",
		"app_id":    "2021001234567890",
		"version":   "1.0",
		"sign_type": "RSA2",
	}

	got := buildSignContent(params)
	want := "app_id=2021001234567890&charset=utf-8&method=alipay.system.oauth.token&sign_type=RSA2&version=1.0"
	if got != want {
		t.Errorf("buildSignContent:\n  got  %q\n  want %q", got, want)
	}
}

func TestBuildSignContent_SkipsEmptyValues(t *testing.T) {
	params := map[string]string{
		"b_key": "value_b",
		"a_key": "value_a",
		"c_key": "",
		"d_key": "value_d",
	}

	got := buildSignContent(params)
	want := "a_key=value_a&b_key=value_b&d_key=value_d"
	if got != want {
		t.Errorf("buildSignContent(skip empty):\n  got  %q\n  want %q", got, want)
	}
}

func TestBuildSignContent_EmptyMap(t *testing.T) {
	got := buildSignContent(map[string]string{})
	if got != "" {
		t.Errorf("buildSignContent(empty): got %q; want empty string", got)
	}
}

func TestBuildSignContent_AllEmptyValues(t *testing.T) {
	params := map[string]string{
		"a": "",
		"b": "",
	}
	got := buildSignContent(params)
	if got != "" {
		t.Errorf("buildSignContent(all empty): got %q; want empty string", got)
	}
}

func TestBuildSignContent_SingleParam(t *testing.T) {
	params := map[string]string{
		"key": "value",
	}
	got := buildSignContent(params)
	want := "key=value"
	if got != want {
		t.Errorf("buildSignContent(single): got %q; want %q", got, want)
	}
}

// --- buildAlipayRequestParams ---

func TestBuildAlipayRequestParams_MergesAndSigns(t *testing.T) {
	key := testGenerateRSAKey(t)

	bizParams := map[string]string{
		"biz_content": `{"grant_type":"authorization_code","code":"abc123"}`,
	}
	commonParams := map[string]string{
		"app_id":    "2021001234567890",
		"method":    "alipay.system.oauth.token",
		"charset":   "utf-8",
		"sign_type": "RSA2",
		"version":   "1.0",
	}

	values, err := buildAlipayRequestParams(bizParams, commonParams, key)
	if err != nil {
		t.Fatalf("buildAlipayRequestParams: unexpected error: %v", err)
	}

	// All params should be present
	for k, v := range commonParams {
		if got := values.Get(k); got != v {
			t.Errorf("param %q = %q; want %q", k, got, v)
		}
	}
	for k, v := range bizParams {
		if got := values.Get(k); got != v {
			t.Errorf("param %q = %q; want %q", k, got, v)
		}
	}

	// sign must be present and non-empty
	sign := values.Get("sign")
	if sign == "" {
		t.Fatal("buildAlipayRequestParams: sign is empty")
	}

	// Verify the signature
	// Rebuild the merged params (without sign) and verify
	merged := make(map[string]string)
	for k, v := range commonParams {
		merged[k] = v
	}
	for k, v := range bizParams {
		merged[k] = v
	}
	content := buildSignContent(merged)

	sigBytes, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		t.Fatalf("decode sign: %v", err)
	}
	h := sha256.Sum256([]byte(content))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h[:], sigBytes); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestBuildAlipayRequestParams_ReturnsURLValues(t *testing.T) {
	key := testGenerateRSAKey(t)

	values, err := buildAlipayRequestParams(
		map[string]string{"biz": "data"},
		map[string]string{"app_id": "123"},
		key,
	)
	if err != nil {
		t.Fatalf("buildAlipayRequestParams: %v", err)
	}

	// Verify it's a proper url.Values
	var _ url.Values = values
	if values.Get("app_id") != "123" {
		t.Errorf("app_id = %q; want %q", values.Get("app_id"), "123")
	}
	if values.Get("biz") != "data" {
		t.Errorf("biz = %q; want %q", values.Get("biz"), "data")
	}
}

func TestBuildAlipayRequestParams_BizOverridesCommon(t *testing.T) {
	key := testGenerateRSAKey(t)

	// If same key exists in both, bizParams takes precedence
	bizParams := map[string]string{"shared_key": "biz_value"}
	commonParams := map[string]string{"shared_key": "common_value", "other": "val"}

	values, err := buildAlipayRequestParams(bizParams, commonParams, key)
	if err != nil {
		t.Fatalf("buildAlipayRequestParams: %v", err)
	}

	if got := values.Get("shared_key"); got != "biz_value" {
		t.Errorf("shared_key = %q; want %q (bizParams should override)", got, "biz_value")
	}
}

// --- Golden test: parsePrivateKey + signWithRSA2 roundtrip ---

func TestParseAndSign_GoldenRoundtrip(t *testing.T) {
	// Generate key, encode as PEM, parse it back, sign, verify
	origKey := testGenerateRSAKey(t)
	pemData := testEncodePKCS1PEM(t, origKey)

	parsedKey, err := parsePrivateKey(pemData)
	if err != nil {
		t.Fatalf("parsePrivateKey: %v", err)
	}

	content := "app_id=2021001234567890&charset=utf-8&method=alipay.system.oauth.token&sign_type=RSA2&timestamp=2025-01-01 00:00:00&version=1.0"
	sig, err := signWithRSA2(parsedKey, content)
	if err != nil {
		t.Fatalf("signWithRSA2: %v", err)
	}

	// Verify with original key's public key
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	h := sha256.Sum256([]byte(content))
	if err := rsa.VerifyPKCS1v15(&origKey.PublicKey, crypto.SHA256, h[:], sigBytes); err != nil {
		t.Errorf("golden roundtrip: signature verification failed: %v", err)
	}
}

func TestParseAndSign_PKCS8Roundtrip(t *testing.T) {
	origKey := testGenerateRSAKey(t)
	pemData := testEncodePKCS8PEM(t, origKey)

	parsedKey, err := parsePrivateKey(pemData)
	if err != nil {
		t.Fatalf("parsePrivateKey(PKCS8): %v", err)
	}

	content := "test=value"
	sig, err := signWithRSA2(parsedKey, content)
	if err != nil {
		t.Fatalf("signWithRSA2: %v", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	h := sha256.Sum256([]byte(content))
	if err := rsa.VerifyPKCS1v15(&origKey.PublicKey, crypto.SHA256, h[:], sigBytes); err != nil {
		t.Errorf("PKCS8 roundtrip: signature verification failed: %v", err)
	}
}

// --- Golden test with fixed private key ---

func TestSignWithRSA2_GoldenFixedKey(t *testing.T) {
	// A fixed RSA-2048 PKCS1 private key used solely for this golden test.
	const goldenPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtLY0HxeSIgyR5RfdeTDr0sVpFPTf5Fggki8JPJZZr9XwDN9t
pd/RgdAP/TasKwxCmbzQEj/19u+q+BwBIkOLG/SZJfizwwclc1f6bLCg4/0zJw5H
l5aTX+tWyPqPFt8V54JpWi4cCiYtPewDlnb0PX7tLjWPOLbZ1POLXN+MQP4jxMCs
Z2V2+HPbgZgQVQxjfOH+A97if8E6vVytdyCzgxQyLnAqPhIGWcPmowAeRLd/gAvM
AzBkA3gmh7mNNrYeDRt1rlpo9OmAxNDSEWgqgLss80AfBUpzthqsZ8f/iAH2LpOF
jsPTeeQ0Xi8PGaa9+v7oYu5A8mDKSPzjvQ8sQQIDAQABAoIBAAOH/G5/msnKylaK
T/f4aGFI3X/s9YuMG83TeLgb/YJpuSw9OPKo9Bp35voVFYntTkdcCMpUgOFLh2Ec
BfsmC/u2vL/g011sIDOX7GMvk+NEnTlmBmjcRsK08fARMlbZct+AXT/nfwGFQ7TO
LfdEmYrylh6lKghrDUhjnm1pCl/yNvaXcrNIAuNiZrhlOklRdpvqYptBJtAUv423
sK5rYGO9xILeyPdUGJw883+7k3PWxmLd2w/qSZGfMj15RuaPgB/WuAxphbz2cIv6
281NbAFJ/xDCHOw5OSOjtd/l8Bsgh+2VgDHMWxCF3VsI3qGTacqFKdAGpz4QOURy
/h5wduECgYEA0ML4TR/4wTCEs6CsbOYgNwL2D7e8Tau7foWlmRC59cMWF+MbT6sM
T1wV7sBV+HGfUAAecRcWwt5qgzvfc0egXeF3TM+rytT8PtjhPd0PaW6LQ9p1d2//
UH3cLCbl9/tr70NudorM1c65a3fNkTuEPxENqQKn4+HqAUorjqraMlECgYEA3Zpg
PVmGA4n04c2wtLDQwG2g9opaZAFpvAZKYMQLRijo8AMoTut3eLRaYv8Pj6o4DMnR
VUVWLZgk4Q6g4R6Br5xXsc1AXc8hdINUsrt8ZnkckvaFzVKMAiNozXGr7hk9bytt
d7ReXiu38Kz2vFK4DKIJXoXjaH2K4lkyUkLXbvECgYEAqkxCbfgE3uQLfNU3k2Zv
JTE/NTc3X00WmHHB0wm4CWnpnfbgEq+ATUTbh3ZTK2bVBVfzfWHOaY0y6ndvIwVt
JuiEf55xj/cLBuG5bNPmfKV26hVN+e7dIfZqI4Jf21m4hOhHNmCoFEqdK7QBd9ZL
XX8124eVGerzD7ZHrgxmDuECgYAE2it/TGWF0FB/XTygSDrZ68yZeWAPToSdLFoW
klRY3e5zyu3oBHniN7i+8CzMDYMarJSb1F/Vsb4k+2gEZeGbEcZNy1u8chuebH2/
SCGqML6ybRly7HrKVTInRXTpSr4wn/fOpjFmyHhHmdHxP7Jt/GJOIopfMFiJKkDS
0knbUQKBgQDP8ZGotUVUWRSd88BXWjN+VsGUe74y9iQ7QoF8tJH0i89cwnDARnWt
5PtPfuIFubXSWNBqYhXksN09fbayM2XGgZxF5dbPtqcjk7AthNE5INhaBkJXMQOb
vo1vY9Qq0u0/Tb4v9jY/d2BOZEy6QeROPhTHjnQCfqaMWuN06AIeFw==
-----END RSA PRIVATE KEY-----`

	const goldenContent = "app_id=2021001234567890&charset=utf-8&method=alipay.system.oauth.token&sign_type=RSA2&timestamp=2025-01-01 00:00:00&version=1.0"

	// Pre-computed expected signature for the above key + content.
	const goldenSignature = "NZXrvMlU6UUAD4TQk+BDj0P6uMsr/7hL8fjm5wnOfPCYBd/YxlIhP1viVKQ8UEoU" +
		"YNRbzvudgBWvWgj9N1tDuGtBsfK5KJ94ymVsN2VFtYP5Xrikpaa7wfkhev9ANVl8" +
		"IJhfqU0CuuvQyd1lEmH8AbwYdTYvwCMdRKsCSpPGdxe7p7AQSALL/622cJQsfXxw" +
		"4U7o5WvE3EDeXMiB2uVDeAmevKBvQZOoGt57XV35iOdnZJpv5cpLBSh8xHp07Ih4" +
		"PC//yvmncT0cwS6m6afzwwljMSqC+7+gOzJmzLD0jX0GpW+9/034hpbjcnIYkupt" +
		"uoEIqLsNvj6vIKur1erjCQ=="

	key, err := parsePrivateKey(goldenPEM)
	if err != nil {
		t.Fatalf("parsePrivateKey: %v", err)
	}

	sig, err := signWithRSA2(key, goldenContent)
	if err != nil {
		t.Fatalf("signWithRSA2: %v", err)
	}

	if sig != goldenSignature {
		t.Errorf("golden signature mismatch:\n  got  %q\n  want %q", sig, goldenSignature)
	}

	// Also verify with buildSignContent to confirm param sort order
	params := map[string]string{
		"app_id":    "2021001234567890",
		"charset":   "utf-8",
		"method":    "alipay.system.oauth.token",
		"sign_type": "RSA2",
		"timestamp": "2025-01-01 00:00:00",
		"version":   "1.0",
	}
	content := buildSignContent(params)
	if content != goldenContent {
		t.Errorf("buildSignContent mismatch:\n  got  %q\n  want %q", content, goldenContent)
	}

	sig2, err := signWithRSA2(key, content)
	if err != nil {
		t.Fatalf("signWithRSA2 (from buildSignContent): %v", err)
	}
	if sig2 != goldenSignature {
		t.Errorf("signature from buildSignContent mismatch:\n  got  %q\n  want %q", sig2, goldenSignature)
	}
}
