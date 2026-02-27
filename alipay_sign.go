package authhub

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/url"
	"sort"
	"strings"
)

// parsePrivateKey decodes a PEM-encoded RSA private key.
// It tries PKCS8 first, then falls back to PKCS1.
// If pemData does not start with "-----BEGIN", it is assumed to be raw base64
// and wrapped with RSA PRIVATE KEY PEM headers before decoding.
func parsePrivateKey(pemData string) (*rsa.PrivateKey, error) {
	pemData = strings.TrimSpace(pemData)

	// If no PEM header, wrap as PKCS1 PEM
	if !strings.HasPrefix(pemData, "-----BEGIN") {
		pemData = "-----BEGIN RSA PRIVATE KEY-----\n" + pemData + "\n-----END RSA PRIVATE KEY-----"
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "failed to decode PEM block", nil)
	}

	// Try PKCS8 first
	key, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if pkcs8Err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "private key is not RSA", nil)
		}
		return rsaKey, nil
	}

	// Fall back to PKCS1
	rsaKey, pkcs1Err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if pkcs1Err != nil {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "failed to parse private key: PKCS8: "+pkcs8Err.Error()+"; PKCS1: "+pkcs1Err.Error(), pkcs1Err)
	}
	return rsaKey, nil
}

// signWithRSA2 signs the content using SHA256WithRSA (RSA2) and returns
// the base64-encoded signature.
func signWithRSA2(privateKey *rsa.PrivateKey, content string) (string, error) {
	h := sha256.Sum256([]byte(content))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h[:])
	if err != nil {
		return "", newAuthError(ErrKindSignature, "alipay", "", "RSA2 sign failed: "+err.Error(), err)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// buildSignContent sorts the parameters by key alphabetically and joins
// them as "key1=value1&key2=value2&...". Entries with empty values are skipped.
func buildSignContent(params map[string]string) string {
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

// buildAlipayRequestParams merges bizParams and commonParams, builds the
// sign content, signs it with the private key, adds the "sign" field,
// and returns the complete set of parameters as url.Values.
func buildAlipayRequestParams(bizParams map[string]string, commonParams map[string]string, privateKey *rsa.PrivateKey) (url.Values, error) {
	// Merge all params: commonParams first, then bizParams (biz overrides common on conflict)
	merged := make(map[string]string, len(bizParams)+len(commonParams))
	for k, v := range commonParams {
		merged[k] = v
	}
	for k, v := range bizParams {
		merged[k] = v
	}

	// Build sign content and sign
	content := buildSignContent(merged)
	sign, err := signWithRSA2(privateKey, content)
	if err != nil {
		return nil, err
	}

	// Add sign to merged params and convert to url.Values
	merged["sign"] = sign
	values := make(url.Values, len(merged))
	for k, v := range merged {
		values.Set(k, v)
	}
	return values, nil
}
