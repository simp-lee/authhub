package authhub

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
)

// parsePublicKey decodes a PEM-encoded RSA public key.
// It tries PKIX first, then falls back to PKCS1.
// If pemData does not start with "-----BEGIN", it is assumed to be raw base64
// and wrapped with PUBLIC KEY PEM headers before decoding.
func parsePublicKey(pemData string) (*rsa.PublicKey, error) {
	pemData = strings.TrimSpace(pemData)

	// If no PEM header, wrap as PKIX PEM
	if !strings.HasPrefix(pemData, "-----BEGIN") {
		pemData = "-----BEGIN PUBLIC KEY-----\n" + pemData + "\n-----END PUBLIC KEY-----"
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "failed to decode PEM block", nil)
	}

	// Try PKIX first
	key, pkixErr := x509.ParsePKIXPublicKey(block.Bytes)
	if pkixErr == nil {
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "public key is not RSA", nil)
		}
		return rsaKey, nil
	}

	// Fall back to PKCS1
	rsaKey, pkcs1Err := x509.ParsePKCS1PublicKey(block.Bytes)
	if pkcs1Err != nil {
		return nil, newAuthError(ErrKindInvalidConfig, "alipay", "", "failed to parse public key: PKIX: "+pkixErr.Error()+"; PKCS1: "+pkcs1Err.Error(), pkcs1Err)
	}
	return rsaKey, nil
}

// verifyRSA2Signature verifies a SHA256WithRSA (RSA2) signature.
// The signature is expected to be base64-encoded.
func verifyRSA2Signature(publicKey *rsa.PublicKey, content, signature string) error {
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return newAuthError(ErrKindSignature, "alipay", "", "signature verification failed: invalid base64: "+err.Error(), err)
	}

	h := sha256.Sum256([]byte(content))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, h[:], sigBytes); err != nil {
		return newAuthError(ErrKindSignature, "alipay", "", "signature verification failed", err)
	}
	return nil
}

// extractSignContent extracts the raw JSON content of the response node,
// the signature value, and the optional certificate serial number from
// a complete Alipay API response body.
//
// The content is extracted using byte-level scanning to preserve the exact
// JSON as returned by Alipay (key order, whitespace), which is critical
// for signature verification.
func extractSignContent(body []byte, nodeName string) (content string, sign string, certSN string, err error) {
	s := string(body)

	valueStart, valueEnd, found, scanErr := findTopLevelObjectValueSpan(s, nodeName)
	if scanErr != nil {
		err = newAuthError(ErrKindSignature, "alipay", "", "malformed response: "+scanErr.Error(), nil)
		return
	}
	if !found {
		err = newAuthError(ErrKindSignature, "alipay", "", "response node not found: "+nodeName, nil)
		return
	}

	content = s[valueStart:valueEnd]

	// Extract top-level sign and alipay_cert_sn from the whole response body.
	sign = extractJSONStringField(s, "sign")
	if sign == "" {
		err = newAuthError(ErrKindSignature, "alipay", "", "sign field not found in response", nil)
		return
	}

	// Extract alipay_cert_sn field (optional, may not exist)
	certSN = extractJSONStringField(s, "alipay_cert_sn")

	return
}

func findTopLevelObjectValueSpan(s, targetKey string) (start int, end int, found bool, err error) {
	i := skipJSONWhitespace(s, 0)
	if i >= len(s) || s[i] != '{' {
		return 0, 0, false, newAuthError(ErrKindSignature, "alipay", "", "response is not a JSON object", nil)
	}
	i++

	for {
		i = skipJSONWhitespace(s, i)
		if i >= len(s) {
			return 0, 0, false, newAuthError(ErrKindSignature, "alipay", "", "unexpected end of JSON object", nil)
		}
		if s[i] == '}' {
			return 0, 0, false, nil
		}

		key, next, keyErr := readJSONStringToken(s, i)
		if keyErr != nil {
			return 0, 0, false, keyErr
		}
		i = skipJSONWhitespace(s, next)
		if i >= len(s) || s[i] != ':' {
			return 0, 0, false, newAuthError(ErrKindSignature, "alipay", "", "missing colon after key", nil)
		}
		i++
		i = skipJSONWhitespace(s, i)

		valueStart := i
		valueEnd, valueType, valueErr := scanJSONValueEnd(s, valueStart)
		if valueErr != nil {
			return 0, 0, false, valueErr
		}

		if key == targetKey {
			if valueType != '{' {
				return 0, 0, false, newAuthError(ErrKindSignature, "alipay", "", "response node is not a JSON object: "+targetKey, nil)
			}
			return valueStart, valueEnd, true, nil
		}

		i = skipJSONWhitespace(s, valueEnd)
		if i >= len(s) {
			return 0, 0, false, newAuthError(ErrKindSignature, "alipay", "", "unexpected end after value", nil)
		}
		if s[i] == ',' {
			i++
			continue
		}
		if s[i] == '}' {
			return 0, 0, false, nil
		}
		return 0, 0, false, newAuthError(ErrKindSignature, "alipay", "", "invalid JSON object separator", nil)
	}
}

func skipJSONWhitespace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

func readJSONStringToken(s string, start int) (string, int, error) {
	if start >= len(s) || s[start] != '"' {
		return "", start, newAuthError(ErrKindSignature, "alipay", "", "expected JSON string key", nil)
	}

	i := start + 1
	escaped := false
	for i < len(s) {
		ch := s[i]
		if escaped {
			escaped = false
			i++
			continue
		}
		if ch == '\\' {
			escaped = true
			i++
			continue
		}
		if ch == '"' {
			i++
			break
		}
		i++
	}

	if i > len(s) || s[i-1] != '"' {
		return "", start, newAuthError(ErrKindSignature, "alipay", "", "unterminated JSON string key", nil)
	}

	raw := s[start:i]
	var key string
	if err := json.Unmarshal([]byte(raw), &key); err != nil {
		return "", start, newAuthError(ErrKindSignature, "alipay", "", "invalid JSON string key", err)
	}

	return key, i, nil
}

func scanJSONValueEnd(s string, start int) (int, byte, error) {
	if start >= len(s) {
		return 0, 0, newAuthError(ErrKindSignature, "alipay", "", "missing JSON value", nil)
	}

	first := s[start]
	switch first {
	case '{', '[':
		return scanJSONComposite(s, start, first)
	case '"':
		return scanJSONString(s, start)
	default:
		return scanJSONLiteral(s, start, first)
	}
}

// scanJSONComposite scans a JSON object or array starting at s[start],
// tracking nested brackets and strings, and returns the position after
// the closing bracket.
func scanJSONComposite(s string, start int, first byte) (int, byte, error) {
	stack := []byte{}
	if first == '{' {
		stack = append(stack, '}')
	} else {
		stack = append(stack, ']')
	}

	inString := false
	escaped := false
	for i := start + 1; i < len(s); i++ {
		ch := s[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}

		if ch == '"' {
			inString = true
			continue
		}

		switch ch {
		case '{':
			stack = append(stack, '}')
		case '[':
			stack = append(stack, ']')
		case '}', ']':
			if len(stack) == 0 || stack[len(stack)-1] != ch {
				return 0, 0, newAuthError(ErrKindSignature, "alipay", "", "mismatched JSON brackets", nil)
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return i + 1, first, nil
			}
		}
	}

	return 0, 0, newAuthError(ErrKindSignature, "alipay", "", "unterminated JSON composite value", nil)
}

// scanJSONString scans a JSON string starting at s[start] (which must be '"')
// and returns the position after the closing quote.
func scanJSONString(s string, start int) (int, byte, error) {
	i := start + 1
	escaped := false
	for i < len(s) {
		ch := s[i]
		if escaped {
			escaped = false
			i++
			continue
		}
		if ch == '\\' {
			escaped = true
			i++
			continue
		}
		if ch == '"' {
			return i + 1, '"', nil
		}
		i++
	}
	return 0, 0, newAuthError(ErrKindSignature, "alipay", "", "unterminated JSON string value", nil)
}

// scanJSONLiteral scans a JSON literal (number, true, false, null) starting
// at s[start] and returns the position after the last character.
func scanJSONLiteral(s string, start int, first byte) (int, byte, error) {
	i := start
	for i < len(s) {
		ch := s[i]
		if ch == ',' || ch == '}' || ch == ']' || ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			break
		}
		i++
	}
	if i == start {
		return 0, 0, newAuthError(ErrKindSignature, "alipay", "", "invalid JSON value", nil)
	}

	return i, first, nil
}

// extractJSONStringField extracts a top-level JSON string field value and
// returns the unescaped JSON string content.
func extractJSONStringField(s string, fieldName string) string {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &top); err != nil {
		return ""
	}
	raw, ok := top[fieldName]
	if !ok {
		return ""
	}

	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return value
}

// verifyAlipayResponse extracts the response content and signature from
// a complete Alipay API response body, then verifies the RSA2 signature.
// On any failure it returns an AuthError with Kind ErrKindSignature.
func verifyAlipayResponse(body []byte, nodeName string, publicKey *rsa.PublicKey) error {
	content, sign, _, err := extractSignContent(body, nodeName)
	if err != nil {
		return err
	}
	return verifyRSA2Signature(publicKey, content, sign)
}
