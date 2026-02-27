package authhub

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// newDefaultHTTPClient returns a new http.Client with a default timeout of 10 seconds.
func newDefaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

// maskURL masks sensitive query parameter values in a URL for safe logging.
// Parameter values whose keys match sensitive substrings (token, secret, key, etc.)
// are masked using the same rules as maskSensitive.
// If the URL cannot be parsed, it is returned unchanged.
func maskURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	if len(q) == 0 {
		return rawURL
	}
	// Build the query string manually to avoid percent-encoding the masked
	// asterisks, producing a human-readable URL suitable for logging.
	// Keys are sorted for deterministic output across calls.
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, key := range keys {
		for _, v := range q[key] {
			maskedValue := maskSensitive(key, v)
			escapedValue := url.QueryEscape(maskedValue)
			escapedValue = strings.ReplaceAll(escapedValue, "%2A", "*")
			parts = append(parts, url.QueryEscape(key)+"="+escapedValue)
		}
	}
	u.RawQuery = strings.Join(parts, "&")
	return u.String()
}

// maxResponseSize is the upper limit on HTTP response bodies read by readBody.
// OAuth token and userinfo responses are typically <10KB; 1MB is generous.
const maxResponseSize = 1 << 20 // 1 MB

// readBody reads the response body (up to maxResponseSize bytes) and closes it.
func readBody(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
}

// doGet sends an HTTP GET request using the provided client and context.
// It logs the masked request URL before sending and the response status after.
// On success (2xx), it returns the response body.
// On failure, it returns an *AuthError with Kind ErrKindNetwork.
// The Provider field is left empty; callers should set it as needed.
func doGet(ctx context.Context, client *http.Client, rawURL string, logger Logger) ([]byte, error) {
	masked := maskURL(rawURL)
	logger.Debug("HTTP request", "method", "GET", "url", masked)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, newAuthError(ErrKindNetwork, "", "", fmt.Sprintf("GET %s: %v", masked, err), err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, newAuthError(ErrKindNetwork, "", "", fmt.Sprintf("GET %s: %v", masked, err), err)
	}

	logger.Debug("HTTP response", "method", "GET", "url", masked, "status", resp.StatusCode)

	body, err := readBody(resp)
	if err != nil {
		return nil, newAuthError(ErrKindNetwork, "", "", fmt.Sprintf("HTTP %d, GET %s: read body: %v", resp.StatusCode, masked, err), err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview := string(body)
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		return nil, newAuthError(ErrKindNetwork, "", "", fmt.Sprintf("HTTP %d, GET %s: %s", resp.StatusCode, masked, preview), nil)
	}

	return body, nil
}

// doPostForm sends an HTTP POST request with form-encoded body using the provided
// client and context. The Content-Type header is set to application/x-www-form-urlencoded.
// It logs the masked request URL before sending and the response status after.
// On success (2xx), it returns the response body.
// On failure, it returns an *AuthError with Kind ErrKindNetwork.
// The Provider field is left empty; callers should set it as needed.
func doPostForm(ctx context.Context, client *http.Client, rawURL string, values url.Values, logger Logger) ([]byte, error) {
	masked := maskURL(rawURL)
	logger.Debug("HTTP request", "method", "POST", "url", masked)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, newAuthError(ErrKindNetwork, "", "", fmt.Sprintf("POST %s: %v", masked, err), err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, newAuthError(ErrKindNetwork, "", "", fmt.Sprintf("POST %s: %v", masked, err), err)
	}

	logger.Debug("HTTP response", "method", "POST", "url", masked, "status", resp.StatusCode)

	body, err := readBody(resp)
	if err != nil {
		return nil, newAuthError(ErrKindNetwork, "", "", fmt.Sprintf("HTTP %d, POST %s: read body: %v", resp.StatusCode, masked, err), err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview := string(body)
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		return nil, newAuthError(ErrKindNetwork, "", "", fmt.Sprintf("HTTP %d, POST %s: %s", resp.StatusCode, masked, preview), nil)
	}

	return body, nil
}
