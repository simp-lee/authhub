package authhub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewDefaultHTTPClient(t *testing.T) {
	client := newDefaultHTTPClient()
	if client == nil {
		t.Fatal("newDefaultHTTPClient returned nil")
	}
	if client.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v; want %v", client.Timeout, 10*time.Second)
	}
}

func TestMaskURL(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		contains []string // substrings that must be present
		excludes []string // substrings that must NOT be present
	}{
		{
			name:     "no query params unchanged",
			rawURL:   "https://example.com/path",
			contains: []string{"https://example.com/path"},
		},
		{
			name:     "sensitive access_token masked",
			rawURL:   "https://api.example.com/info?access_token=abcdefgh12345&openid=user123",
			contains: []string{"abcd****", "openid=user123"},
			excludes: []string{"abcdefgh12345"},
		},
		{
			name:     "sensitive secret masked",
			rawURL:   "https://api.example.com/?secret=mysecretvalue&name=test",
			contains: []string{"myse****", "name=test"},
			excludes: []string{"mysecretvalue"},
		},
		{
			name:     "short sensitive value fully masked",
			rawURL:   "https://api.example.com/?token=abc",
			contains: []string{"****"},
			excludes: []string{"token=abc"},
		},
		{
			name:     "invalid URL returned as-is",
			rawURL:   "://invalid\x7f",
			contains: []string{"://invalid"},
		},
		{
			name:     "non-sensitive params unchanged",
			rawURL:   "https://example.com/?openid=user123&lang=zh_CN",
			contains: []string{"openid=user123", "lang=zh_CN"},
		},
		{
			name:     "non-sensitive value with reserved chars remains encoded",
			rawURL:   "https://example.com/?note=a%26b%3Dc",
			contains: []string{"note=a%26b%3Dc"},
			excludes: []string{"note=a&b=c"},
		},
		{
			name:     "non-sensitive value with newline is escaped",
			rawURL:   "https://example.com/?note=line1%0Aline2",
			contains: []string{"note=line1%0Aline2"},
			excludes: []string{"\n"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskURL(tt.rawURL)
			for _, s := range tt.contains {
				if !strings.Contains(got, s) {
					t.Errorf("maskURL(%q) = %q; want to contain %q", tt.rawURL, got, s)
				}
			}
			for _, s := range tt.excludes {
				if strings.Contains(got, s) {
					t.Errorf("maskURL(%q) = %q; should NOT contain %q", tt.rawURL, got, s)
				}
			}
		})
	}
}

func TestDoGet_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s; want GET", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()

	body, err := doGet(context.Background(), srv.Client(), srv.URL+"/test", &noopLogger{})
	if err != nil {
		t.Fatalf("doGet returned error: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q; want %q", string(body), `{"ok":true}`)
	}
}

func TestDoGet_Non2xx(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"400 Bad Request", http.StatusBadRequest},
		{"404 Not Found", http.StatusNotFound},
		{"500 Internal Server Error", http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = fmt.Fprint(w, "error body content")
			}))
			defer srv.Close()

			_, err := doGet(context.Background(), srv.Client(), srv.URL+"/fail", &noopLogger{})
			if err == nil {
				t.Fatal("expected error for non-2xx status")
			}

			var authErr *AuthError
			if !errors.As(err, &authErr) {
				t.Fatalf("error is not *AuthError: %v", err)
			}
			if authErr.Kind != ErrKindNetwork {
				t.Errorf("Kind = %q; want %q", authErr.Kind, ErrKindNetwork)
			}
			if !errors.Is(err, ErrNetwork) {
				t.Error("errors.Is(err, ErrNetwork) = false; want true")
			}
			wantStatus := fmt.Sprintf("HTTP %d", tt.statusCode)
			if !strings.Contains(authErr.Message, wantStatus) {
				t.Errorf("Message = %q; want to contain %q", authErr.Message, wantStatus)
			}
			if !strings.Contains(authErr.Message, "error body content") {
				t.Errorf("Message = %q; want to contain response body preview", authErr.Message)
			}
		})
	}
}

func TestDoGet_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := doGet(ctx, srv.Client(), srv.URL+"/slow", &noopLogger{})
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error is not *AuthError: %v", err)
	}
	if authErr.Kind != ErrKindNetwork {
		t.Errorf("Kind = %q; want %q", authErr.Kind, ErrKindNetwork)
	}
}

func TestDoGet_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 50 * time.Millisecond}
	_, err := doGet(context.Background(), client, srv.URL+"/slow", &noopLogger{})
	if err == nil {
		t.Fatal("expected error for timeout")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error is not *AuthError: %v", err)
	}
	if authErr.Kind != ErrKindNetwork {
		t.Errorf("Kind = %q; want %q", authErr.Kind, ErrKindNetwork)
	}
}

func TestDoPostForm_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s; want POST", r.Method)
		}
		ct := r.Header.Get("Content-Type")
		if ct != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q; want %q", ct, "application/x-www-form-urlencoded")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.PostFormValue("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q; want %q", r.PostFormValue("grant_type"), "authorization_code")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"result":"success"}`)
	}))
	defer srv.Close()

	vals := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"testcode123"},
	}
	body, err := doPostForm(context.Background(), srv.Client(), srv.URL+"/token", vals, &noopLogger{})
	if err != nil {
		t.Fatalf("doPostForm returned error: %v", err)
	}
	if string(body) != `{"result":"success"}` {
		t.Errorf("body = %q; want %q", string(body), `{"result":"success"}`)
	}
}

func TestDoPostForm_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, "forbidden")
	}))
	defer srv.Close()

	_, err := doPostForm(context.Background(), srv.Client(), srv.URL+"/fail", url.Values{"key": {"val"}}, &noopLogger{})
	if err == nil {
		t.Fatal("expected error for non-2xx status")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error is not *AuthError: %v", err)
	}
	if authErr.Kind != ErrKindNetwork {
		t.Errorf("Kind = %q; want %q", authErr.Kind, ErrKindNetwork)
	}
	if !strings.Contains(authErr.Message, "HTTP 403") {
		t.Errorf("Message = %q; want to contain %q", authErr.Message, "HTTP 403")
	}
	if !strings.Contains(authErr.Message, "POST") {
		t.Errorf("Message = %q; want to contain %q", authErr.Message, "POST")
	}
	if !strings.Contains(authErr.Message, "forbidden") {
		t.Errorf("Message = %q; want to contain response body preview %q", authErr.Message, "forbidden")
	}
}

func TestDoPostForm_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := doPostForm(ctx, srv.Client(), srv.URL+"/slow", url.Values{}, &noopLogger{})
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error is not *AuthError: %v", err)
	}
	if authErr.Kind != ErrKindNetwork {
		t.Errorf("Kind = %q; want %q", authErr.Kind, ErrKindNetwork)
	}
}

func TestDoPostForm_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 50 * time.Millisecond}
	_, err := doPostForm(context.Background(), client, srv.URL+"/slow", url.Values{"k": {"v"}}, &noopLogger{})
	if err == nil {
		t.Fatal("expected error for timeout")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error is not *AuthError: %v", err)
	}
	if authErr.Kind != ErrKindNetwork {
		t.Errorf("Kind = %q; want %q", authErr.Kind, ErrKindNetwork)
	}
}

func TestReadBody_ReadsAndCloses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello body")
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("http.Get: %v", err)
	}
	body, err := readBody(resp)
	if err != nil {
		t.Fatalf("readBody returned error: %v", err)
	}
	if string(body) != "hello body" {
		t.Errorf("body = %q; want %q", string(body), "hello body")
	}
	// After readBody, body should be closed — reading again should return 0 bytes or error.
	n, readErr := resp.Body.Read(make([]byte, 1))
	if n != 0 || readErr == nil {
		t.Errorf("expected 0 bytes and error after body closed; got n=%d, err=%v", n, readErr)
	}
}

func TestReadBody_LimitsSize(t *testing.T) {
	// Serve a response larger than maxResponseSize (1 MB).
	oversized := strings.Repeat("A", maxResponseSize+1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, oversized)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("http.Get: %v", err)
	}
	body, err := readBody(resp)
	if err != nil {
		t.Fatalf("readBody returned error: %v", err)
	}
	if len(body) != maxResponseSize {
		t.Errorf("body length = %d; want %d (maxResponseSize)", len(body), maxResponseSize)
	}
}

func TestDoGet_LoggerCalled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	logger := &recordingLogger{}
	_, err := doGet(context.Background(), srv.Client(), srv.URL+"/test?access_token=secret1234", logger)
	if err != nil {
		t.Fatalf("doGet returned error: %v", err)
	}

	if len(logger.debugMessages) < 2 {
		t.Fatalf("expected at least 2 debug log messages; got %d", len(logger.debugMessages))
	}

	// Verify sensitive values are masked in log messages
	for _, msg := range logger.debugMessages {
		for _, arg := range msg.args {
			s, ok := arg.(string)
			if ok && strings.Contains(s, "secret1234") {
				t.Errorf("log contains unmasked sensitive value: %v", msg.args)
			}
		}
	}
}

func TestDoPostForm_LoggerCalled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	logger := &recordingLogger{}
	_, err := doPostForm(context.Background(), srv.Client(), srv.URL+"/token?client_secret=topsecret99", url.Values{"code": {"abc"}}, logger)
	if err != nil {
		t.Fatalf("doPostForm returned error: %v", err)
	}

	if len(logger.debugMessages) < 2 {
		t.Fatalf("expected at least 2 debug log messages; got %d", len(logger.debugMessages))
	}

	// Verify sensitive values are masked in log messages
	for _, msg := range logger.debugMessages {
		for _, arg := range msg.args {
			s, ok := arg.(string)
			if ok && strings.Contains(s, "topsecret99") {
				t.Errorf("log contains unmasked sensitive value: %v", msg.args)
			}
		}
	}
}

func TestDoGet_NetworkErrorWrapped(t *testing.T) {
	// Use an invalid URL to trigger a request error
	_, err := doGet(context.Background(), http.DefaultClient, "http://127.0.0.1:0/invalid", &noopLogger{})
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error is not *AuthError: %v", err)
	}
	if authErr.Kind != ErrKindNetwork {
		t.Errorf("Kind = %q; want %q", authErr.Kind, ErrKindNetwork)
	}
	// Should have the wrapped underlying error
	if authErr.Err == nil {
		t.Error("expected wrapped error to be non-nil")
	}
}

func TestDoGet_ProviderEmpty(t *testing.T) {
	// Verify that Provider is empty (caller sets it)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	_, err := doGet(context.Background(), srv.Client(), srv.URL, &noopLogger{})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error is not *AuthError: %v", err)
	}
	if authErr.Provider != "" {
		t.Errorf("Provider = %q; want empty string", authErr.Provider)
	}
}

// recordingLogger captures log messages for test assertions.
type recordingLogger struct {
	debugMessages []logEntry
}

type logEntry struct {
	msg  string
	args []any
}

func (l *recordingLogger) Debug(msg string, args ...any) {
	l.debugMessages = append(l.debugMessages, logEntry{msg: msg, args: args})
}
func (l *recordingLogger) Info(msg string, args ...any)  {}
func (l *recordingLogger) Warn(msg string, args ...any)  {}
func (l *recordingLogger) Error(msg string, args ...any) {}
