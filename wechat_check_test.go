package authhub

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// CheckWechatToken
// ---------------------------------------------------------------------------

func TestCheckWechatToken_Valid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sns/auth" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("access_token"); got != "valid_token" {
			t.Errorf("access_token = %q, want %q", got, "valid_token")
		}
		if got := r.URL.Query().Get("openid"); got != "o_openid" {
			t.Errorf("openid = %q, want %q", got, "o_openid")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "errmsg": "ok"})
	}))
	defer ts.Close()

	valid, err := CheckWechatToken(context.Background(), "valid_token", "o_openid",
		WithHTTPClient(ts.Client()),
		withWechatCheckBaseURL(ts.URL),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected valid=true, got false")
	}
}

func TestCheckWechatToken_Expired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 40003, "errmsg": "invalid openid"})
	}))
	defer ts.Close()

	valid, err := CheckWechatToken(context.Background(), "expired_token", "o_openid",
		WithHTTPClient(ts.Client()),
		withWechatCheckBaseURL(ts.URL),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected valid=false, got true")
	}
}

func TestCheckWechatToken_NetworkError(t *testing.T) {
	// Point at a closed server to trigger a network error.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.Close()

	valid, err := CheckWechatToken(context.Background(), "tok", "oid",
		WithHTTPClient(ts.Client()),
		withWechatCheckBaseURL(ts.URL),
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if valid {
		t.Error("expected valid=false on network error")
	}
	if !errors.Is(err, ErrNetwork) {
		t.Errorf("expected ErrNetwork, got %v", err)
	}
}

func TestCheckWechatToken_EmptyAccessToken(t *testing.T) {
	valid, err := CheckWechatToken(context.Background(), "", "o_openid")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if valid {
		t.Error("expected valid=false")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
	ae, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	if ae.Provider != "wechat_check" {
		t.Errorf("provider = %q; want %q", ae.Provider, "wechat_check")
	}
}

func TestCheckWechatToken_EmptyOpenID(t *testing.T) {
	valid, err := CheckWechatToken(context.Background(), "some_token", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if valid {
		t.Error("expected valid=false")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestCheckWechatToken_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer ts.Close()

	valid, err := CheckWechatToken(context.Background(), "tok", "oid",
		WithHTTPClient(ts.Client()),
		withWechatCheckBaseURL(ts.URL),
	)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if valid {
		t.Error("expected valid=false for invalid JSON")
	}
	ae, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	if ae.Provider != "wechat_check" {
		t.Errorf("provider = %q; want %q", ae.Provider, "wechat_check")
	}
}

func TestCheckWechatToken_CancelledContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "errmsg": "ok"})
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	valid, err := CheckWechatToken(ctx, "tok", "oid",
		WithHTTPClient(ts.Client()),
		withWechatCheckBaseURL(ts.URL),
	)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if valid {
		t.Error("expected valid=false for cancelled context")
	}
	ae, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	if ae.Provider != "wechat_check" {
		t.Errorf("provider = %q; want %q", ae.Provider, "wechat_check")
	}
}

// ---------------------------------------------------------------------------
// CheckWechatToken — expired token (errcode 42001)
// ---------------------------------------------------------------------------

func TestCheckWechatToken_ExpiredToken42001(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 42001, "errmsg": "access_token expired"})
	}))
	defer ts.Close()

	valid, err := CheckWechatToken(context.Background(), "expired_token", "o_openid",
		WithHTTPClient(ts.Client()),
		withWechatCheckBaseURL(ts.URL),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected valid=false for expired token")
	}
}

// ---------------------------------------------------------------------------
// Concurrency safety
// ---------------------------------------------------------------------------

func TestCheckWechatToken_Concurrency(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "errmsg": "ok"})
	}))
	defer ts.Close()

	const goroutines = 10
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			valid, err := CheckWechatToken(context.Background(), "tok", "oid",
				WithHTTPClient(ts.Client()),
				withWechatCheckBaseURL(ts.URL),
			)
			if err != nil {
				errCh <- err
				return
			}
			if !valid {
				errCh <- errors.New("expected valid=true")
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent call failed: %v", err)
	}
}
