package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestGateway(t *testing.T, resin http.Handler) (*Gateway, *httptest.Server) {
	t.Helper()
	resinServer := httptest.NewServer(resin)
	t.Cleanup(resinServer.Close)
	baseURL, err := url.Parse(resinServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewStateStore(filepath.Join(t.TempDir(), "state.json"), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		AuthToken:             "gateway-secret",
		ResinBaseURL:          baseURL,
		ResinProxyToken:       "resin-secret",
		ResinPlatform:         "AppsGlobal",
		StatePath:             filepath.Join(t.TempDir(), "unused.json"),
		MaxRequestBodyBytes:   1024,
		MaxResponseBodyBytes:  1024,
		MaxAttempts:           3,
		ResponseHeaderTimeout: 200 * time.Millisecond,
		FirstByteTimeout:      200 * time.Millisecond,
		MaxRetryAfter:         10 * time.Millisecond,
		RouteStateTTL:         24 * time.Hour,
		AllowHTTP:             true,
		AllowPrivateTargets:   true,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, state, logger), resinServer
}

func forwardRequest(t *testing.T, handler http.Handler, method, target, key, mode string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/v1/forward", bytes.NewReader(body))
	req.Header.Set("Proxy-Authorization", "Bearer gateway-secret")
	req.Header.Set(targetHeader, base64.RawURLEncoding.EncodeToString([]byte(target)))
	req.Header.Set(keyHeader, key)
	if mode != "" {
		req.Header.Set(retryModeHeader, mode)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func TestAuthenticationAndTargetValidation(t *testing.T) {
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("Resin should not be called")
	}))

	unauthorized := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/forward", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/forward", nil)
	req.Header.Set("Proxy-Authorization", "Bearer gateway-secret")
	req.Header.Set(targetHeader, "not-base64")
	req.Header.Set(keyHeader, "key")
	recorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("malformed target status = %d", recorder.Code)
	}
}

func TestTransportRetryReplaysBodyAcrossNewIdentities(t *testing.T) {
	var calls atomic.Int32
	var mu sync.Mutex
	var bodies []string
	var identities []string
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		identities = append(identities, r.Header.Get(resinAccountHeader))
		mu.Unlock()
		if calls.Add(1) < 3 {
			w.Header().Set(resinErrorHeader, "UPSTREAM_REQUEST_FAILED")
			http.Error(w, "failed", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))

	recorder := forwardRequest(t, gateway.Handler(), http.MethodPost, "http://service.test/checkin?day=1", "account-42", "transport", []byte(`{"action":"checkin"}`))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get(attemptsResponseHeader) != "3" || recorder.Header().Get(generationResponseHeader) != "2" {
		t.Fatalf("attempt headers = %q/%q", recorder.Header().Get(attemptsResponseHeader), recorder.Header().Get(generationResponseHeader))
	}
	if len(bodies) != 3 || bodies[0] != bodies[1] || bodies[1] != bodies[2] {
		t.Fatalf("bodies were not replayed exactly: %#v", bodies)
	}
	if len(identities) != 3 || identities[0] == identities[1] || identities[1] == identities[2] || identities[0] == identities[2] {
		t.Fatalf("identities were not rotated: %#v", identities)
	}
}

func TestResinReverseURLAndSensitiveHeadersArePreserved(t *testing.T) {
	var escapedPath string
	var rawQuery string
	var authorization string
	var cookie string
	var leakedControl string
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escapedPath = r.URL.EscapedPath()
		rawQuery = r.URL.RawQuery
		authorization = r.Header.Get("Authorization")
		cookie = r.Header.Get("Cookie")
		leakedControl = r.Header.Get(targetHeader)
		_, _ = io.WriteString(w, "ok")
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/forward", nil)
	req.Header.Set("Proxy-Authorization", "Bearer gateway-secret")
	req.Header.Set(targetHeader, base64.RawURLEncoding.EncodeToString([]byte("http://example.test:8443/a%2Fb?q=x%2Fy")))
	req.Header.Set(keyHeader, "account")
	req.Header.Set("Authorization", "Bearer upstream-secret")
	req.Header.Set("Cookie", "session=secret")
	recorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if escapedPath != "/resin-secret/AppsGlobal/http/example.test:8443/a%2Fb" {
		t.Fatalf("escaped Resin path = %q", escapedPath)
	}
	if rawQuery != "q=x%2Fy" {
		t.Fatalf("raw query = %q", rawQuery)
	}
	if authorization != "Bearer upstream-secret" || cookie != "session=secret" {
		t.Fatalf("sensitive headers not preserved: authorization=%q cookie=%q", authorization, cookie)
	}
	if leakedControl != "" {
		t.Fatalf("Gateway control header leaked: %q", leakedControl)
	}
}

func TestSafeRetriesStatusesButTransportDoesNot(t *testing.T) {
	var calls atomic.Int32
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}))

	transport := forwardRequest(t, gateway.Handler(), http.MethodPost, "http://service.test/checkin", "transport-key", "transport", []byte("{}"))
	if transport.Code != http.StatusServiceUnavailable || calls.Load() != 1 {
		t.Fatalf("transport mode status/calls = %d/%d", transport.Code, calls.Load())
	}

	calls.Store(0)
	safe := forwardRequest(t, gateway.Handler(), http.MethodPost, "http://service.test/checkin", "safe-key", "safe", []byte("{}"))
	if safe.Code != http.StatusServiceUnavailable || calls.Load() != 3 {
		t.Fatalf("safe mode status/calls = %d/%d", safe.Code, calls.Load())
	}
}

func TestResinAuthenticationFailureIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set(resinErrorHeader, "AUTH_FAILED")
		http.Error(w, "no", http.StatusForbidden)
	}))
	recorder := forwardRequest(t, gateway.Handler(), http.MethodGet, "http://service.test/data", "key", "safe", nil)
	if recorder.Code != http.StatusForbidden || calls.Load() != 1 {
		t.Fatalf("status/calls = %d/%d", recorder.Code, calls.Load())
	}
}

func TestFirstByteTimeoutRetriesBeforeCommit(t *testing.T) {
	var calls atomic.Int32
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		if current < 3 {
			time.Sleep(80 * time.Millisecond)
		}
		_, _ = io.WriteString(w, `{"ready":true}`)
	}))
	gateway.cfg.FirstByteTimeout = 20 * time.Millisecond
	recorder := forwardRequest(t, gateway.Handler(), http.MethodGet, "http://service.test/data", "slow-key", "transport", nil)
	if recorder.Code != http.StatusOK || calls.Load() != 3 {
		t.Fatalf("status/calls = %d/%d body=%s", recorder.Code, calls.Load(), recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "ready") {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}
}

func TestSSEFailureAfterFirstByteIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: first\n\n")
	}))
	recorder := forwardRequest(t, gateway.Handler(), http.MethodPost, "http://service.test/events", "stream-key", "transport", []byte("{}"))
	if recorder.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("status/calls = %d/%d", recorder.Code, calls.Load())
	}
	if !strings.Contains(recorder.Body.String(), "data: first") {
		t.Fatalf("missing first event: %q", recorder.Body.String())
	}
}

func TestOversizedRequestIsRejectedBeforeResin(t *testing.T) {
	var calls atomic.Int32
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	body := bytes.Repeat([]byte("x"), 1025)
	recorder := forwardRequest(t, gateway.Handler(), http.MethodPost, "http://service.test/upload", "key", "transport", body)
	if recorder.Code != http.StatusRequestEntityTooLarge || calls.Load() != 0 {
		t.Fatalf("status/calls = %d/%d", recorder.Code, calls.Load())
	}
}

func TestClientCancellationDoesNotRetry(t *testing.T) {
	var calls atomic.Int32
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-r.Context().Done()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/v1/forward", bytes.NewReader([]byte("{}"))).WithContext(ctx)
	req.Header.Set("Proxy-Authorization", "Bearer gateway-secret")
	req.Header.Set(targetHeader, base64.RawURLEncoding.EncodeToString([]byte("http://service.test/checkin")))
	req.Header.Set(keyHeader, "cancel-key")
	req.Header.Set(retryModeHeader, "transport")
	cancel()
	recorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(recorder, req)
	if calls.Load() > 1 {
		t.Fatalf("canceled request retried %d times", calls.Load())
	}
}

func TestPrivateTargetRejectedByDefault(t *testing.T) {
	baseURL, _ := url.Parse("http://127.0.0.1:1")
	state, err := NewStateStore(filepath.Join(t.TempDir(), "state.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	gateway := New(Config{
		AuthToken: "gateway-secret", ResinBaseURL: baseURL, ResinProxyToken: "resin", ResinPlatform: "AppsGlobal",
		MaxRequestBodyBytes: 1024, MaxResponseBodyBytes: 1024, MaxAttempts: 1,
		ResponseHeaderTimeout: time.Second, FirstByteTimeout: time.Second, RouteStateTTL: time.Hour,
		AllowHTTP: true, AllowPrivateTargets: false,
	}, state, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recorder := forwardRequest(t, gateway.Handler(), http.MethodGet, "http://127.0.0.1/admin", "key", "never", nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("private target status = %d", recorder.Code)
	}
}
