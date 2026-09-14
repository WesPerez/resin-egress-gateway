package gateway

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func tlsProfileRequest(profile string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/forward/tls-v1", strings.NewReader(`{}`))
	req.Header.Set("Proxy-Authorization", "Bearer gateway-secret")
	req.Header.Set(targetHeader, base64.RawURLEncoding.EncodeToString([]byte("https://upstream.example/api/user/checkin")))
	req.Header.Set(keyHeader, "AppsGlobal.metapi-account-167")
	req.Header.Set(retryModeHeader, "safe")
	req.Header.Set(tlsProfileHeader, profile)
	req.Header.Set(resinTLSProfileHeader, "injected")
	return req
}

func TestTLSProfileSurvivesRetryIdentityRotation(t *testing.T) {
	profile := "v1:42726:" + strings.Repeat("a", 64)
	var calls atomic.Int32
	var profiles, identities []string
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/https+tls-v1/") {
			t.Errorf("account request used an unversioned Resin protocol: %s", r.URL.Path)
		}
		profiles = append(profiles, r.Header.Get(resinTLSProfileHeader))
		identities = append(identities, r.Header.Get(resinAccountHeader))
		if r.Header.Get(tlsProfileHeader) != "" {
			t.Error("egress control header leaked to Resin")
		}
		if calls.Add(1) < 3 {
			w.Header().Set(resinErrorHeader, "UPSTREAM_REQUEST_FAILED")
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set(resinTLSProfileHeader, profile)
		w.Write([]byte(`{"ok":true}`))
	}))
	recorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(recorder, tlsProfileRequest(profile))
	if recorder.Code != http.StatusOK || calls.Load() != 3 {
		t.Fatalf("status %d; calls %d", recorder.Code, calls.Load())
	}
	for _, got := range profiles {
		if got != profile {
			t.Fatalf("profile changed on retry: %q", got)
		}
	}
	if identities[0] == identities[1] || identities[1] == identities[2] {
		t.Fatal("lease identities should rotate independently of TLS")
	}
	if recorder.Header().Get(resinTLSProfileHeader) != "" || recorder.Header().Get(tlsProfileHeader) != profile {
		t.Fatal("profile acknowledgment must use the gateway protocol")
	}
}

func TestMissingTLSProfileAcknowledgmentDoesNotReplayPOST(t *testing.T) {
	var calls atomic.Int32
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"success":true}`))
	}))
	recorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(recorder, tlsProfileRequest("v1:42726:"+strings.Repeat("a", 64)))
	if recorder.Code != http.StatusBadGateway || calls.Load() != 1 {
		t.Fatalf("status %d; calls %d", recorder.Code, calls.Load())
	}
}

func TestRejectInvalidTLSProfileBeforeResin(t *testing.T) {
	var calls atomic.Int32
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	for _, profile := range []string{"", "invalid", "v2:1:" + strings.Repeat("a", 64), "v1:103680:" + strings.Repeat("a", 64)} {
		recorder := httptest.NewRecorder()
		gateway.Handler().ServeHTTP(recorder, tlsProfileRequest(profile))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status %d", recorder.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid profile reached Resin")
	}
}

func TestOlderResinRejectsTLSProtocolBeforeForwarding(t *testing.T) {
	var forwarded atomic.Int32
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/https+tls-v1/") {
			w.Header().Set(resinErrorHeader, "INVALID_PROTOCOL")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		forwarded.Add(1)
		w.Write([]byte(`{"success":true}`))
	}))
	recorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(recorder, tlsProfileRequest("v1:42726:"+strings.Repeat("a", 64)))
	if recorder.Code != http.StatusBadRequest || forwarded.Load() != 0 {
		t.Fatalf("status %d; unisolated upstream requests %d", recorder.Code, forwarded.Load())
	}
}
