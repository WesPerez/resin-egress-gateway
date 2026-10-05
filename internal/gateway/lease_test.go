package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestStableAccountRecoveryAndSiteFailures(t *testing.T) {
	for _, tc := range []struct {
		code, recovery         string
		wantCalls, wantReports int
	}{
		{"UPSTREAM_REQUEST_FAILED", "rotated", 2, 1},
		{"UPSTREAM_REQUEST_FAILED", "stale_lease", 2, 1},
		{"UPSTREAM_REQUEST_FAILED", "recovery_limited", 1, 1},
		{"UPSTREAM_REQUEST_FAILED", "no_alternative", 1, 1},
		{"LEASE_GUARD_FAILED", "", 2, 0},
		{"UPSTREAM_TLS_CERTIFICATE_ERROR", "", 1, 0},
		{"http_503", "", 2, 0},
	} {
		t.Run(tc.code+tc.recovery, func(t *testing.T) {
			calls, reports, acquires := 0, 0, 0
			lease := recoveryLease{Account: "metapi-account-42", NodeHash: strings.Repeat("a", 32), CreatedAt: "123", EgressIP: "203.0.113.1", GuardVersion: 1}
			g, _ := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/proxy-api/") {
					if r.Header.Get("Authorization") != "Bearer resin-secret" {
						t.Error("missing recovery authentication")
					}
					if !strings.Contains(r.URL.Path, "/leases/metapi-account-42/actions/") {
						t.Error("account changed on recovery")
					}
					var payload map[string]string
					if json.NewDecoder(r.Body).Decode(&payload) != nil || payload["target_host"] != "service.test:80" {
						t.Error("invalid target")
					}
					status := "available"
					if strings.HasSuffix(r.URL.Path, "report-failure") {
						reports++
						if payload["expected_node_hash"] != lease.NodeHash || payload["expected_created_at_ns"] != lease.CreatedAt {
							t.Error("missing CAS snapshot")
						}
						status = tc.recovery
					} else {
						acquires++
					}
					_ = json.NewEncoder(w).Encode(recoveryResponse{Version: 1, Status: status, Lease: &lease})
					return
				}
				calls++
				if !strings.HasPrefix(r.Header.Get(resinAccountHeader), "metapi-account-42~r1~") {
					t.Error("attempt not bound to the acquired account lease")
				}
				if calls == 1 {
					if tc.code != "http_503" {
						w.Header().Set(resinErrorHeader, tc.code)
					}
					http.Error(w, "upstream failure", 503)
					return
				}
				fmt.Fprint(w, "ok")
			}))
			g.cfg.StableAccounts = true
			response := forwardRequest(t, g.Handler(), "GET", "http://service.test/", "AppsGlobal.metapi-account-42-slot-2", "safe", nil)
			if calls != tc.wantCalls || reports != tc.wantReports || acquires != calls {
				t.Fatalf("calls=%d reports=%d acquires=%d", calls, reports, acquires)
			}
			if tc.wantCalls == 2 && response.Code != 200 {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if tc.code == "UPSTREAM_TLS_CERTIFICATE_ERROR" {
				if !strings.Contains(response.Body.String(), tc.code) {
					t.Fatal("certificate reason lost")
				}
				second := forwardRequest(t, g.Handler(), "GET", "http://service.test/other", "AppsGlobal.metapi-account-77", "safe", nil)
				if calls != 1 || second.Header().Get("Retry-After") != "300" {
					t.Fatal("site cooldown did not prevent more probes")
				}
			}
		})
	}
}

func TestStableIdentityAcrossTargets(t *testing.T) {
	g, _ := newTestGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, key := range []string{"AppsGlobal.metapi-account-42", "AppsGlobal.metapi-account-42-slot-1", "AppsGlobal.metapi-account-42-slot-2"} {
		if got := g.stableIdentity(key); got != "metapi-account-42" {
			t.Fatalf("%q became %q", key, got)
		}
	}
	if g.stableIdentity("sender-account-1") != g.stableIdentity("sender-account-1") || g.stableIdentity("sender-account-1") == g.stableIdentity("sender-account-2") {
		t.Fatal("opaque identity unstable or colliding")
	}
}
