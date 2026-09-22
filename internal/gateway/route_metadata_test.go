package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRouteMetadataReadOnly(t *testing.T) {
	g, _ := newTestGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("metadata must not call Resin") }))
	u, _ := url.Parse("https://example.com/checkin")
	route := routeHash("app-account-42", u)
	if err := g.state.Touch(route, 3); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(g.state.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body, auth string
		status           int
	}{
		{"ok", `{"key":"app-account-42","origin":"https://example.com"}`, "gateway-secret", 200},
		{"unauthorized", `{}`, "wrong", 401},
		{"missing", `{"key":"missing","origin":"https://example.com"}`, "gateway-secret", 404},
		{"path", `{"key":"app-account-42","origin":"https://example.com/path"}`, "gateway-secret", 400},
		{"query", `{"key":"app-account-42","origin":"https://example.com?secret"}`, "gateway-secret", 400},
		{"userinfo", `{"key":"app-account-42","origin":"https://secret@example.com"}`, "gateway-secret", 400},
		{"unknown", `{"key":"app-account-42","origin":"https://example.com","extra":1}`, "gateway-secret", 400},
		{"trailing", `{"key":"app-account-42","origin":"https://example.com"}{}`, "gateway-secret", 400},
		{"oversize", `{"key":"` + strings.Repeat("x", 5000) + `"}`, "gateway-secret", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/routes/generation", strings.NewReader(tc.body))
			r.Header.Set("Proxy-Authorization", "Bearer "+tc.auth)
			w := httptest.NewRecorder()
			g.Handler().ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if tc.status == 200 && w.Body.String() != "{\"generation\":3}\n" {
				t.Fatalf("unexpected metadata: %s", w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("metadata must not be cached")
			}
		})
	}
	after, err := os.ReadFile(g.state.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("read changed persistent state")
	}
	if len(g.state.routes) != 1 {
		t.Fatal("read created a route")
	}
	g.state.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	if _, ok := g.state.Peek(route); ok {
		t.Fatal("expired route returned")
	}
	if len(g.state.routes) != 1 {
		t.Fatal("read pruned state")
	}
}
