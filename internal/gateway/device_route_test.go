package gateway

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func deviceRouteRequest(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Proxy-Authorization", "Bearer gateway-secret")
	req.Header.Set(targetHeader, base64.RawURLEncoding.EncodeToString([]byte("https://example.test/api")))
	req.Header.Set(keyHeader, "AppsGlobal.metapi-account-167")
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	return result
}

func TestDeviceRouteSharesForwardIdentityWithoutSendingRequests(t *testing.T) {
	var identity string
	var calls atomic.Int32
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		identity = r.Header.Get(resinAccountHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	handler := gateway.Handler()
	resolved := deviceRouteRequest(handler, "GET", "/v1/route/device-v2", "")
	if resolved.Code != 200 || calls.Load() != 0 {
		t.Fatalf("resolve = %d, upstream calls = %d", resolved.Code, calls.Load())
	}
	var route struct {
		ProxyUsername string `json:"proxyUsername"`
		Generation    int    `json:"generation"`
	}
	if err := json.Unmarshal(resolved.Body.Bytes(), &route); err != nil {
		t.Fatal(err)
	}
	forward := forwardRequest(t, handler, "GET", "https://example.test/other?different=path", "AppsGlobal.metapi-account-167", "never", nil)
	if forward.Code != 204 || route.ProxyUsername != "AppsGlobal."+identity || route.Generation != 0 {
		t.Fatalf("forward = %d, route = %+v, identity = %q", forward.Code, route, identity)
	}
	if strings.Contains(resolved.Body.String(), "secret") || resolved.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("invalid route disclosure")
	}
}

func TestDeviceRouteFeedbackAdvancesOnceAndNeverReplays(t *testing.T) {
	gateway, _ := newTestGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("control requests must not call Resin")
	}))
	handler := gateway.Handler()
	deviceRouteRequest(handler, "GET", "/v1/route/device-v2", "")
	var changed atomic.Int32
	var conflicts atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response := deviceRouteRequest(handler, "POST", "/v1/route/device-v2/feedback", `{"generation":0,"kind":"transport"}`)
			switch response.Code {
			case 200:
				changed.Add(1)
			case 409:
				conflicts.Add(1)
			default:
				t.Errorf("feedback = %d", response.Code)
			}
		}()
	}
	wg.Wait()
	if changed.Load() != 1 || conflicts.Load() != 9 {
		t.Fatalf("changed = %d, conflicts = %d", changed.Load(), conflicts.Load())
	}
	response := deviceRouteRequest(handler, "GET", "/v1/route/device-v2", "")
	if !strings.Contains(response.Body.String(), `"generation":1`) {
		t.Fatalf("generation advanced more than once: %s", response.Body.String())
	}
}

func TestDeviceRouteValidationAndFailedSave(t *testing.T) {
	gateway, _ := newTestGateway(t, http.NotFoundHandler())
	handler := gateway.Handler()
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest("GET", "/v1/route/device-v2", nil))
	if unauthorized.Code != 401 {
		t.Fatal(unauthorized.Code)
	}
	for _, body := range []string{`{}`, `{"kind":"transport"}`, `{"generation":null,"kind":"transport"}`,
		`{"generation":0,"kind":"wrong"}`, `{"generation":0,"kind":"transport","unknown":1}`,
		`{"generation":0,"kind":"transport"}{}`, strings.Repeat("x", 1025)} {
		response := deviceRouteRequest(handler, "POST", "/v1/route/device-v2/feedback", body)
		if response.Code != 400 {
			t.Errorf("validation status = %d for %q", response.Code, body)
		}
	}
	if deviceRouteRequest(handler, "POST", "/v1/route/device-v2", "").Code != 405 {
		t.Fatal("incorrect method accepted")
	}
	deviceRouteRequest(handler, "GET", "/v1/route/device-v2", "")
	original := gateway.state.path
	gateway.state.path = t.TempDir()
	response := deviceRouteRequest(handler, "POST", "/v1/route/device-v2/feedback", `{"generation":0,"kind":"challenge"}`)
	if response.Code != 500 {
		t.Fatal(response.Code)
	}
	gateway.state.path = original
	response = deviceRouteRequest(handler, "GET", "/v1/route/device-v2", "")
	if !strings.Contains(response.Body.String(), `"generation":0`) {
		t.Fatal("failed save changed the live generation")
	}
}
