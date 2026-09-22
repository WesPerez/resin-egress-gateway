package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// handleRouteGeneration exposes only the metadata needed by a trusted caller
// to use its existing CONNECT identity. It never probes, creates or rotates a
// route. Authentication has the same trust boundary as /v1/forward.
func (g *Gateway) handleRouteGeneration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !g.authorized(r) {
		g.metrics.authRejected.Add(1)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var input struct {
		Key    string `json:"key"`
		Origin string `json:"origin"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid route request", http.StatusBadRequest)
		return
	}
	if decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid route request", http.StatusBadRequest)
		return
	}
	origin, err := url.Parse(input.Origin)
	if err != nil || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" ||
		(origin.Path != "" && origin.Path != "/") || origin.Opaque != "" ||
		(origin.Scheme != "https" && !(g.cfg.AllowHTTP && origin.Scheme == "http")) ||
		input.Key == "" || input.Key != strings.TrimSpace(input.Key) || len(input.Key) > 1024 || strings.ContainsAny(input.Key, "\r\n\x00") {
		http.Error(w, "invalid route request", http.StatusBadRequest)
		return
	}
	generation, ok := g.state.Peek(routeHash(input.Key, origin))
	if !ok {
		http.Error(w, "route not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Generation uint64 `json:"generation"`
	}{generation})
}
