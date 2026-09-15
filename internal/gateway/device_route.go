package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// Device clients send target TLS through Resin CONNECT. This control endpoint
// shares the forwarder's route identity without handling an upstream request.
func (g *Gateway) handleDeviceRoute(w http.ResponseWriter, r *http.Request) {
	if !g.authorized(r) {
		g.metrics.authRejected.Add(1)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	target, err := g.parseTarget(r.Context(), r.Header.Get(targetHeader))
	key := strings.TrimSpace(r.Header.Get(keyHeader))
	if err != nil || key == "" || len(key) > 1024 {
		http.Error(w, "invalid route", http.StatusBadRequest)
		return
	}
	routeID := routeHash(key, target)
	status := http.StatusOK
	var generation uint64
	if r.Method == http.MethodPost {
		var input struct {
			Generation *uint64 `json:"generation"`
			Kind       string  `json:"kind"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
			(input.Kind != "transport" && input.Kind != "challenge") || input.Generation == nil || *input.Generation > 9007199254740990 {
			http.Error(w, "invalid feedback", http.StatusBadRequest)
			return
		}
		var changed bool
		generation, changed, err = g.state.CompareAndAdvance(routeID, *input.Generation)
		if !changed {
			status = http.StatusConflict
		}
	} else {
		generation, err = g.state.Current(routeID)
	}
	if err != nil {
		http.Error(w, "state unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Version       int    `json:"version"`
		RouteID       string `json:"routeId"`
		Generation    uint64 `json:"generation"`
		ProxyUsername string `json:"proxyUsername"`
	}{2, routeID, generation, g.cfg.ResinPlatform + "." + resinIdentity(routeID, generation)})
}
