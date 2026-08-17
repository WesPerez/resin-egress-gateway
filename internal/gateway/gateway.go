package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	targetHeader             = "X-Egress-Target"
	keyHeader                = "X-Egress-Key"
	retryModeHeader          = "X-Egress-Retry-Mode"
	headerTimeoutHeader      = "X-Egress-Response-Header-Timeout-Ms"
	firstByteTimeoutHeader   = "X-Egress-First-Byte-Timeout-Ms"
	attemptsResponseHeader   = "X-Egress-Attempts"
	generationResponseHeader = "X-Egress-Generation"
	resinAccountHeader       = "X-Resin-Account"
	resinErrorHeader         = "X-Resin-Error"
	maxTargetHeaderBytes     = 16 << 10
	defaultMaxInFlight       = 4
	defaultMaxQueueWait      = 30 * time.Second
	defaultBufferTimeout     = 2 * time.Minute
	targetLookupTimeout      = 2 * time.Second
)

type retryMode uint8

const (
	retryNever retryMode = iota
	retryTransport
	retrySafe
)

type Metrics struct {
	requests       atomic.Uint64
	successes      atomic.Uint64
	failures       atomic.Uint64
	retries        atomic.Uint64
	authRejected   atomic.Uint64
	bodyRejected   atomic.Uint64
	targetRejected atomic.Uint64
	queueRejected  atomic.Uint64
}

type Gateway struct {
	cfg      Config
	state    *StateStore
	client   *http.Client
	logger   *slog.Logger
	inFlight chan struct{}
	lookupIP func(context.Context, string) ([]netip.Addr, error)
	metrics  Metrics
}

func New(cfg Config, state *StateStore, logger *slog.Logger) *Gateway {
	if logger == nil {
		logger = slog.Default()
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
	}
	if cfg.MaxInFlight <= 0 {
		cfg.MaxInFlight = defaultMaxInFlight
	}
	if cfg.MaxQueueWait <= 0 {
		cfg.MaxQueueWait = defaultMaxQueueWait
	}
	if cfg.ResponseBufferTimeout <= 0 {
		cfg.ResponseBufferTimeout = defaultBufferTimeout
	}
	return &Gateway{
		cfg:      cfg,
		state:    state,
		client:   &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		logger:   logger,
		inFlight: make(chan struct{}, cfg.MaxInFlight),
		lookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
	}
}

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", g.handleHealth)
	mux.HandleFunc("GET /metrics", g.handleMetrics)
	mux.HandleFunc("/v1/forward", g.handleForward)
	return mux
}

func (g *Gateway) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

func (g *Gateway) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !g.authorized(r) {
		g.metrics.authRejected.Add(1)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	writeMetric := func(name string, value uint64) {
		_, _ = fmt.Fprintf(w, "resin_egress_gateway_%s %d\n", name, value)
	}
	writeMetric("requests_total", g.metrics.requests.Load())
	writeMetric("successes_total", g.metrics.successes.Load())
	writeMetric("failures_total", g.metrics.failures.Load())
	writeMetric("retries_total", g.metrics.retries.Load())
	writeMetric("auth_rejected_total", g.metrics.authRejected.Load())
	writeMetric("body_rejected_total", g.metrics.bodyRejected.Load())
	writeMetric("target_rejected_total", g.metrics.targetRejected.Load())
	writeMetric("queue_rejected_total", g.metrics.queueRejected.Load())
}

func (g *Gateway) handleForward(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if !g.authorized(r) {
		g.metrics.authRejected.Add(1)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	g.metrics.requests.Add(1)
	if !g.acquire(r.Context()) {
		g.metrics.queueRejected.Add(1)
		if r.Context().Err() == nil {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "gateway busy", http.StatusServiceUnavailable)
		}
		return
	}
	defer g.release()
	if r.Method == http.MethodConnect || strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		g.metrics.targetRejected.Add(1)
		http.Error(w, "CONNECT and protocol upgrades are not supported", http.StatusNotImplemented)
		return
	}
	target, err := g.parseTarget(r.Context(), r.Header.Get(targetHeader))
	if err != nil {
		g.metrics.targetRejected.Add(1)
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}
	routeKey := strings.TrimSpace(r.Header.Get(keyHeader))
	if routeKey == "" || len(routeKey) > 1024 {
		g.metrics.targetRejected.Add(1)
		http.Error(w, "missing or invalid egress key", http.StatusBadRequest)
		return
	}
	body, err := readBoundedBody(r.Body, g.cfg.MaxRequestBodyBytes)
	if err != nil {
		g.metrics.bodyRejected.Add(1)
		if errors.Is(err, errBodyTooLarge) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
		}
		return
	}

	mode, err := parseRetryMode(r)
	if err != nil {
		http.Error(w, "invalid retry mode", http.StatusBadRequest)
		return
	}
	headerTimeout, err := boundedTimeoutHeader(r.Header.Get(headerTimeoutHeader), g.cfg.ResponseHeaderTimeout)
	if err != nil {
		http.Error(w, "invalid response header timeout", http.StatusBadRequest)
		return
	}
	firstByteTimeout, err := boundedTimeoutHeader(r.Header.Get(firstByteTimeoutHeader), g.cfg.FirstByteTimeout)
	if err != nil {
		http.Error(w, "invalid first byte timeout", http.StatusBadRequest)
		return
	}

	routeID := routeHash(routeKey, target)
	generation, err := g.state.Current(routeID)
	if err != nil {
		g.writeGatewayError(w, http.StatusInternalServerError, "state unavailable", 0, generation)
		return
	}
	maxAttempts := g.cfg.MaxAttempts
	if mode == retryNever {
		maxAttempts = 1
	}

	var finalErr error
	var finalStatus int
	attemptsUsed := 0
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		attemptsUsed = attempt
		identity := resinIdentity(routeID, generation)
		result := g.performAttempt(r.Context(), r.Method, r.Header, body, target, identity, mode, headerTimeout, firstByteTimeout)
		if result.response != nil && !result.retry {
			err = g.deliverResponse(w, result.response, result.firstChunk, result.bufferedBody, result.streaming, attempt, generation)
			result.cancel()
			if err != nil {
				g.metrics.failures.Add(1)
				g.logger.Warn("downstream delivery failed", "route", shortRoute(routeID), "host", target.Hostname(), "attempt", attempt, "error", errorClass(err))
				return
			}
			if touchErr := g.state.Touch(routeID, generation); touchErr != nil {
				g.logger.Warn("state touch failed", "route", shortRoute(routeID), "error", errorClass(touchErr))
			}
			g.metrics.successes.Add(1)
			g.logger.Info("request completed", "route", shortRoute(routeID), "host", target.Hostname(), "method", r.Method, "status", result.response.StatusCode, "attempts", attempt, "generation", generation, "elapsed_ms", time.Since(started).Milliseconds())
			return
		}

		if result.response != nil {
			finalStatus = result.response.StatusCode
		}
		finalErr = result.err
		if result.response != nil {
			drainAndClose(result.response.Body)
		}
		result.cancel()
		if !result.retry || mode == retryNever {
			break
		}
		if attempt >= maxAttempts {
			if next, advanceErr := g.state.Advance(routeID, generation); advanceErr == nil {
				generation = next
			}
			break
		}
		next, advanceErr := g.state.Advance(routeID, generation)
		if advanceErr != nil {
			finalErr = advanceErr
			break
		}
		generation = next
		g.metrics.retries.Add(1)
		g.logger.Warn("request retrying", "route", shortRoute(routeID), "host", target.Hostname(), "method", r.Method, "attempt", attempt, "next_generation", generation, "reason", result.reason)
		if !waitForRetry(r.Context(), result.retryAfter, attempt) {
			finalErr = r.Context().Err()
			break
		}
	}

	g.metrics.failures.Add(1)
	status := http.StatusBadGateway
	if errors.Is(finalErr, context.DeadlineExceeded) {
		status = http.StatusGatewayTimeout
	} else if finalStatus != 0 {
		status = finalStatus
	}
	g.writeGatewayError(w, status, "upstream attempts exhausted", attemptsUsed, generation)
	g.logger.Error("request failed", "route", shortRoute(routeID), "host", target.Hostname(), "method", r.Method, "status", status, "generation", generation, "elapsed_ms", time.Since(started).Milliseconds(), "error", errorClass(finalErr))
}

type attemptResult struct {
	response     *http.Response
	firstChunk   []byte
	bufferedBody []byte
	streaming    bool
	retry        bool
	reason       string
	retryAfter   time.Duration
	err          error
	cancel       context.CancelFunc
}

func (g *Gateway) performAttempt(parent context.Context, method string, inboundHeaders http.Header, body []byte, target *url.URL, identity string, mode retryMode, headerTimeout, firstByteTimeout time.Duration) attemptResult {
	ctx, cancel := context.WithCancel(parent)
	result := attemptResult{cancel: cancel}
	upstreamURL := g.buildResinURL(target)
	req, err := http.NewRequestWithContext(ctx, method, upstreamURL, bytes.NewReader(body))
	if err != nil {
		result.err = err
		return result
	}
	copyRequestHeaders(req.Header, inboundHeaders)
	req.Header.Set(resinAccountHeader, identity)
	resp, err := g.doWithHeaderTimeout(ctx, cancel, req, headerTimeout)
	if err != nil {
		result.err = err
		result.retry = parent.Err() == nil && isRetryableTransportError(err)
		result.reason = "transport"
		return result
	}
	result.response = resp

	if resinCode := strings.ToUpper(strings.TrimSpace(resp.Header.Get(resinErrorHeader))); resinCode != "" {
		result.retry = mode != retryNever && isRetryableResinError(resinCode)
		result.reason = "resin_" + strings.ToLower(resinCode)
		return result
	}
	if mode == retrySafe && isRetryableStatus(resp.StatusCode) {
		result.retry = true
		result.reason = "http_" + strconv.Itoa(resp.StatusCode)
		result.retryAfter = retryAfter(resp.Header.Get("Retry-After"), g.cfg.MaxRetryAfter)
		return result
	}
	if responseHasNoBody(method, resp) {
		return result
	}

	firstChunk, err := readFirstChunk(ctx, cancel, resp.Body, firstByteTimeout)
	if err != nil {
		result.err = err
		result.retry = parent.Err() == nil && isRetryableTransportError(err)
		result.reason = "first_byte"
		return result
	}
	result.firstChunk = firstChunk
	result.streaming = isStreamingResponse(resp) || resp.ContentLength > g.cfg.MaxResponseBodyBytes
	if result.streaming || len(firstChunk) == 0 {
		return result
	}

	remaining := g.cfg.MaxResponseBodyBytes - int64(len(firstChunk))
	if remaining < 0 {
		result.streaming = true
		return result
	}
	rest, readErr := readBufferedResponse(ctx, cancel, resp.Body, remaining+1, g.cfg.ResponseBufferTimeout)
	if readErr != nil {
		result.err = readErr
		result.retry = parent.Err() == nil && isRetryableTransportError(readErr)
		result.reason = "response_body"
		return result
	}
	result.bufferedBody = rest
	if int64(len(rest)) > remaining {
		result.streaming = true
	}
	return result
}

type responseResult struct {
	response *http.Response
	err      error
}

func (g *Gateway) doWithHeaderTimeout(ctx context.Context, cancel context.CancelFunc, req *http.Request, timeout time.Duration) (*http.Response, error) {
	results := make(chan responseResult, 1)
	go func() {
		resp, err := g.client.Do(req)
		results <- responseResult{response: resp, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-results:
		return result.response, result.err
	case <-ctx.Done():
		cancel()
		go closeLateResponse(results)
		return nil, ctx.Err()
	case <-timer.C:
		cancel()
		go closeLateResponse(results)
		return nil, context.DeadlineExceeded
	}
}

func closeLateResponse(results <-chan responseResult) {
	result := <-results
	if result.response != nil {
		result.response.Body.Close()
	}
}

func (g *Gateway) deliverResponse(w http.ResponseWriter, resp *http.Response, firstChunk, bufferedBody []byte, streaming bool, attempts int, generation uint64) error {
	copyResponseHeaders(w.Header(), resp.Header)
	w.Header().Set(attemptsResponseHeader, strconv.Itoa(attempts))
	w.Header().Set(generationResponseHeader, strconv.FormatUint(generation, 10))
	w.WriteHeader(resp.StatusCode)
	if len(firstChunk) > 0 {
		if _, err := w.Write(firstChunk); err != nil {
			resp.Body.Close()
			return err
		}
	}
	if len(bufferedBody) > 0 {
		if _, err := w.Write(bufferedBody); err != nil {
			resp.Body.Close()
			return err
		}
	}
	if streaming {
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		_, err := io.Copy(w, resp.Body)
		resp.Body.Close()
		return err
	}
	return resp.Body.Close()
}

func (g *Gateway) writeGatewayError(w http.ResponseWriter, status int, message string, attempts int, generation uint64) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if attempts > 0 {
		w.Header().Set(attemptsResponseHeader, strconv.Itoa(attempts))
	}
	w.Header().Set(generationResponseHeader, strconv.FormatUint(generation, 10))
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (g *Gateway) authorized(r *http.Request) bool {
	value := strings.TrimSpace(r.Header.Get("Proxy-Authorization"))
	if !strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return false
	}
	provided := strings.TrimSpace(value[len("Bearer "):])
	return len(provided) == len(g.cfg.AuthToken) && subtle.ConstantTimeCompare([]byte(provided), []byte(g.cfg.AuthToken)) == 1
}

func (g *Gateway) parseTarget(parent context.Context, encoded string) (*url.URL, error) {
	if encoded == "" || len(encoded) > maxTargetHeaderBytes*2 {
		return nil, errors.New("missing target")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > maxTargetHeaderBytes {
		return nil, errors.New("invalid target encoding")
	}
	target, err := url.Parse(string(decoded))
	if err != nil || !target.IsAbs() || target.Host == "" || target.User != nil || target.Fragment != "" {
		return nil, errors.New("invalid target URL")
	}
	if target.Scheme != "https" && !(g.cfg.AllowHTTP && target.Scheme == "http") {
		return nil, errors.New("target scheme is not allowed")
	}
	if !g.cfg.AllowPrivateTargets {
		if err := g.validateTargetHost(parent, target.Hostname()); err != nil {
			return nil, err
		}
	}
	return target, nil
}

func (g *Gateway) validateTargetHost(parent context.Context, host string) error {
	if forbiddenTargetHost(host) {
		return errors.New("target host is not allowed")
	}
	if _, err := netip.ParseAddr(strings.TrimSuffix(host, ".")); err == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, targetLookupTimeout)
	defer cancel()
	addresses, err := g.lookupIP(ctx, host)
	if err != nil || len(addresses) == 0 {
		return errors.New("target host could not be resolved")
	}
	for _, address := range addresses {
		if forbiddenTargetAddress(address) {
			return errors.New("target host resolves to a disallowed address")
		}
	}
	return nil
}

func (g *Gateway) acquire(ctx context.Context) bool {
	timer := time.NewTimer(g.cfg.MaxQueueWait)
	defer timer.Stop()
	select {
	case g.inFlight <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	case <-timer.C:
		return false
	}
}

func (g *Gateway) release() {
	<-g.inFlight
}

func (g *Gateway) buildResinURL(target *url.URL) string {
	base := strings.TrimSuffix(g.cfg.ResinBaseURL.String(), "/")
	path := target.EscapedPath()
	if path == "" {
		path = "/"
	}
	result := base + "/" + url.PathEscape(g.cfg.ResinProxyToken) + "/" + url.PathEscape(g.cfg.ResinPlatform) + "/" + target.Scheme + "/" + url.PathEscape(target.Host) + path
	if target.RawQuery != "" {
		result += "?" + target.RawQuery
	}
	return result
}

func routeHash(key string, target *url.URL) string {
	sum := sha256.Sum256([]byte(key + "\n" + strings.ToLower(target.Scheme) + "://" + strings.ToLower(target.Host)))
	return hex.EncodeToString(sum[:])
}

func resinIdentity(route string, generation uint64) string {
	return "egw-" + route[:20] + "-g" + strconv.FormatUint(generation, 10)
}

func shortRoute(route string) string {
	if len(route) <= 12 {
		return route
	}
	return route[:12]
}

var errBodyTooLarge = errors.New("body exceeds configured limit")

func readBoundedBody(body io.ReadCloser, limit int64) ([]byte, error) {
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errBodyTooLarge
	}
	return data, nil
}

func parseRetryMode(r *http.Request) (retryMode, error) {
	return parseRetryModeFromValue(r.Header.Get(retryModeHeader), r.Method, r.Header.Get("Idempotency-Key") != "")
}

func parseRetryModeFromValue(value, method string, hasIdempotencyKey bool) (retryMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "never":
		return retryNever, nil
	case "transport":
		return retryTransport, nil
	case "safe":
		return retrySafe, nil
	case "", "auto":
		if hasIdempotencyKey || method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions || method == http.MethodPut || method == http.MethodDelete {
			return retrySafe, nil
		}
		return retryNever, nil
	default:
		return retryNever, errors.New("unknown retry mode")
	}
}

func boundedTimeoutHeader(value string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	milliseconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0, err
	}
	duration := time.Duration(milliseconds) * time.Millisecond
	if duration < time.Second || duration > 10*time.Minute {
		return 0, errors.New("timeout outside allowed range")
	}
	return duration, nil
}

func isRetryableStatus(status int) bool {
	switch status {
	case 408, 425, 429, 500, 502, 503, 504:
		return true
	default:
		return false
	}
}

func isRetryableResinError(code string) bool {
	switch code {
	case "NO_AVAILABLE_NODES", "UPSTREAM_CONNECT_FAILED", "UPSTREAM_TIMEOUT", "UPSTREAM_REQUEST_FAILED", "INTERNAL_ERROR":
		return true
	default:
		return false
	}
}

func isRetryableTransportError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) || errors.Is(err, io.ErrUnexpectedEOF)
}

func responseHasNoBody(method string, resp *http.Response) bool {
	return method == http.MethodHead || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified || resp.ContentLength == 0
}

func isStreamingResponse(resp *http.Response) bool {
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	contentDisposition := strings.ToLower(resp.Header.Get("Content-Disposition"))
	return resp.StatusCode == http.StatusSwitchingProtocols ||
		strings.Contains(contentType, "text/event-stream") ||
		strings.Contains(contentType, "application/x-ndjson") ||
		strings.Contains(contentType, "application/json-seq") ||
		strings.Contains(contentType, "application/octet-stream") ||
		strings.HasPrefix(contentType, "image/") ||
		strings.HasPrefix(contentType, "audio/") ||
		strings.HasPrefix(contentType, "video/") ||
		strings.Contains(contentDisposition, "attachment")
}

func readFirstChunk(ctx context.Context, cancel context.CancelFunc, body io.ReadCloser, timeout time.Duration) ([]byte, error) {
	type readResult struct {
		data []byte
		err  error
	}
	results := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := body.Read(buf)
			if n > 0 || err != nil {
				results <- readResult{data: append([]byte(nil), buf[:n]...), err: err}
				return
			}
		}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-results:
		if result.err == io.EOF && len(result.data) > 0 {
			result.err = nil
		}
		return result.data, result.err
	case <-ctx.Done():
		cancel()
		body.Close()
		return nil, ctx.Err()
	case <-timer.C:
		cancel()
		body.Close()
		return nil, context.DeadlineExceeded
	}
}

func readBufferedResponse(ctx context.Context, cancel context.CancelFunc, body io.ReadCloser, limit int64, timeout time.Duration) ([]byte, error) {
	type readResult struct {
		data []byte
		err  error
	}
	results := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(body, limit))
		results <- readResult{data: data, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-results:
		return result.data, result.err
	case <-ctx.Done():
		cancel()
		body.Close()
		return nil, ctx.Err()
	case <-timer.C:
		cancel()
		body.Close()
		return nil, context.DeadlineExceeded
	}
}

func retryAfter(value string, maximum time.Duration) time.Duration {
	if maximum <= 0 || strings.TrimSpace(value) == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
		delay := time.Duration(seconds) * time.Second
		if delay > maximum {
			return maximum
		}
		if delay > 0 {
			return delay
		}
		return 0
	}
	if when, err := http.ParseTime(value); err == nil {
		delay := time.Until(when)
		if delay < 0 {
			return 0
		}
		if delay > maximum {
			return maximum
		}
		return delay
	}
	return 0
}

func waitForRetry(ctx context.Context, requested time.Duration, attempt int) bool {
	delay := requested
	if delay <= 0 {
		delay = time.Duration(attempt*100) * time.Millisecond
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func forbiddenTargetHost(host string) bool {
	normalized := strings.ToLower(strings.TrimSuffix(host, "."))
	if normalized == "localhost" || normalized == "proxy.internal" || normalized == "host.docker.internal" ||
		strings.HasSuffix(normalized, ".localhost") || strings.HasSuffix(normalized, ".local") || strings.HasSuffix(normalized, ".internal") {
		return true
	}
	address, err := netip.ParseAddr(normalized)
	if err != nil {
		return false
	}
	return forbiddenTargetAddress(address)
}

func forbiddenTargetAddress(address netip.Addr) bool {
	address = address.Unmap()
	if address.IsLoopback() || address.IsPrivate() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return true
	}
	for _, prefix := range forbiddenPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

var forbiddenPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Proxy-Connection":    {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

func copyRequestHeaders(dst, src http.Header) {
	connectionTokens := headerTokens(src.Get("Connection"))
	for key, values := range src {
		canonical := http.CanonicalHeaderKey(key)
		lower := strings.ToLower(canonical)
		if _, skip := hopByHopHeaders[canonical]; skip || connectionTokens[canonical] || strings.HasPrefix(lower, "x-egress-") || strings.HasPrefix(lower, "x-resin-") {
			continue
		}
		for _, value := range values {
			dst.Add(canonical, value)
		}
	}
}

func copyResponseHeaders(dst, src http.Header) {
	connectionTokens := headerTokens(src.Get("Connection"))
	for key, values := range src {
		canonical := http.CanonicalHeaderKey(key)
		lower := strings.ToLower(canonical)
		if _, skip := hopByHopHeaders[canonical]; skip || connectionTokens[canonical] || strings.HasPrefix(lower, "x-egress-") || strings.HasPrefix(lower, "x-resin-") {
			continue
		}
		for _, value := range values {
			dst.Add(canonical, value)
		}
	}
}

func headerTokens(value string) map[string]bool {
	result := make(map[string]bool)
	for _, item := range strings.Split(value, ",") {
		if token := http.CanonicalHeaderKey(strings.TrimSpace(item)); token != "" {
			result[token] = true
		}
	}
	return result
}

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 64<<10))
	_ = body.Close()
}

func errorClass(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return "network"
	}
	return "other"
}
