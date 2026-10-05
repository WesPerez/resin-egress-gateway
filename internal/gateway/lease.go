package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var legacyMetapiSlot = regexp.MustCompile(`^(metapi-account-[0-9]+)-slot-[0-2]$`)

var accountName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Business keys already carrying our platform retain the original account.
// Arbitrary callers get a stable opaque key, independent of request/host/retry.
func (g *Gateway) stableIdentity(key string) string {
	if account, ok := strings.CutPrefix(key, g.cfg.ResinPlatform+"."); ok && accountName.MatchString(account) {
		return legacyMetapiSlot.ReplaceAllString(account, "$1")
	}
	return "egw-" + routeHash(key, &url.URL{})[:20]
}

type recoveryLease struct {
	Account      string `json:"account"`
	NodeHash     string `json:"node_hash"`
	CreatedAt    string `json:"created_at_ns"`
	EgressIP     string `json:"egress_ip"`
	GuardVersion int    `json:"lease_guard_version"`
}

type recoveryResponse struct {
	Version int            `json:"recovery_version"`
	Status  string         `json:"status"`
	Lease   *recoveryLease `json:"lease"`
}

func recoveryTarget(target *url.URL) string {
	if target.Port() != "" {
		return target.Host
	}
	port := "443"
	if target.Scheme == "http" {
		port = "80"
	}
	return net.JoinHostPort(target.Hostname(), port)
}

func (g *Gateway) leaseAction(ctx context.Context, account, action string, payload any) (*recoveryResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(g.cfg.ResinBaseURL.String(), "/") + "/proxy-api/v1/" + url.PathEscape(g.cfg.ResinPlatform) + "/leases/" + url.PathEscape(account) + "/actions/" + action
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid recovery endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+g.cfg.ResinProxyToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, errors.New("recovery service unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("recovery service rejected request")
	}
	var value recoveryResponse
	if json.NewDecoder(io.LimitReader(resp.Body, 16384)).Decode(&value) != nil || value.Version != 1 {
		return nil, errors.New("invalid recovery capability")
	}
	if value.Lease != nil && (value.Lease.Account != account || len(value.Lease.NodeHash) != 32 || value.Lease.CreatedAt == "") {
		return nil, errors.New("recovery identity mismatch")
	}
	return &value, nil
}

func (g *Gateway) acquireLease(ctx context.Context, account string, target *url.URL) (*recoveryLease, error) {
	r, err := g.leaseAction(ctx, account, "acquire", map[string]string{"target_host": recoveryTarget(target)})
	if err != nil {
		return nil, err
	}
	if r.Status != "available" || r.Lease == nil {
		return nil, errors.New("account recovery unavailable or cooling down")
	}
	created, parseErr := strconv.ParseInt(r.Lease.CreatedAt, 10, 64)
	ip, ipErr := netip.ParseAddr(r.Lease.EgressIP)
	if parseErr != nil || created <= 0 || ipErr != nil || !ip.IsGlobalUnicast() || r.Lease.GuardVersion != 1 {
		return nil, errors.New("invalid guarded lease capability")
	}
	return r.Lease, nil
}

func (g *Gateway) recoverLease(ctx context.Context, account string, target *url.URL, observed *recoveryLease, reason string) error {
	// HTTP application errors (including quota/429 and site 5xx) do not prove a
	// broken proxy. Never rotate an account merely to evade an upstream limit.
	if strings.HasPrefix(reason, "http_") {
		return errors.New("upstream application failure")
	}
	r, err := g.leaseAction(ctx, account, "report-failure", map[string]string{
		"target_host": recoveryTarget(target), "expected_node_hash": observed.NodeHash,
		"expected_created_at_ns": observed.CreatedAt, "reason": "transport_error",
	})
	if err != nil {
		return err
	}
	if r.Status != "rotated" && r.Status != "stale_lease" {
		return errors.New("account recovery limited or unavailable")
	}
	return nil
}

func (g *Gateway) sitePaused(target *url.URL) bool {
	g.siteMu.Lock()
	defer g.siteMu.Unlock()
	now := time.Now()
	for key, until := range g.sitePause {
		if !until.After(now) {
			delete(g.sitePause, key)
		}
	}
	return g.sitePause[target.Scheme+"://"+strings.ToLower(target.Host)].After(now)
}

func (g *Gateway) pauseSite(target *url.URL) {
	g.siteMu.Lock()
	defer g.siteMu.Unlock()
	key := target.Scheme + "://" + strings.ToLower(target.Host)
	if len(g.sitePause) < 1024 {
		g.sitePause[key] = time.Now().Add(5 * time.Minute)
	}
}

func (lease *recoveryLease) guardedIdentity() string {
	return fmt.Sprintf("%s~r1~%s~%s~%d~%s", lease.Account, lease.NodeHash, lease.CreatedAt,
		time.Now().Add(time.Minute).UnixMilli(), base64.RawURLEncoding.EncodeToString([]byte(lease.EgressIP)))
}

func shouldRecover(reason string) bool {
	switch reason {
	case "resin_lease_guard_failed", "resin_no_available_nodes", "resin_internal_error":
		return false
	}
	return !strings.HasPrefix(reason, "http_")
}
