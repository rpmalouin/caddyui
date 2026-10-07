// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// appHealthEntry is the cached result of a single HTTPS GET against a proxy
// host's public domain. Unlike the TCP/port health (which asks Caddy whether
// it can open a socket to the upstream), this probe goes all the way through
// — DNS → Caddy → upstream — so it catches "port open but app wedged" cases
// that the TCP probe can't see.
type appHealthEntry struct {
	Status    string    // "ok" / "degraded" / "down" / "unknown" / "disabled"
	Code      int       // HTTP status code, 0 if no response received
	Error     string    // short error detail
	LatencyMS int64     // wall-clock round trip
	CheckedAt time.Time // when the cache entry was written
}

// App-poller tunables. Kept conservative so a dashboard full of hosts doesn't
// hammer the public edge: 60s between cycles, 5s per probe, max 3 redirects,
// at most 8 probes in flight concurrently.
const (
	appHealthInterval    = 60 * time.Second
	appHealthProbeTO     = 5 * time.Second
	appHealthMaxRedirect = 3
	appHealthMaxParallel = 8
)

// StartAppHealthPoller launches a background goroutine that periodically
// probes every enabled proxy host's public URL and caches the result. The
// cached result is read by /api/upstream-health and rendered as the "App"
// dot next to the existing "Port" dot on the dashboard + proxy hosts pages.
//
// The poller shares cadence with (but runs independently of) the server
// health poller — a stuck HTTP probe shouldn't delay the Caddy admin pings.
func (s *Server) StartAppHealthPoller(ctx context.Context) {
	go func() {
		// Fire once right away so the UI is populated on first load after boot
		// without waiting a full interval.
		s.pollAllApps(ctx)
		ticker := time.NewTicker(appHealthInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.pollAllApps(ctx)
			}
		}
	}()
}

// pollAllApps iterates every proxy host across every server and probes each
// in a bounded worker pool. We don't scope to a single server here because
// the dashboard can show hosts from the active server but the user may
// switch servers — keeping all hosts warm means the "App" dot is instantly
// correct after a server switch.
func (s *Server) pollAllApps(ctx context.Context) {
	caddyServers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		log.Printf("app-health poller: list servers: %v", err)
		return
	}
	// Collect every proxy host across every server. We deliberately ignore
	// ownership here (isAdmin=true, viewer=0) because the poller is a
	// system-level background job, not user-facing.
	var allHosts []models.ProxyHost
	for _, cs := range caddyServers {
		hosts, err := models.ListProxyHosts(s.DB, cs.ID, 0, true, nil)
		if err != nil {
			log.Printf("app-health poller: list hosts (server %d): %v", cs.ID, err)
			continue
		}
		allHosts = append(allHosts, hosts...)
	}

	// Worker pool to cap concurrent outbound probes.
	sem := make(chan struct{}, appHealthMaxParallel)
	var wg sync.WaitGroup
	for _, h := range allHosts {
		wg.Add(1)
		sem <- struct{}{}
		// v2.28.0 (issue #39): skip hosts whose custom interval hasn't elapsed
		// yet. The ticker still fires every appHealthInterval; a host asking
		// for a longer gap simply sits out the intervening cycles, so the
		// effective interval rounds up to a multiple of the tick. Checked
		// before spawning the goroutine so a mostly-idle fleet doesn't
		// allocate workers it will immediately discard.
		if !s.appProbeDue(h) {
			wg.Done()
			<-sem
			continue
		}
		go func(h models.ProxyHost) {
			defer wg.Done()
			defer func() { <-sem }()
			entry := s.probeApp(ctx, h)
			s.appHealthMu.Lock()
			s.appHealth[h.ID] = entry
			s.appHealthMu.Unlock()
		}(h)
	}
	wg.Wait()

	// Garbage-collect cache entries for hosts that no longer exist, so the
	// map doesn't grow forever as hosts are created and deleted.
	live := make(map[int64]struct{}, len(allHosts))
	for _, h := range allHosts {
		live[h.ID] = struct{}{}
	}
	s.appHealthMu.Lock()
	for id := range s.appHealth {
		if _, ok := live[id]; !ok {
			delete(s.appHealth, id)
		}
	}
	s.appHealthMu.Unlock()
}

// probeApp performs one HTTPS GET against the host's primary domain and
// classifies the result. Classification rules (designed to match what a
// human reading the dashboard would actually call "up" or "down"):
//
//	ok       — 2xx / 3xx / 401 / 403 (app responded with something sensible)
//	degraded — 5xx or slow (>appHealthProbeTO)
//	down     — connection refused / TLS error / timeout
//	unknown  — domain doesn't resolve publicly (WG/Tailscale-only edge) AND the
//	           front door could not answer for it either, or it resolves only
//	           to private/RFC1918 IPs (split-horizon DNS, /etc/hosts override,
//	           Docker embedded DNS — caddyui's view of the world isn't the
//	           public internet's view, so refusing to judge is the right call),
//	           or it is a wildcard domain.
//
// A name this container cannot resolve is not the end of the probe: the front
// door is asked by address with the vhost name in Host and SNI (see
// frontdoor_probe.go), which is how the `.home` hosts get a real verdict
// instead of a grey dot.
//
// Redirects are followed up to appHealthMaxRedirect hops so "/ → /login"
// ends up as ok (200) rather than showing the 302. Cert validation is
// skipped — an expired or self-signed cert shouldn't mask the fact that the
// upstream *is* responding; the cert-expiry notifier handles that concern.
// appProbeDue reports whether enough time has passed since this host's last
// cached probe to warrant another one. Hosts on the default interval are
// always due, because the poller tick already paces them.
//
// v2.28.0 (issue #39).
func (s *Server) appProbeDue(h models.ProxyHost) bool {
	_, _, _, interval, _ := h.MonitorSettings(appHealthInterval, appHealthProbeTO)
	if interval <= appHealthInterval {
		return true
	}
	s.appHealthMu.Lock()
	prev, ok := s.appHealth[h.ID]
	s.appHealthMu.Unlock()
	if !ok || prev.CheckedAt.IsZero() {
		return true
	}
	// Subtract half a tick so a host configured at exactly 2× the interval
	// isn't pushed out to 3× by scheduling jitter.
	return time.Since(prev.CheckedAt) >= interval-(appHealthInterval/2)
}

func (s *Server) probeApp(ctx context.Context, h models.ProxyHost) appHealthEntry {
	now := time.Now()
	if !h.Enabled {
		return appHealthEntry{Status: "disabled", CheckedAt: now}
	}
	// v2.28.0 (issue #39): the operator has switched CaddyUI's own probes off
	// for this host. Emit no outbound request at all — the whole point is to
	// stop generating traffic toward a backend that is deliberately
	// unreachable from here, not merely to hide the dot.
	if h.MonitoringDisabled() {
		return appHealthEntry{Status: "off", Error: "monitoring disabled for this host", CheckedAt: now}
	}

	domains := h.DomainList()
	if len(domains) == 0 {
		return appHealthEntry{Status: "unknown", Error: "no domain configured", CheckedAt: now}
	}
	primary := domains[0]

	// Wildcard domains (e.g. "*.example.com") can't be probed directly —
	// there's no specific host to GET. Skip with "unknown" rather than
	// flagging as down.
	if strings.Contains(primary, "*") {
		return appHealthEntry{Status: "unknown", Error: "wildcard domain — no specific host to probe", CheckedAt: now}
	}

	// Preflight: if DNS from caddyui's vantage point resolves the domain
	// only to private/RFC1918 addresses (split-horizon DNS, /etc/hosts
	// override, Docker embedded DNS), any probe result here is a view of
	// caddyui's private network plumbing, not the public reachability the
	// user cares about. Bail early with "unknown" and a pointed tooltip
	// instead of showing a misleading red "down" for a site that's fine
	// from the internet. Handled before the outbound request so we don't
	// burn a 5s timeout on something we already know won't tell the truth.
	if ip, onlyPrivate := resolvesOnlyPrivate(primary); onlyPrivate {
		return appHealthEntry{
			Status:    "unknown",
			Error:     fmt.Sprintf("DNS from caddyui points to %s (private) — probe from here would be misleading; check your browser", ip),
			CheckedAt: now,
		}
	}

	// Decide scheme: we always use https because Caddy auto-upgrades, but
	// fall back to http if the host explicitly disables SSL (SSLEnabled=false
	// + no custom cert). Most installs will be https.
	scheme := "https"
	if !h.SSLEnabled && h.CertificateID == 0 {
		scheme = "http"
	}
	// v2.28.0 (issue #39): resolve the per-host probe overrides. An "auto"
	// host yields exactly the values that were hardcoded before this change,
	// so its behaviour is unchanged.
	probePath, probeMethod, expectStatus, _, probeTimeout := h.MonitorSettings(appHealthInterval, appHealthProbeTO)
	probeURL := (&url.URL{Scheme: scheme, Host: primary, Path: probePath}).String()

	client := &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			// Skip TLS verification: we care whether the app responds, not
			// about cert validity (that's tracked separately by the cert
			// notifier). Self-signed / expired certs shouldn't mask app
			// status.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // nolint:gosec // probe-only
			// Be polite: reuse one connection per host, don't hold it open.
			DisableKeepAlives: true,
		},
		CheckRedirect: appProbeRedirectPolicy(),
	}

	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, probeMethod, probeURL, nil)
	if err != nil {
		return appHealthEntry{Status: "down", Error: err.Error(), CheckedAt: now}
	}
	req.Header.Set("User-Agent", "caddyui-app-health/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		// DNS resolution failure → ask the front door by address before
		// giving up: the caddyui container may legitimately not resolve an
		// internal name (`.home`) that the front door serves perfectly well.
		// Only if that also fails is the honest answer "unknown", not "down".
		if isDNSError(err) || isNetDNSError(err) {
			if fdResp, fdLatency, ok := s.probeVhostFrontDoor(probeCtx, h, primary, scheme, probePath, probeMethod, probeTimeout); ok {
				defer fdResp.Body.Close()
				status, errMsg := classifyAppCode(fdResp.StatusCode, expectStatus)
				return appHealthEntry{
					Status: status, Code: fdResp.StatusCode, Error: errMsg,
					LatencyMS: fdLatency, CheckedAt: now,
				}
			}
			return appHealthEntry{Status: "unknown", Error: err.Error(), LatencyMS: latency, CheckedAt: now}
		}
		// If the dial failed against a private IP, the preflight check
		// above should've caught this — but DNS caches and IPv6 vs IPv4
		// races can still slip one through. Re-check the error string for
		// an embedded private IP (Go error format is
		// `dial tcp 192.168.x.x:443: connect: connection refused`).
		// Treat it the same as the preflight case: "unknown", not "down".
		if ip := privateIPFromErr(err); ip != "" {
			return appHealthEntry{
				Status:    "unknown",
				Error:     fmt.Sprintf("caddyui reached %s (private) — probe from here would be misleading; check your browser", ip),
				LatencyMS: latency,
				CheckedAt: now,
			}
		}
		return appHealthEntry{Status: "down", Error: err.Error(), LatencyMS: latency, CheckedAt: now}
	}
	defer resp.Body.Close()

	code := resp.StatusCode
	status, errMsg := classifyAppCode(code, expectStatus)
	return appHealthEntry{Status: status, Code: code, Error: errMsg, LatencyMS: latency, CheckedAt: now}
}

// appProbeRedirectPolicy follows redirects up to appHealthMaxRedirect so
// "/ → /login" ends up classified on the page it lands on, then stops.
func appProbeRedirectPolicy() func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= appHealthMaxRedirect {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

// classifyAppCode maps an HTTP status to the App dot's verdict, honouring an
// operator-declared expected status. Shared by the direct probe and the
// front-door fallback so the two can never disagree about a status code:
//
//	ok       — 2xx / 3xx / 401 / 403 (the app answered with something sensible)
//	degraded — 5xx, or a 4xx other than 401/403
//
// v2.28.0 (issue #39): when expectStatus is set it replaces the heuristic
// entirely — that is what makes a deliberately-unusual endpoint reportable.
func classifyAppCode(code, expectStatus int) (status, errMsg string) {
	if expectStatus > 0 {
		if code == expectStatus {
			return "ok", ""
		}
		return "down", fmt.Sprintf("HTTP %d (expected %d)", code, expectStatus)
	}
	switch {
	case code >= 500:
		return "degraded", fmt.Sprintf("HTTP %d", code)
	case code >= 200 && code < 400, code == http.StatusUnauthorized, code == http.StatusForbidden:
		return "ok", ""
	default:
		// 4xx other than 401/403 — treat as degraded so the user notices;
		// 404 on "/" often means the app is misconfigured.
		return "degraded", fmt.Sprintf("HTTP %d", code)
	}
}

// probeVhostFrontDoor re-issues one App-dot probe against the front door by
// address, carrying the vhost's name in Host and SNI (see frontdoor_probe.go).
// It answers only for hosts whose own URL the container could not resolve, and
// only over https, because that is the listener the vhosts live on. The caller
// owns closing the returned response; ok=false means the front door did not
// answer either, which leaves the caller to record "unknown".
func (s *Server) probeVhostFrontDoor(ctx context.Context, h models.ProxyHost, domain, scheme, probePath, method string, timeout time.Duration) (*http.Response, int64, bool) {
	if scheme != "https" {
		return nil, 0, false
	}
	for _, addr := range s.frontDoorAddrs(h.ServerID) {
		u := (&url.URL{Scheme: "https", Host: addr, Path: probePath}).String()
		req, err := http.NewRequestWithContext(ctx, method, u, nil)
		if err != nil {
			return nil, 0, false
		}
		req.Header.Set("User-Agent", "caddyui-app-health/1.0")
		start := time.Now()
		resp, err := frontDoorClient(domain, timeout, appProbeRedirectPolicy()).Do(frontDoorRequest(req, addr, domain))
		latency := time.Since(start).Milliseconds()
		if err != nil {
			continue
		}
		return resp, latency, true
	}
	return nil, 0, false
}

// isNetDNSError catches net.DNSError values that the simpler string-match
// isDNSError() might miss (e.g. wrapped errors). Shared with the existing
// isDNSError helper so callers get the same "unknown not down" semantics
// whichever error shape bubbles up.
func isNetDNSError(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

// resolvesOnlyPrivate reports whether DNS from caddyui's vantage point
// returns only non-public addresses for host — i.e. RFC1918 IPv4
// (10/8, 172.16/12, 192.168/16), IPv4/IPv6 loopback, link-local, or
// IPv6 ULA (fc00::/7). Returns the first offending IP as a string for
// tooltip context. Used to short-circuit the App probe in split-horizon
// DNS setups where caddyui's answer is an internal IP that doesn't
// match what a public client would see.
//
// A "mixed" result (some public, some private) returns false — Go's
// stdlib dialer will happily fail over to the public address, so the
// probe can still give a meaningful result.
func resolvesOnlyPrivate(host string) (string, bool) {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		// DNS failure is already handled downstream as "unknown" via
		// isDNSError. Don't claim "onlyPrivate" here just because lookup
		// bombed — let the real probe run and surface the DNSError.
		return "", false
	}
	firstPrivate := ""
	for _, ip := range ips {
		if !isPrivateOrLocalIP(ip) {
			return "", false
		}
		if firstPrivate == "" {
			firstPrivate = ip.String()
		}
	}
	return firstPrivate, true
}

// isPrivateOrLocalIP is IsPrivate ∪ loopback ∪ link-local ∪ ULA. We treat
// all of these as "caddyui's private view" — a probe hitting any of them
// isn't a trustworthy signal of public reachability.
func isPrivateOrLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return true
	}
	// IsPrivate covers RFC1918 + ULA in Go 1.17+. IsUnspecified catches 0.0.0.0 / ::
	// which dialers should never return from LookupIP but defensively
	// don't count as "public."
	if ip.IsUnspecified() {
		return true
	}
	return false
}

// privateIPFromErr tries to pull a private IP literal out of a Go dial
// error. Format from the net stdlib looks like:
//
//	"dial tcp 192.168.112.7:443: connect: connection refused"
//	"dial tcp [fc00::1]:443: connect: connection refused"
//
// Returns "" if no private IP is found. Intentionally string-based
// because Go doesn't expose the dialed address as a typed field on
// net.OpError.Err in a stable way — the error message is the stable
// contract most callers rely on.
func privateIPFromErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// Look for "dial tcp <addr>:<port>" token.
	const marker = "dial tcp "
	i := strings.Index(msg, marker)
	if i < 0 {
		return ""
	}
	rest := msg[i+len(marker):]
	// IPv6 bracketed form first.
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		if end < 0 {
			return ""
		}
		ipStr := rest[1:end]
		if ip := net.ParseIP(ipStr); ip != nil && isPrivateOrLocalIP(ip) {
			return ipStr
		}
		return ""
	}
	// IPv4: up to the next colon.
	end := strings.IndexAny(rest, ":,] ")
	if end < 0 {
		return ""
	}
	ipStr := rest[:end]
	if ip := net.ParseIP(ipStr); ip != nil && isPrivateOrLocalIP(ip) {
		return ipStr
	}
	return ""
}
