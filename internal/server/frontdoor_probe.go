// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// --- Judging a vhost whose own name this container cannot resolve ---
//
// The homelab's internal sites are named `*.home`, and `.home` exists in no DNS
// server this host can ask (NXDOMAIN from the router, from systemd-resolved and
// from 1.1.1.1/8.8.8.8 — measured 2026-10-07). The operator's own clients
// resolve those names by a path this VM does not share, so a probe that insists
// on the public name can never see the site: it can only report "cannot resolve",
// which is a fact about this container and not about the vhost.
//
// The fix is to stop asking DNS where the vhost is and ask the front door
// instead: dial the Caddy that serves it **by address**, and carry the vhost's
// name in the Host header so Caddy matches the site block the operator's browser
// matches. That walks the same path a real request walks — Caddy, its routes,
// basicauth, the upstream — and skips only the name lookup that this container
// was never able to do.
//
// One detail is not optional: the TLS handshake must present the vhost's name as
// SNI, because Caddy picks the certificate from SNI. An HTTPS request addressed
// to a bare IP does not fail politely — it fails the handshake with no response
// at all (measured: 000 for `https://10.1.10.10/`, the same request with
// SNI=the vhost returns the site), so a probe without it would look like an
// outage rather than a mistake.

// frontDoorHostPort normalises an address into a dialable host:port. Accepts
// "10.1.10.10", "10.1.10.10:8443", "https://10.1.10.10", "http://host:2019",
// "[fd00::1]:443" or a bare IPv6 literal. A value with no port gets 443, the
// port a vhost is served on. Anything unusable reports false rather than
// guessing — a wrong address here would probe an unrelated service.
func frontDoorHostPort(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "", false
		}
		raw = u.Host
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		if host == "" || !validPort(port) {
			return "", false
		}
		return net.JoinHostPort(host, port), true
	}
	// No port. A bare IPv6 literal contains colons and must be re-bracketed;
	// anything else with a colon is malformed (host:badport lands here, since
	// SplitHostPort succeeds on a non-numeric port and validPort rejected it).
	if strings.Contains(raw, ":") {
		ip := net.ParseIP(raw)
		if ip == nil {
			return "", false
		}
		return net.JoinHostPort(raw, "443"), true
	}
	return net.JoinHostPort(raw, "443"), true
}

func validPort(p string) bool {
	n, err := strconv.Atoi(p)
	return err == nil && n > 0 && n <= 65535
}

// frontDoorAddrs lists, best first, the addresses worth trying to reach
// serverID's vhosts when a host's own domain does not resolve from this
// container. Empty means the probe has no honest way to reach them and must
// record no verdict.
//
// The server record's public IP comes first: it is the operator's own statement
// of "this is the address this Caddy answers on", and the same value the managed
// DNS records are written from (serverIPFor). The admin URL's host follows,
// because the admin API and the front door are the same machine — and it is the
// one that saves the common case where the public IP is a WAN address this
// container cannot dial back to (a hairpin that fails resolves to no verdict,
// not to a false outage, but trying the local address as well usually answers).
// A loopback admin URL contributes nothing: that is the shape of a front door
// this container is not meant to reach by itself, and inventing an address
// there would be worse than admitting the probe cannot judge. (An explicit
// address from the operator is honoured even when it is loopback — that is a
// statement, not an inference, and the tests rely on it.)
func (s *Server) frontDoorAddrs(serverID int64) []string {
	var out []string
	seen := map[string]bool{}
	add := func(hostport string, ok bool) {
		if !ok || hostport == "" || seen[hostport] {
			return
		}
		seen[hostport] = true
		out = append(out, hostport)
	}
	add(frontDoorHostPort(s.serverIPFor(serverID)))

	srv, err := models.GetCaddyServer(s.DB, serverID)
	if err == nil && srv != nil {
		if u, perr := url.Parse(strings.TrimSpace(srv.AdminURL)); perr == nil && u.Host != "" {
			host := u.Hostname()
			loopback := strings.EqualFold(host, "localhost")
			if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
				loopback = true
			}
			if host != "" && !loopback {
				add(net.JoinHostPort(host, "443"), true)
			}
		}
	}
	return out
}

// frontDoorRequest re-addresses req to addr while still asking for domain, which
// is what makes Caddy serve the vhost the operator named. The method, path and
// query are the request's own — the fallback changes where the request is sent,
// never what it asks for.
func frontDoorRequest(req *http.Request, addr, domain string) *http.Request {
	r := req.Clone(req.Context())
	u := *req.URL
	u.Scheme = "https"
	u.Host = addr
	r.URL = &u
	r.Host = domain
	return r
}

// frontDoorClient builds the client for a front-door request: SNI carries the
// vhost name (see the note at the top of this file), verification is skipped
// exactly as the direct probes skip it, and the caller's redirect policy is
// preserved so the App dot keeps following redirects while the persisted Public
// check keeps reading the first response.
func frontDoorClient(domain string, timeout time.Duration, checkRedirect func(*http.Request, []*http.Request) error) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         domain,
				InsecureSkipVerify: true, // nolint:gosec // probe-only: reachability, not cert validity
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: checkRedirect,
	}
}
