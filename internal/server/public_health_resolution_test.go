// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// A proxy host whose domain does not resolve from this container used to be
// persisted as ok=0 by the public health checker, which the dashboard turned
// into a critical "Upstreams are down — N enabled proxy host(s) have failing
// health checks" recommendation. On the homelab this fired for all 54
// internally-named hosts at once (every row the same `dial tcp: lookup
// <host>.home on 127.0.0.11:53: no such host`) while every one of them was
// serving through the front door. These tests pin the fix: an unresolvable
// domain yields no verdict and no row, while a real failure still does.

func TestCheckAllProxyHostsTreatsUnresolvableDomainAsNoVerdict(t *testing.T) {
	s := newPublicHealthTestServer(t)

	host := &models.ProxyHost{
		// .invalid is reserved (RFC 2606) and never resolves.
		Domains: "does-not-resolve.invalid", ForwardScheme: "http", ForwardHost: "backend",
		ForwardPort: 80, Enabled: true, SSLEnabled: false,
	}
	id, err := models.CreateProxyHost(s.DB, 1, 0, host)
	if err != nil {
		t.Fatal(err)
	}

	// Pre-seed exactly the row an earlier build wrote for this case — the
	// production message text, resolution failure and all.
	if err := models.InsertProxyHealth(s.DB, id, false, 0, 0,
		`Get "https://does-not-resolve.invalid/": dial tcp: lookup does-not-resolve.invalid on 127.0.0.11:53: no such host`); err != nil {
		t.Fatal(err)
	}

	s.checkAllProxyHosts()

	history, err := models.GetProxyHealthHistory(s.DB, id, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 0 {
		t.Fatalf("history = %+v, want no rows: an unresolvable domain must leave the host unjudged, not down", history)
	}
	// The dashboard reads LatestProxyHealth — a host absent from it counts as
	// "unknown" (grey), which is the point.
	latest, err := models.LatestProxyHealth(s.DB, []int64{id})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := latest[id]; ok {
		t.Error("host still has a latest health row, so the dashboard would still count it as down")
	}
}

func TestCheckAllProxyHostsStillRecordsRealFailures(t *testing.T) {
	s := newPublicHealthTestServer(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Close it before the check: the domain resolves, the port is closed, so
	// the probe gets a genuine "connection refused" — that IS a verdict and
	// must still be recorded. Guards against the fix over-reaching.
	target := hostportOfURL(t, srv.URL)
	srv.Close()

	host := &models.ProxyHost{
		Domains: target, ForwardScheme: "http", ForwardHost: "backend",
		ForwardPort: 80, Enabled: true, SSLEnabled: false,
	}
	id, err := models.CreateProxyHost(s.DB, 1, 0, host)
	if err != nil {
		t.Fatal(err)
	}
	host.ID = id

	if recorded := s.checkProxyHost(*host, target, "http://"+target+"/", "GET", 0, publicHealthCheckerTimeout, nil); recorded != probeJudged {
		t.Errorf("checkProxyHost reported %v for a connection-refused probe, want a recorded failure", recorded)
	}

	history, err := models.GetProxyHealthHistory(s.DB, id, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Fatalf("history rows = %d, want 1 (a refused connection is a real failure)", len(history))
	}
	if history[0].OK {
		t.Error("connection-refused probe recorded OK")
	}
}

// The row cleanup in models repeats isDNSError()'s markers in SQL, because the
// table stores the message text and nothing else. Keep the two in step.
func TestResolutionFailureRowSetMatchesGoPredicate(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		// wantGo is what isDNSError(errors.New(msg)) must say; wantDropped is
		// what DeleteResolutionFailureProxyHealth must do with the row.
		wantGo      bool
		wantDropped bool
	}{
		{
			name:        "prod .home NXDOMAIN",
			msg:         `Get "https://paperless-gpt.home/": dial tcp: lookup paperless-gpt.home on 127.0.0.11:53: no such host`,
			wantGo:      true,
			wantDropped: true,
		},
		{
			name:        "resolver misbehaving",
			msg:         `Get "https://app.home/": dial tcp: lookup app.home on 127.0.0.11:53: server misbehaving`,
			wantGo:      true,
			wantDropped: true,
		},
		{
			name:        "temporary name resolution failure",
			msg:         `Get "https://app.home/": dial tcp: lookup app.home on 127.0.0.11:53: Temporary failure in name resolution`,
			wantGo:      true,
			wantDropped: true,
		},
		{
			// *net.DNSError with IsTimeout — isNetDNSError's shape, reached by
			// the "dial tcp: lookup" marker.
			name:        "resolver timeout",
			msg:         `Get "https://app.home/": dial tcp: lookup app.home on 127.0.0.11:53: i/o timeout`,
			wantGo:      false, // not one of isDNSError's strings; the typed error is what catches it
			wantDropped: true,
		},
		{
			name:        "connection refused",
			msg:         `Get "https://app.home:8091/": dial tcp 10.1.10.10:8091: connect: connection refused`,
			wantDropped: false,
		},
		{
			name:        "tls failure",
			msg:         `Get "https://app.home/": tls: failed to verify certificate: x509: certificate signed by unknown authority`,
			wantDropped: false,
		},
		{
			name:        "timeout talking to a resolved address",
			msg:         `Get "https://app.home/": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`,
			wantDropped: false,
		},
		{
			name:        "healthy row has no error text",
			msg:         "",
			wantDropped: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isDNSError(errors.New(c.msg)); got != c.wantGo {
				t.Errorf("isDNSError(%q) = %v, want %v", c.msg, got, c.wantGo)
			}
			// isNetDNSError covers the typed shape Go actually returns; it must
			// recognise a real DNSError, which is why the cleanup has to keep
			// the timeout variant too.
			if c.name == "resolver timeout" || c.name == "prod .home NXDOMAIN" {
				if !isNetDNSError(&net.DNSError{Err: "no such host", Name: "app.home", IsNotFound: true}) {
					t.Error("isNetDNSError does not recognise a *net.DNSError — the probe's real error type")
				}
			}

			s := newPublicHealthTestServer(t)
			host := &models.ProxyHost{
				Domains: "app.home", ForwardScheme: "http", ForwardHost: "backend",
				ForwardPort: 80, Enabled: true, SSLEnabled: false,
			}
			id, err := models.CreateProxyHost(s.DB, 1, 0, host)
			if err != nil {
				t.Fatal(err)
			}
			if err := models.InsertProxyHealth(s.DB, id, false, 0, 0, c.msg); err != nil {
				t.Fatal(err)
			}

			n, err := models.DeleteResolutionFailureProxyHealth(s.DB, id)
			if err != nil {
				t.Fatal(err)
			}
			if dropped := n > 0; dropped != c.wantDropped {
				t.Errorf("DeleteResolutionFailureProxyHealth dropped = %v (n=%d), want %v for %q", dropped, n, c.wantDropped, c.msg)
			}
			history, err := models.GetProxyHealthHistory(s.DB, id, 1)
			if err != nil {
				t.Fatal(err)
			}
			wantKept := !c.wantDropped
			if kept := len(history) == 1; kept != wantKept {
				t.Errorf("row kept = %v after cleanup, want %v", kept, wantKept)
			}
		})
	}
}
