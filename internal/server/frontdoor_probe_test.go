// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// The `.home` case: a vhost whose name exists in no DNS this container can ask.
// These tests pin the front-door fallback — dial the address that serves the
// vhosts, carry the name in Host and SNI, and judge on what comes back — and
// pin the limit of it: when the front door does not answer either, the probe
// still records nothing rather than inventing a "down".

func TestFrontDoorHostPort(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"10.1.10.10", "10.1.10.10:443", true},
		{" 10.1.10.10 ", "10.1.10.10:443", true},
		{"10.1.10.10:8443", "10.1.10.10:8443", true},
		{"https://10.1.10.10", "10.1.10.10:443", true},
		{"http://hub.internal:2019", "hub.internal:2019", true},
		{"[fd00::1]:443", "[fd00::1]:443", true},
		{"fd00::1", "[fd00::1]:443", true},
		{"", "", false},
		{"   ", "", false},
		{"10.1.10.10:notaport", "", false}, // SplitHostPort accepts it; the port must still be a port
		{"10.1.10.10:0", "", false},
		{"10.1.10.10:70000", "", false},
		{"://nope", "", false},
	}
	for _, c := range cases {
		got, ok := frontDoorHostPort(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("frontDoorHostPort(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestFrontDoorAddrs(t *testing.T) {
	cases := []struct {
		name     string
		publicIP string
		adminURL string
		want     []string
	}{
		{"operator-set address first, admin host kept as a second try", "10.1.10.10", "http://192.168.96.1:2019", []string{"10.1.10.10:443", "192.168.96.1:443"}},
		{"operator-set address with port", "10.1.10.10:8443", "http://192.168.96.1:2019", []string{"10.1.10.10:8443", "192.168.96.1:443"}},
		{"admin URL host is the fallback", "", "http://192.168.96.1:2019", []string{"192.168.96.1:443"}},
		{"admin URL hostname fallback", "", "https://hub.internal:2019", []string{"hub.internal:443"}},
		{"same address twice is listed once", "192.168.96.1", "http://192.168.96.1:2019", []string{"192.168.96.1:443"}},
		{"loopback admin URL yields nothing", "", "http://127.0.0.1:2019", nil},
		{"localhost admin URL yields nothing", "", "http://localhost:2019", nil},
		{"admin URL with no host", "", "no-url", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newPublicHealthTestServer(t)
			if c.adminURL != "" {
				if err := models.UpdateCaddyServer(s.DB, &models.CaddyServer{
					ID: 1, Name: "Primary", AdminURL: c.adminURL, Type: models.CaddyServerTypeManaged,
				}); err != nil {
					t.Fatal(err)
				}
			}
			if c.publicIP != "" {
				if _, err := models.SetCaddyServerPublicIP(s.DB, 1, c.publicIP); err != nil {
					t.Fatal(err)
				}
			}
			got := s.frontDoorAddrs(1)
			if len(got) != len(c.want) {
				t.Fatalf("frontDoorAddrs = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("frontDoorAddrs = %v, want %v", got, c.want)
				}
			}
		})
	}
}

// frontDoorTestServer stands in for the homelab's front door: a TLS listener
// that records the Host header it was asked for and answers with a fixed code.
func frontDoorTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckProxyHostJudgesAnUnresolvableHostThroughTheFrontDoor(t *testing.T) {
	s := newPublicHealthTestServer(t)

	var sawHost atomic.Value
	sawHost.Store("")
	front := frontDoorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		sawHost.Store(r.Host)
		w.WriteHeader(http.StatusUnauthorized) // basicauth, as the .home vhosts answer
	})

	// The front door is reachable only by the address the operator recorded.
	addr := hostportOfURL(t, front.URL)
	if _, err := models.SetCaddyServerPublicIP(s.DB, 1, addr); err != nil {
		t.Fatal(err)
	}

	host := &models.ProxyHost{
		Domains: "does-not-resolve.invalid", ForwardScheme: "http", ForwardHost: "backend",
		ForwardPort: 80, Enabled: true, SSLEnabled: true,
	}
	id, err := models.CreateProxyHost(s.DB, 1, 0, host)
	if err != nil {
		t.Fatal(err)
	}
	host.ID = id

	got := s.checkProxyHost(*host, "does-not-resolve.invalid", "https://does-not-resolve.invalid/",
		"GET", 0, publicHealthCheckerTimeout, []string{addr})
	if got != probeJudgedViaFrontDoor {
		t.Fatalf("checkProxyHost = %v, want probeJudgedViaFrontDoor", got)
	}
	if h := sawHost.Load().(string); h != "does-not-resolve.invalid" {
		t.Errorf("front door was asked for Host %q, want the vhost name — Caddy matches the site block on it", h)
	}

	history, err := models.GetProxyHealthHistory(s.DB, id, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Fatalf("history rows = %d, want 1 (the front door answered)", len(history))
	}
	if !history[0].OK || history[0].StatusCode != http.StatusUnauthorized {
		t.Errorf("recorded %+v, want an OK row with HTTP 401 — 401 is how these vhosts answer", history[0])
	}
}

func TestCheckProxyHostRecordsNothingWhenTheFrontDoorAlsoFails(t *testing.T) {
	s := newPublicHealthTestServer(t)

	// A front-door address that resolves but refuses connections: the probe
	// must not turn that into a verdict about the vhost.
	closed := frontDoorTestServer(t, func(w http.ResponseWriter, r *http.Request) {})
	addr := hostportOfURL(t, closed.URL)
	closed.Close()
	if _, err := models.SetCaddyServerPublicIP(s.DB, 1, addr); err != nil {
		t.Fatal(err)
	}

	host := &models.ProxyHost{
		Domains: "does-not-resolve.invalid", ForwardScheme: "http", ForwardHost: "backend",
		ForwardPort: 80, Enabled: true, SSLEnabled: true,
	}
	id, err := models.CreateProxyHost(s.DB, 1, 0, host)
	if err != nil {
		t.Fatal(err)
	}
	host.ID = id

	got := s.checkProxyHost(*host, "does-not-resolve.invalid", "https://does-not-resolve.invalid/",
		"GET", 0, publicHealthCheckerTimeout, []string{addr})
	if got != probeUnresolved {
		t.Fatalf("checkProxyHost = %v, want probeUnresolved (no verdict is the honest answer)", got)
	}
	history, err := models.GetProxyHealthHistory(s.DB, id, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 0 {
		t.Errorf("history = %+v, want no rows: a front-door failure is not a vhost outage", history)
	}
}

func TestCheckAllProxyHostsUsesTheFrontDoorForHomeStyleNames(t *testing.T) {
	s := newPublicHealthTestServer(t)

	front := frontDoorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "app.home" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	if _, err := models.SetCaddyServerPublicIP(s.DB, 1, hostportOfURL(t, front.URL)); err != nil {
		t.Fatal(err)
	}

	host := &models.ProxyHost{
		Domains: "app.home", ForwardScheme: "http", ForwardHost: "backend",
		ForwardPort: 80, Enabled: true, SSLEnabled: true,
	}
	id, err := models.CreateProxyHost(s.DB, 1, 0, host)
	if err != nil {
		t.Fatal(err)
	}

	s.checkAllProxyHosts()

	history, err := models.GetProxyHealthHistory(s.DB, id, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || !history[0].OK || history[0].StatusCode != http.StatusOK {
		t.Fatalf("history = %+v, want one OK row with HTTP 200 — the front door serves app.home", history)
	}
}

func TestProbeAppJudgesThroughTheFrontDoor(t *testing.T) {
	s := newPublicHealthTestServer(t)

	front := frontDoorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "app.home" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	if _, err := models.SetCaddyServerPublicIP(s.DB, 1, hostportOfURL(t, front.URL)); err != nil {
		t.Fatal(err)
	}

	host := models.ProxyHost{
		ID: 7, ServerID: 1, Domains: "app.home", ForwardScheme: "http",
		ForwardHost: "backend", ForwardPort: 80, Enabled: true, SSLEnabled: true,
	}
	entry := s.probeApp(t.Context(), host)
	if entry.Status != "ok" || entry.Code != http.StatusOK {
		t.Fatalf("probeApp = %+v, want ok/200 through the front door", entry)
	}
}

// The front-door fallback must not fire for a host that is served over plain
// HTTP: those vhosts live on the operator's `:80` server, which CaddyUI does not
// own, and guessing at it is how a probe invents traffic to a port that means
// something else. The App dot keeps its "unknown" there.
func TestProbeAppDoesNotUseTheFrontDoorForPlainHTTPHosts(t *testing.T) {
	s := newPublicHealthTestServer(t)

	var hits int64
	front := frontDoorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	})
	if _, err := models.SetCaddyServerPublicIP(s.DB, 1, hostportOfURL(t, front.URL)); err != nil {
		t.Fatal(err)
	}

	host := models.ProxyHost{
		ID: 8, ServerID: 1, Domains: "does-not-resolve.invalid", ForwardScheme: "http",
		ForwardHost: "backend", ForwardPort: 80, Enabled: true, SSLEnabled: false,
	}
	entry := s.probeApp(t.Context(), host)
	if entry.Status != "unknown" {
		t.Errorf("probeApp = %+v, want unknown", entry)
	}
	if n := atomic.LoadInt64(&hits); n != 0 {
		t.Errorf("front door received %d request(s) for a plain-HTTP host, want 0", n)
	}
}

// frontDoorClient must present the vhost name as SNI: a request addressed to a
// bare IP fails the handshake against this homelab's front door outright
// (measured: no response at all), so a probe without SNI would look like an
// outage. httptest's TLS server echoes the SNI it was given.
func TestFrontDoorRequestCarriesHostAndSNI(t *testing.T) {
	got := make(chan [2]string, 1)
	front := frontDoorTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		got <- [2]string{r.Host, r.TLS.ServerName}
		w.WriteHeader(http.StatusOK)
	})
	addr := hostportOfURL(t, front.URL)

	u, err := url.Parse("https://app.home/healthz")
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := frontDoorClient("app.home", 5*time.Second, nil).Do(frontDoorRequest(req, addr, "app.home"))
	if err != nil {
		t.Fatalf("front-door request failed: %v", err)
	}
	defer resp.Body.Close()

	select {
	case pair := <-got:
		if pair[0] != "app.home" || pair[1] != "app.home" {
			t.Errorf("front door saw Host=%q SNI=%q, want both app.home", pair[0], pair[1])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("front door never received the request")
	}
}
