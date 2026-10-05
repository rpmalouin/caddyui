// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Caddy's admin API enforces a host check: it answers only requests whose Host
// header is 127.0.0.1:2019 / localhost. When the admin API is reached through a
// forwarding hop (a bridge gateway address, for instance), the URL-derived Host
// is refused with `403 host not allowed`, so the client needs an override.
// CADDYUI_ADMIN_HOST_HEADER supplies it, and it must be applied to every
// request path — applyAuth is the shared hook all of them call.
func TestAdminHostHeaderOverride(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	t.Run("applied when the env var is set", func(t *testing.T) {
		t.Setenv("CADDYUI_ADMIN_HOST_HEADER", "127.0.0.1:2019")
		gotHost = ""
		c := New(srv.URL, "", "")
		if c.HostHeader != "127.0.0.1:2019" {
			t.Fatalf("New() did not pick up the env var: HostHeader=%q", c.HostHeader)
		}
		if _, err := c.FetchPath("/config/"); err != nil {
			t.Fatalf("FetchPath: %v", err)
		}
		if gotHost != "127.0.0.1:2019" {
			t.Fatalf("request Host = %q, want 127.0.0.1:2019", gotHost)
		}
	})

	t.Run("URL host is used when unset", func(t *testing.T) {
		t.Setenv("CADDYUI_ADMIN_HOST_HEADER", "")
		gotHost = ""
		c := New(srv.URL, "", "")
		if c.HostHeader != "" {
			t.Fatalf("HostHeader should be empty, got %q", c.HostHeader)
		}
		if _, err := c.FetchPath("/config/"); err != nil {
			t.Fatalf("FetchPath: %v", err)
		}
		want := srv.URL[len("http://"):]
		if gotHost != want {
			t.Fatalf("request Host = %q, want the URL host %q", gotHost, want)
		}
	})
}
