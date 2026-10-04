// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Review finding #10 (2026-10-04): handlers used to redirect straight to the
// raw Referer header. These cases pin the sanitiser that replaced it: only a
// same-origin path may come back, everything else falls back.
func TestSafeLocalReferer(t *testing.T) {
	tests := []struct {
		name     string
		referer  string
		fallback string
		want     string
	}{
		{"empty", "", "/proxy-hosts", "/proxy-hosts"},
		{"plain path", "/proxy-hosts/3/edit", "/proxy-hosts", "/proxy-hosts/3/edit"},
		{"path with query dropped", "/snapshots?page=2", "/", "/snapshots"},
		{"absolute same-origin URL reduces to path", "https://caddyui.example.com/proxy-hosts", "/", "/proxy-hosts"},
		{"off-site URL cannot leave the origin", "https://evil.example/steal", "/", "/steal"},
		{"protocol-relative rejected", "//evil.example/steal", "/", "/"},
		{"traversal cannot escape the origin", "/..//evil.example", "/", "/evil.example"},
		{"javascript scheme rejected", "javascript:alert(1)", "/", "/"},
		{"not a URL rejected", "::::", "/", "/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/proxy-hosts/3/toggle", nil)
			if tc.referer != "" {
				r.Header.Set("Referer", tc.referer)
			}
			got := safeLocalReferer(r, tc.fallback)
			if got != tc.want {
				t.Errorf("safeLocalReferer(%q) = %q, want %q", tc.referer, got, tc.want)
			}
			// The property that matters: whatever comes back is a cleaned,
			// same-origin path a browser cannot resolve off-origin.
			if strings.HasPrefix(got, "//") || strings.Contains(got, "..") {
				t.Errorf("safeLocalReferer(%q) = %q, which is not a clean local path", tc.referer, got)
			}
		})
	}
	if got := safeLocalReferer(nil, "/fallback"); got != "/fallback" {
		t.Errorf("safeLocalReferer(nil) = %q, want the fallback", got)
	}
}
