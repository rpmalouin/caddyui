// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Review finding #9 (2026-10-04): the require_2fa gate used to exempt every
// /api/ path, so a session user who never enrolled TOTP kept full use of the
// JSON API and the policy was advisory. These cases pin the corrected shape:
// JSON callers are refused with 403, page loads are redirected into enrolment,
// the enrolment page and its assets stay reachable (or nobody could comply),
// and bearer-token automation is untouched.
func TestTwoFactorGateCoversAPIRoutes(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	s := &Server{DB: conn}

	uid, err := models.CreateUser(conn, "gate@example.com", "unused-hash", "Gate", models.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := auth.CreateSession(conn, uid)
	if err != nil {
		t.Fatal(err)
	}

	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	gate := s.requireAuth(next)

	do := func(method, path, cookie, bearer string) *httptest.ResponseRecorder {
		t.Helper()
		reached = false
		req := httptest.NewRequest(method, path, nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: cookie})
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req)
		return rec
	}

	// A bearer token for the case below: a machine credential, not a browser
	// session, so the enrolment gate must not break automation.
	rawToken := "caddyui_test_bearer_token"
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(rawToken)))
	if _, err := models.CreateAPIToken(conn, uid, "gate-test", hash, models.TokenScopeFull, nil); err != nil {
		t.Fatal(err)
	}

	for _, setting := range []string{settingRequire2FA, settingRequireTOTP} {
		if err := models.SetSetting(conn, setting, "1"); err != nil {
			t.Fatal(err)
		}

		// 1. An un-enrolled session user cannot drive the JSON API.
		for _, path := range []string{"/api/v1/proxy-hosts", "/api/ai/chat", "/api/search"} {
			rec := do(http.MethodGet, path, session, "")
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s: GET %s = %d, want 403", setting, path, rec.Code)
			}
			if reached {
				t.Errorf("%s: GET %s reached the handler despite the TOTP gate", setting, path)
			}
		}

		// 2. A page load redirects into enrolment. require_2fa uses 303,
		// require_totp uses 302 — both are redirects into the same page.
		rec := do(http.MethodGet, "/proxy-hosts", session, "")
		if rec.Code != http.StatusSeeOther && rec.Code != http.StatusFound {
			t.Errorf("%s: GET /proxy-hosts = %d, want a redirect", setting, rec.Code)
		}
		if !strings.HasPrefix(rec.Header().Get("Location"), "/totp/setup") {
			t.Errorf("%s: GET /proxy-hosts Location = %q, want a redirect to /totp/setup",
				setting, rec.Header().Get("Location"))
		}

		// 3. The enrolment page and its static assets stay reachable.
		if rec := do(http.MethodGet, "/totp/setup", session, ""); rec.Code != http.StatusOK {
			t.Errorf("%s: GET /totp/setup = %d, want 200", setting, rec.Code)
		}
		if rec := do(http.MethodGet, "/static/app.css", session, ""); rec.Code != http.StatusOK {
			t.Errorf("%s: GET /static/app.css = %d, want 200", setting, rec.Code)
		}

		// 4. A bearer token is a machine credential, not a browser session:
		// the enrolment gate must not break automation that has no TOTP.
		if rec := do(http.MethodGet, "/api/v1/proxy-hosts", "", rawToken); rec.Code != http.StatusOK {
			t.Errorf("%s: bearer GET /api/v1/proxy-hosts = %d, want 200", setting, rec.Code)
		}

		if err := models.SetSetting(conn, setting, "0"); err != nil {
			t.Fatal(err)
		}
	}
}
