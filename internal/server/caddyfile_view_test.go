// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/X4Applegate/caddyui/internal/caddy"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// --- fixtures ---------------------------------------------------------------

// caddyfileTestConfig is a live-config shape: two servers, hosts wrapped in a
// subroute exactly the way Caddyfile adaptation emits them.
func caddyfileTestConfig(upstream string) map[string]any {
	return map[string]any{
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"srv0": map[string]any{
						"listen": []any{":443"},
						"routes": []any{
							map[string]any{
								"match": []any{map[string]any{"host": []any{"paperless.home"}}},
								"handle": []any{map[string]any{
									"handler": "subroute",
									"routes": []any{map[string]any{
										"handle": []any{
											map[string]any{
												"handler": "authentication",
												"providers": map[string]any{"http_basic": map[string]any{"accounts": []any{
													map[string]any{"username": "ron", "password": "hashed"},
												}}},
											},
											map[string]any{
												"handler": "headers",
												"request": map[string]any{"set": []any{map[string]any{"field": "X-Real-IP", "value": []any{"{remote_host}"}}}},
											},
											map[string]any{
												"handler":   "reverse_proxy",
												"upstreams": []any{map[string]any{"dial": upstream}},
											},
										},
									}},
								}},
								"terminal": true,
							},
							map[string]any{
								"match":    []any{map[string]any{"host": []any{"beets.home"}}},
								"handle":   []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": "10.1.10.10:8337"}}}},
								"terminal": true,
							},
						},
					},
					"srv1": map[string]any{
						"listen": []any{":80"},
						"routes": []any{
							map[string]any{
								"match":  []any{map[string]any{"host": []any{"home.malouin.com"}}},
								"handle": []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": "10.1.10.10:8123"}}}},
							},
						},
					},
				},
			},
		},
	}
}

// caddyfileFakeAdmin stands in for the admin API. It records every request path and
// serves /config/ and /adapt only — anything else (notably /load) is recorded
// and answered 500 so a test can prove it was never called.
func caddyfileFakeAdmin(t *testing.T, live map[string]any, adapt map[string]any, adaptStatus int) (*caddy.Client, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch {
		case r.URL.Path == "/config/" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(live)
		case r.URL.Path == "/adapt" && r.Method == http.MethodPost:
			if adaptStatus >= 400 {
				w.WriteHeader(adaptStatus)
				if adaptStatus == http.StatusForbidden {
					_ = json.NewEncoder(w).Encode(map[string]string{"error": "host not allowed: 192.168.96.1:2019"})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": `adapting config using caddyfile adapter: syntax error: unexpected token 'hi', expecting '}', at Caddyfile:2`,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result":   adapt,
				"warnings": []any{map[string]any{"file": "Caddyfile", "line": 7.0, "message": "Caddyfile input is not formatted; run 'caddy fmt --overwrite' to fix inconsistencies"}},
			})
		default:
			// /load and every other mutating endpoint.
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return caddy.New(srv.URL, "", ""), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

func assertNoConfigWrite(t *testing.T, paths []string) {
	t.Helper()
	for _, p := range paths {
		if strings.Contains(p, "/load") || strings.Contains(p, "/config/apps") ||
			strings.Contains(p, "/stop") || strings.Contains(p, "/id/") {
			t.Fatalf("the Caddyfile page made a config-writing request: %q (all: %v)", p, paths)
		}
	}
}

func caddyfileTestServer(t *testing.T, admin *caddy.Client, path string) (*Server, func()) {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	s := newRenderingTestServer(t, conn)
	s.Caddy = admin
	s.CaddyfilePath = path
	return s, func() { _ = conn.Close() }
}

// --- pure helpers -----------------------------------------------------------

func TestCaddyfileIndexConfigReadsThroughSubroute(t *testing.T) {
	idx := indexConfig(caddyfileTestConfig("10.1.10.10:8000"))
	srv0, ok := idx["srv0"]
	if !ok {
		t.Fatalf("srv0 missing: %#v", idx)
	}
	if srv0.RouteCount != 2 || len(srv0.Hosts) != 2 {
		t.Fatalf("srv0 routes/hosts = %d/%d, want 2/2", srv0.RouteCount, len(srv0.Hosts))
	}
	sig, ok := srv0.Hosts["paperless.home"]
	if !ok {
		t.Fatalf("paperless.home not indexed: %#v", srv0.Hosts)
	}
	if len(sig.Dial) != 1 || sig.Dial[0] != "10.1.10.10:8000" {
		t.Fatalf("dial = %v, want the subroute-unwrapped upstream", sig.Dial)
	}
	if len(sig.Handlers) != 3 {
		t.Fatalf("handlers = %v, want 3 flattened handlers", sig.Handlers)
	}
	if len(sig.Auth) != 1 || !strings.HasPrefix(sig.Auth[0], "ron:") {
		t.Fatalf("auth = %v, want one hashed account for ron", sig.Auth)
	}
	if len(sig.Auth) == 1 && strings.Contains(sig.Auth[0], "hashed") {
		t.Fatalf("the basicauth password must never appear in a signature: %v", sig.Auth)
	}
	if len(sig.HeaderUp) != 1 || !strings.HasPrefix(sig.HeaderUp[0], "X-Real-IP=") {
		t.Fatalf("header_up = %v", sig.HeaderUp)
	}
	if _, ok := idx["srv1"]; !ok {
		t.Fatalf("srv1 missing: %#v", idx)
	}
}

func TestCaddyfileDriftReportsOnlyFileOnlyLiveAndChanged(t *testing.T) {
	file := indexConfig(caddyfileTestConfig("10.1.10.10:8000")) // paperless on :8000
	live := indexConfig(map[string]any{
		"apps": map[string]any{"http": map[string]any{"servers": map[string]any{
			"srv0": map[string]any{
				"listen": []any{":443"},
				"routes": []any{
					// same host, different dial + no auth
					map[string]any{
						"match":  []any{map[string]any{"host": []any{"paperless.home"}}},
						"handle": []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": "10.1.10.10:9999"}}}},
					},
					map[string]any{
						"match":  []any{map[string]any{"host": []any{"plex.home"}}},
						"handle": []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": "10.1.10.10:32400"}}}},
					},
				},
			},
		}}},
	})

	drift := driftBetween(file, live)
	var srv0 *serverDrift
	for i := range drift {
		if drift[i].Name == "srv0" {
			srv0 = &drift[i]
		}
	}
	if srv0 == nil {
		t.Fatalf("srv0 missing from drift: %#v", drift)
	}
	if len(srv0.OnlyFile) != 1 || srv0.OnlyFile[0] != "beets.home" {
		t.Fatalf("OnlyFile = %v, want [beets.home]", srv0.OnlyFile)
	}
	if len(srv0.OnlyLive) != 1 || srv0.OnlyLive[0] != "plex.home" {
		t.Fatalf("OnlyLive = %v, want [plex.home]", srv0.OnlyLive)
	}
	if len(srv0.Changed) != 1 || srv0.Changed[0].Host != "paperless.home" {
		t.Fatalf("Changed = %v, want paperless.home", srv0.Changed)
	}
	detail := strings.Join(srv0.Changed[0].Detail, " ; ")
	if !strings.Contains(detail, "dial") || !strings.Contains(detail, "basicauth") {
		t.Fatalf("change detail = %q, want the dial and basicauth fields named", detail)
	}
	if srv0.equivalent() {
		t.Fatal("a drift with three findings cannot report as equivalent")
	}

	// A config compared with itself has no differences at all — the check that
	// keeps shape/order noise from reading as drift.
	for _, d := range driftBetween(file, file) {
		if !d.equivalent() {
			t.Fatalf("%s compared with itself reported a difference: %#v", d.Name, d)
		}
	}

	// The live config in this fixture has no :80 server at all, so srv1 must
	// read as "only in the file" rather than silently disappearing.
	for i := range drift {
		if drift[i].Name == "srv1" {
			if len(drift[i].OnlyFile) != 1 || drift[i].OnlyFile[0] != "home.malouin.com" {
				t.Fatalf("srv1 OnlyFile = %v, want [home.malouin.com]", drift[i].OnlyFile)
			}
		}
	}
}

// --- handlers ---------------------------------------------------------------

func TestCaddyfileViewServesFileAndNeverWritesConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Caddyfile")
	file := "{\r\n\tadmin 0.0.0.0:2019\r\n}\r\n\r\npaperless.home {\r\n\treverse_proxy 10.1.10.10:9999\r\n}\r\n"
	if err := os.WriteFile(path, []byte(file), 0o644); err != nil {
		t.Fatal(err)
	}
	admin, paths := caddyfileFakeAdmin(t, caddyfileTestConfig("10.1.10.10:8000"), caddyfileTestConfig("10.1.10.10:9999"), 200)
	s, cleanup := caddyfileTestServer(t, admin, path)
	defer cleanup()

	rec := httptest.NewRecorder()
	s.getCaddyfileView(rec, httptest.NewRequest(http.MethodGet, "/caddyfile", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"paperless.home", "Drift — this file vs. live", "CRLF", "Validate (adapt only)"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page is missing %q", want)
		}
	}
	// The file dials :9999, live serves :8000 — that must read as a difference.
	if !strings.Contains(body, "differs") || !strings.Contains(body, "10.1.10.10:9999") {
		t.Fatalf("the dial difference is not rendered")
	}
	assertNoConfigWrite(t, paths())
}

func TestCaddyfileValidateAdaptsTheBufferOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(path, []byte("paperless.home {\r\n\treverse_proxy 10.1.10.10:8000\r\n}\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	admin, paths := caddyfileFakeAdmin(t, caddyfileTestConfig("10.1.10.10:8000"), caddyfileTestConfig("10.1.10.10:8000"), 200)
	s, cleanup := caddyfileTestServer(t, admin, path)
	defer cleanup()

	form := strings.NewReader("content=" + "newhost.home+%7B%0A%09respond+%22hello%22%0A%7D")
	req := httptest.NewRequest(http.MethodPost, "/caddyfile/validate", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.postCaddyfileValidate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Showing the validated buffer") {
		t.Fatalf("the page does not mark the buffer as the validated text")
	}
	assertNoConfigWrite(t, paths())
}

func TestCaddyfileViewSurfacesAnAdaptFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(path, []byte("research.home {\r\n\treverse_proxy 10.1.10.10:19999\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	admin, paths := caddyfileFakeAdmin(t, caddyfileTestConfig("10.1.10.10:8000"), nil, http.StatusBadRequest)
	s, cleanup := caddyfileTestServer(t, admin, path)
	defer cleanup()

	rec := httptest.NewRecorder()
	s.getCaddyfileView(rec, httptest.NewRequest(http.MethodGet, "/caddyfile", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(body, "does not adapt") || !strings.Contains(body, "syntax error") || !strings.Contains(body, "Caddyfile:2") {
		t.Fatalf("the adapter error is not shown verbatim: %s", body)
	}
	assertNoConfigWrite(t, paths())
}

func TestCaddyfileBlockOwnership(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	s := newRenderingTestServer(t, conn)

	serverID, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Production", AdminURL: "http://127.0.0.1:2019", Type: "managed"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateProxyHost(conn, serverID, 0, &models.ProxyHost{Domains: "enabled.home", ForwardHost: "10.1.10.10", ForwardPort: 8080, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateProxyHost(conn, serverID, 0, &models.ProxyHost{Domains: "disabled.home", ForwardHost: "10.1.10.10", ForwardPort: 8080, Enabled: false}); err != nil {
		t.Fatal(err)
	}

	file := strings.Join([]string{
		"{",
		"\tadmin 0.0.0.0:2019",
		"}",
		"",
		"(common) {",
		"\tencode gzip",
		"}",
		"",
		"enabled.home {",
		"\treverse_proxy 10.1.10.10:8080",
		"}",
		"",
		"disabled.home {",
		"\treverse_proxy 10.1.10.10:8080",
		"}",
		"",
		"unknown.home {",
		"\treverse_proxy 10.1.10.10:8080",
		"}",
		"",
		"http://tunnel.malouin.com {",
		"\treverse_proxy 10.1.10.10:8080",
		"}",
		"",
	}, "\n")

	live := map[string]serverIndex{}
	blocks := s.classifyCaddyfileBlocks(httptest.NewRequest(http.MethodGet, "/caddyfile", nil), file, nil, live)
	if len(blocks) != 6 {
		t.Fatalf("blocks = %d, want 6: %#v", len(blocks), blocks)
	}
	want := map[string]string{
		"(common)":                  "snippet",
		"(global options)":          "global options",
		"enabled.home":              "model (enabled)",
		"disabled.home":             "model row DISABLED",
		"unknown.home":              "not in the model",
		"http://tunnel.malouin.com": "Caddyfile (:80)",
	}
	for _, b := range blocks {
		if exp, ok := want[b.Head]; ok && b.Owner != exp {
			t.Fatalf("block %q owner = %q, want %q", b.Head, b.Owner, exp)
		}
	}
}

func TestCaddyfileViewSeparatesAnAdminRefusalFromABadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(path, []byte("paperless.home {\r\n\treverse_proxy 10.1.10.10:8000\r\n}\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	admin, paths := caddyfileFakeAdmin(t, caddyfileTestConfig("10.1.10.10:8000"), nil, http.StatusForbidden)
	s, cleanup := caddyfileTestServer(t, admin, path)
	defer cleanup()

	rec := httptest.NewRecorder()
	s.getCaddyfileView(rec, httptest.NewRequest(http.MethodGet, "/caddyfile", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "admin API refused the request") {
		t.Fatalf("an admin-API refusal must be named as a wiring problem, not as a bad file")
	}
	if !strings.Contains(body, "host not allowed") {
		t.Fatalf("the refusal text is not shown")
	}
	if strings.Contains(body, "The Caddyfile does not adapt") {
		t.Fatalf("an admin-API refusal was mislabelled as a Caddyfile problem")
	}
	assertNoConfigWrite(t, paths())
}

func TestCaddyfileCommentOnlyBlocksAreNotSites(t *testing.T) {
	s := &Server{}
	file := "# ---- header ----\n# a second comment line\n\n# another run\n\npaperless.home {\r\n\treverse_proxy 10.1.10.10:8000\r\n}\r\n\n# trailing note\n"
	blocks := s.classifyCaddyfileBlocks(httptest.NewRequest(http.MethodGet, "/caddyfile", nil), file, nil, nil)
	if len(blocks) != 1 {
		t.Fatalf("blocks = %d, want 1 (comments are not site blocks): %#v", len(blocks), blocks)
	}
	if blocks[0].Head != "paperless.home" {
		t.Fatalf("head = %q, want paperless.home", blocks[0].Head)
	}
	if blocks[0].Kind != "https" {
		t.Fatalf("kind = %q, want https", blocks[0].Kind)
	}
}
