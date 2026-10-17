// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/X4Applegate/caddyui/internal/caddy"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// --- the guard (pure) --------------------------------------------------------

func TestCaddyfileGuardRefusesModelOwnedChanges(t *testing.T) {
	base := caddyfileTestConfig("10.1.10.10:8000")

	cases := []struct {
		name   string
		mutate func(c map[string]any)
		want   string
	}{
		{
			name: "dial change on a :443 host",
			mutate: func(c map[string]any) {
				srv0 := c["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv0"].(map[string]any)
				srv0["routes"].([]any)[1].(map[string]any)["handle"].([]any)[0].(map[string]any)["upstreams"].([]any)[0].(map[string]any)["dial"] = "10.1.10.10:9999"
			},
			want: "beets.home",
		},
		{
			name: "host removed from :443",
			mutate: func(c map[string]any) {
				srv0 := c["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv0"].(map[string]any)
				srv0["routes"] = srv0["routes"].([]any)[:1]
			},
			want: "route removed from srv0",
		},
		{
			name: "automatic_https change",
			mutate: func(c map[string]any) {
				c["apps"].(map[string]any)["http"].(map[string]any)["automatic_https"] = map[string]any{"disable": true}
			},
			want: "automatic_https",
		},
		{
			name: "tls app change",
			mutate: func(c map[string]any) {
				c["apps"].(map[string]any)["tls"] = map[string]any{"automation": map[string]any{"policies": []any{}}}
			},
			want: "apps.tls",
		},
	}
	for _, tc := range cases {
		after := caddyfileTestConfig("10.1.10.10:8000")
		tc.mutate(after)
		got := caddyfileForbiddenChanges(base, after)
		if len(got) == 0 {
			t.Fatalf("%s: guard allowed a model-owned change", tc.name)
		}
		if !strings.Contains(strings.Join(got, " | "), tc.want) {
			t.Fatalf("%s: guard said %v, want it to name %q", tc.name, got, tc.want)
		}
	}
}

func TestCaddyfileGuardAllowsTheFilesOwnTerritory(t *testing.T) {
	base := caddyfileTestConfig("10.1.10.10:8000")
	after := caddyfileTestConfig("10.1.10.10:8000")
	// A :80 tunnel dial change is the file's business.
	srv1 := after["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv1"].(map[string]any)
	srv1["routes"].([]any)[0].(map[string]any)["handle"].([]any)[0].(map[string]any)["upstreams"].([]any)[0].(map[string]any)["dial"] = "10.1.10.10:8124"
	// So is adding a new plain-HTTP site.
	srv1["routes"] = append(srv1["routes"].([]any), map[string]any{
		"match":  []any{map[string]any{"host": []any{"newtunnel.malouin.com"}}},
		"handle": []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": "10.1.10.10:9000"}}}},
	})

	if got := caddyfileForbiddenChanges(base, after); len(got) != 0 {
		t.Fatalf("guard refused a :80-only change: %v", got)
	}
	summary := caddyfileAllowedSummary(indexConfig(base), indexConfig(after))
	joined := strings.Join(summary, " | ")
	if !strings.Contains(joined, "newtunnel.malouin.com") || !strings.Contains(joined, "home.malouin.com") {
		t.Fatalf("allowed-change summary does not describe the edit: %v", summary)
	}
}

// --- the save path (handler) -------------------------------------------------

type saveFixture struct {
	t          *testing.T
	dir        string
	path       string
	server     *Server
	mu         sync.Mutex
	loads      []string
	adaptFails bool
	loadFails  bool
}

// newSaveFixture wires a Server against a fake admin API that records every
// /load body, so a test can prove what would have been pushed and how often.
func newSaveFixture(t *testing.T, file string) *saveFixture {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(path, []byte(file), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &saveFixture{t: t, dir: dir, path: path}
	live := caddyfileTestConfig("10.1.10.10:8000")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/config/" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(live)
		case r.URL.Path == "/adapt" && r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			if f.adaptFails || !strings.Contains(string(body), "{") {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "adapting config using caddyfile adapter: syntax error: unexpected end of input, at Caddyfile:2"})
				return
			}
			res := caddyfileTestConfig("10.1.10.10:8000")
			if strings.Contains(string(body), "8124") {
				// a :80 dial change the fixture asks for
				srv1 := res["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv1"].(map[string]any)
				srv1["routes"].([]any)[0].(map[string]any)["handle"].([]any)[0].(map[string]any)["upstreams"].([]any)[0].(map[string]any)["dial"] = "10.1.10.10:8124"
			}
			if strings.Contains(string(body), "9999") {
				srv0 := res["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv0"].(map[string]any)
				srv0["routes"].([]any)[1].(map[string]any)["handle"].([]any)[0].(map[string]any)["upstreams"].([]any)[0].(map[string]any)["dial"] = "10.1.10.10:9999"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"result": res})
		case r.URL.Path == "/load" && r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.loads = append(f.loads, string(body))
			f.mu.Unlock()
			if f.loadFails {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "loading config: loading new config: tls: no certificates"})
				return
			}
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	s, cleanup := caddyfileTestServer(t, caddy.New(srv.URL, "", ""), path)
	t.Cleanup(cleanup)
	f.server = s
	t.Setenv(caddyfileSnapshotEnv, filepath.Join(dir, "snapshots"))
	return f
}

func (f *saveFixture) loadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.loads)
}

func (f *saveFixture) lastLoad() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.loads) == 0 {
		return ""
	}
	return f.loads[len(f.loads)-1]
}

func (f *saveFixture) currentFile() string {
	b, _ := os.ReadFile(f.path)
	return string(b)
}

func (f *saveFixture) inode() uint64 {
	st, err := os.Stat(f.path)
	if err != nil {
		f.t.Fatal(err)
	}
	return st.Sys().(*syscall.Stat_t).Ino
}

func (f *saveFixture) save(content, baseSHA string, confirm bool) *httptest.ResponseRecorder {
	form := "content=" + urlEncode(content) + "&base_sha=" + urlEncode(baseSHA)
	if confirm {
		form += "&confirm=on"
	}
	req := httptest.NewRequest(http.MethodPost, "/caddyfile/save", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.server.postCaddyfileSave(rec, req)
	return rec
}

func urlEncode(s string) string {
	r := strings.NewReplacer("+", "%2B", "&", "%26", "=", "%3D", "%", "%25", " ", "+", "\n", "%0A", "\r", "%0D", "{", "%7B", "}", "%7D", "\"", "%22", "#", "%23", "(", "%28", ")", "%29", "<", "%3C", ">", "%3E")
	return r.Replace(s)
}

const saveFixtureFile = "home.malouin.com {\r\n\treverse_proxy 10.1.10.10:8123\r\n}\r\n"

func TestCaddyfileSaveRefusesAnEditToModelOwnedRoutes(t *testing.T) {
	f := newSaveFixture(t, saveFixtureFile)
	before := f.currentFile()
	ino := f.inode()

	// This buffer would re-dial a :443 host (:9999 in the fixture's adapter).
	edited := saveFixtureFile + "\r\npaperless.home {\r\n\treverse_proxy 10.1.10.10:9999\r\n}\r\n"
	rec := f.save(edited, sha256Hex([]byte(before)), true)
	body := rec.Body.String()

	if !strings.Contains(body, "Refusing to save") || !strings.Contains(body, "beets.home") {
		t.Fatalf("the guard did not refuse the :443 edit; page says: %s", firstLines(body, 40))
	}
	if f.currentFile() != before {
		t.Fatal("the file was written despite a refused edit")
	}
	if f.inode() != ino {
		t.Fatal("the refused save still replaced the inode")
	}
	if f.loadCount() != 0 {
		t.Fatal("a refused edit still reloaded Caddy")
	}
}

func TestCaddyfileSaveRefusesStaleBaseAndMissingConfirm(t *testing.T) {
	f := newSaveFixture(t, saveFixtureFile)
	if rec := f.save(saveFixtureFile+"# x\r\n", "deadbeef", true); !strings.Contains(rec.Body.String(), "changed on disk") {
		t.Fatal("a stale base_sha was not refused")
	}
	if rec := f.save(saveFixtureFile+"# x\r\n", sha256Hex([]byte(saveFixtureFile)), false); !strings.Contains(rec.Body.String(), "confirmation box is unticked") {
		t.Fatal("an unconfirmed save was not refused")
	}
	if f.loadCount() != 0 || f.currentFile() != saveFixtureFile {
		t.Fatal("a refused save touched the file or Caddy")
	}
}

func TestCaddyfileSaveWritesReloadsAndKeepsTheInode(t *testing.T) {
	f := newSaveFixture(t, saveFixtureFile)
	ino := f.inode()

	// A :80 dial edit — the file's own territory.
	edited := strings.Replace(saveFixtureFile, "8123", "8124", 1) + "\r\nhttp://tunnel.malouin.com {\r\n\treverse_proxy 10.1.10.10:8124\r\n}\r\n"
	rec := f.save(edited, sha256Hex([]byte(saveFixtureFile)), true)
	body := rec.Body.String()

	if !strings.Contains(body, "Saved") {
		t.Fatalf("a permitted save did not report success: %s", firstLines(body, 30))
	}
	// The fixture's database holds no proxy-host rows, so the follow-up sync is
	// skipped — and the page must say so instead of claiming srv0 was re-asserted.
	// This fixture has no server record at all, so the follow-up sync errors. Either
	// honest outcome is acceptable; claiming the model wrote is not.
	if strings.Contains(body, "the model re-asserted srv0") ||
		(!strings.Contains(body, "follow-up model sync failed") && !strings.Contains(body, "did NOT re-assert srv0")) {
		t.Fatalf("the save reported a model write that did not happen: %s", firstLines(body, 40))
	}
	if f.loadCount() != 1 {
		t.Fatalf("expected exactly one reload, got %d", f.loadCount())
	}
	if !strings.Contains(f.lastLoad(), "tunnel.malouin.com") {
		t.Fatal("the reload body is not the submitted Caddyfile")
	}
	if f.inode() != ino {
		t.Fatal("the save replaced the inode; a single-file bind would go stale")
	}
	if !strings.Contains(f.currentFile(), "\r\n") || strings.Contains(strings.ReplaceAll(f.currentFile(), "\r\n", ""), "\n") {
		t.Fatal("the saved file lost its CRLF line endings")
	}
	snaps, _ := filepath.Glob(filepath.Join(f.dir, "snapshots", "*.bak"))
	if len(snaps) != 1 {
		t.Fatalf("expected one pre-save snapshot, got %v", snaps)
	}
	if snap, _ := os.ReadFile(snaps[0]); string(snap) != saveFixtureFile {
		t.Fatal("the snapshot is not the pre-save file")
	}
}

func TestCaddyfileSaveRollsBackWhenCaddyRejectsTheReload(t *testing.T) {
	f := newSaveFixture(t, saveFixtureFile)
	f.loadFails = true
	edited := saveFixtureFile + "\r\nhttp://tunnel.malouin.com {\r\n\treverse_proxy 10.1.10.10:8124\r\n}\r\n"
	rec := f.save(edited, sha256Hex([]byte(saveFixtureFile)), true)
	body := rec.Body.String()

	if !strings.Contains(body, "rolled back") {
		t.Fatalf("a rejected reload did not report the rollback: %s", firstLines(body, 30))
	}
	if f.currentFile() != saveFixtureFile {
		t.Fatal("the file was not restored after the rejected reload")
	}
}

func TestCaddyfileSaveRefusesAnUnadaptableBuffer(t *testing.T) {
	f := newSaveFixture(t, saveFixtureFile)
	f.adaptFails = true
	rec := f.save("this is not a caddyfile {{{\r\n", sha256Hex([]byte(saveFixtureFile)), true)
	if !strings.Contains(rec.Body.String(), "does not adapt") {
		t.Fatalf("an unadaptable buffer was not refused: %s", firstLines(rec.Body.String(), 25))
	}
	if f.currentFile() != saveFixtureFile || f.loadCount() != 0 {
		t.Fatal("an unadaptable buffer still reached the file or Caddy")
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

func TestModelWillPushExplainsEverySkip(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	s := newRenderingTestServer(t, conn)

	if will, why := s.modelWillPush(1); will || !strings.Contains(why, "no Caddy server record") {
		t.Fatalf("missing server record: will=%v why=%q", will, why)
	}
	id, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "ext", AdminURL: "http://127.0.0.1:2019", Type: "external"})
	if err != nil {
		t.Fatal(err)
	}
	if will, why := s.modelWillPush(id); will || !strings.Contains(why, "type external") {
		t.Fatalf("external record: will=%v why=%q", will, why)
	}
	if err := models.UpdateCaddyServer(conn, &models.CaddyServer{ID: id, Name: "prod", AdminURL: "http://127.0.0.1:2019", Type: "managed"}); err != nil {
		t.Fatal(err)
	}
	if will, why := s.modelWillPush(id); will || !strings.Contains(why, "no proxy-host rows") {
		t.Fatalf("empty model: will=%v why=%q", will, why)
	}
	if _, err := models.CreateProxyHost(conn, id, 0, &models.ProxyHost{Domains: "a.home", ForwardHost: "10.1.10.10", ForwardPort: 80, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if will, why := s.modelWillPush(id); !will {
		t.Fatalf("managed with rows should push, got why=%q", why)
	}
}
