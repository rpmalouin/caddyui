// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Stage 2: the scoped write path.
//
// The file owns what the model does not — the plain-HTTP tunnel blocks, snippet
// definitions and the global options block. srv0 (:443) belongs to the
// proxy_hosts rows, so a save is only allowed to touch the rest: caddyfileForbiddenChanges
// compares the adapted document of the buffer against the adapted document of
// the file on disk and REFUSES the write when any :443 route or the global TLS
// settings move. That guard, not the operator's care, is what keeps a text edit
// from becoming a front-door change the model then contradicts.
//
// The order of a save is deliberate and each step protects the next:
//   stale check → adapt (validates) → guard (:443 untouched) → snapshot →
//   in-place write → reload → model sync (last writer) → activity log.
//
// A failed reload rolls the file back from the snapshot. The model sync runs
// after a successful reload so srv0 is rebuilt from the rows rather than left in
// the Caddyfile's shape, with its route set (including rows the model holds
// disabled) re-asserted.

const caddyfileSnapshotEnv = "CADDYUI_CADDYFILE_SNAPSHOT_DIR"

// caddyfileSnapshotDir is where the pre-save copies go. It defaults next to the
// app's data directory so the same restic plan that covers /data covers them.
func caddyfileSnapshotDir() string {
	if v := strings.TrimSpace(os.Getenv(caddyfileSnapshotEnv)); v != "" {
		return v
	}
	return "/data/caddyfile-snapshots"
}

// caddyfileForbiddenChanges lists the parts of a proposed change that belong to
// the model rather than to the file. Empty means the edit stays in the file's
// territory (:80 listeners, snippets, global options unrelated to TLS).
func caddyfileForbiddenChanges(before, after map[string]any) []string {
	var out []string
	bi, ai := indexConfig(before), indexConfig(after)

	names := map[string]bool{}
	for n := range bi {
		names[n] = true
	}
	for n := range ai {
		names[n] = true
	}
	ordered := make([]string, 0, len(names))
	for n := range names {
		ordered = append(ordered, n)
	}
	sort.Strings(ordered)

	for _, name := range ordered {
		b, hasB := bi[name]
		a, hasA := ai[name]
		if !isHTTPSListener(b.Listen) && !isHTTPSListener(a.Listen) {
			continue // a :80 listener (or something else) — the file's own territory
		}
		switch {
		case hasB && !hasA:
			out = append(out, fmt.Sprintf("server %s (%s) would disappear", name, b.listenString()))
			continue
		case hasA && !hasB:
			out = append(out, fmt.Sprintf("server %s (%s) would be created", name, a.listenString()))
			continue
		}
		for _, h := range missingKeys(b.Hosts, a.Hosts) {
			out = append(out, fmt.Sprintf("%s: route removed from %s", h, name))
		}
		for _, h := range missingKeys(a.Hosts, b.Hosts) {
			out = append(out, fmt.Sprintf("%s: route added to %s", h, name))
		}
		for _, h := range sharedKeys(b.Hosts, a.Hosts) {
			if d := b.Hosts[h].diff(a.Hosts[h]); len(d) > 0 {
				out = append(out, fmt.Sprintf("%s: %s", h, strings.Join(d, ", ")))
			}
		}
	}

	// Global TLS behaviour governs the :443 side no matter which block set it.
	if !reflect.DeepEqual(httpAutomaticHTTPS(before), httpAutomaticHTTPS(after)) {
		out = append(out, "apps.http.automatic_https would change (the model sets it for the foreign :80 listener)")
	}
	if !reflect.DeepEqual(appsTLS(before), appsTLS(after)) {
		out = append(out, "apps.tls would change (certificate policies belong to the model)")
	}
	return out
}

func isHTTPSListener(listen []string) bool {
	for _, l := range listen {
		if strings.HasSuffix(strings.TrimSpace(l), ":443") || strings.Contains(l, ":443 ") {
			return true
		}
	}
	return false
}

func missingKeys(a, b map[string]routeSignature) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func sharedKeys(a, b map[string]routeSignature) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func httpAutomaticHTTPS(cfg map[string]any) any {
	return asMap(asMap(cfg["apps"])["http"])["automatic_https"]
}

func appsTLS(cfg map[string]any) any {
	return asMap(cfg["apps"])["tls"]
}

// caddyfileLineEnding reports the dominant line-ending style of a file body.
func caddyfileLineEnding(s string) string {
	crlf := strings.Count(s, "\r\n")
	lf := strings.Count(s, "\n") - crlf
	if crlf > lf {
		return "\r\n"
	}
	return "\n"
}

// normalizeCaddyfileEOL rewrites the submitted text to the file's existing
// line-ending style. A single-file bind is pinned to an inode and this file is
// CRLF; letting an editor convert it to LF would rewrite every line and make the
// next hand edit a whole-file diff.
func normalizeCaddyfileEOL(content, like string) string {
	if caddyfileLineEnding(like) == "\r\n" {
		return strings.ReplaceAll(strings.ReplaceAll(content, "\r\n", "\n"), "\n", "\r\n")
	}
	return strings.ReplaceAll(content, "\r\n", "\n")
}

// writeInPlace truncates and rewrites the file, keeping the inode. A
// rename-style save would move the inode out from under every container that
// bind-mounts the file (Caddy included) until it is recreated.
func writeInPlace(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// snapshotCaddyfile writes a timestamped copy of the current file and returns
// its path. Every save is preceded by one, so the previous version is always on
// disk next to the app data.
func (s *Server) snapshotCaddyfile(current []byte) (string, error) {
	dir := caddyfileSnapshotDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s.%s.bak", filepath.Base(s.CaddyfilePath), time.Now().UTC().Format("20060102-150405"))
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(current); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	return path, f.Close()
}

// postCaddyfileSave is the only write path for the mounted Caddyfile. Every
// refusal below happens BEFORE the file is touched; the only write that can be
// followed by a rollback is the reload.
func (s *Server) postCaddyfileSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "could not read the submitted Caddyfile", http.StatusBadRequest)
		return
	}
	content := r.PostFormValue("content")
	page := &caddyfilePage{Path: s.CaddyfilePath, Buffer: content, FromBuf: true}
	finish := func() { s.renderCaddyfilePage(w, r, page, content) }

	refuse := func(msg string) {
		page.SaveErr = msg
		finish()
	}

	if s.CaddyfilePath == "" {
		refuse("CADDYFILE_PATH is not set, so there is nothing to save to.")
		return
	}
	if r.PostFormValue("confirm") != "on" {
		refuse("Nothing was written: the confirmation box is unticked.")
		return
	}
	current, err := os.ReadFile(s.CaddyfilePath)
	if err != nil {
		refuse("Could not read " + s.CaddyfilePath + ": " + err.Error())
		return
	}
	if got, want := strings.TrimSpace(r.PostFormValue("base_sha")), sha256Hex(current); got != want {
		shorter := want
		if len(shorter) > 12 {
			shorter = shorter[:12]
		}
		refuse("Refusing to save: the file changed on disk since this page was loaded (it is now " + shorter + "…). Reload the page and re-apply your edit — overwriting would discard someone else's change.")
		return
	}

	cl := s.caddyForRequest(r)
	if cl == nil {
		refuse("No Caddy admin API is configured for the selected server, so the edit cannot be validated — nothing was written.")
		return
	}

	proposed, err := cl.Adapt(content)
	if err != nil {
		if isCaddyfileAdapterError(err.Error()) {
			refuse("Nothing was written: the Caddyfile does not adapt. " + err.Error())
		} else {
			refuse("Nothing was written: Caddy's admin API refused the adapt request (wiring, not the file). " + err.Error())
		}
		return
	}
	existing, err := cl.Adapt(string(current))
	if err != nil {
		refuse("Refusing to save: the file currently on disk does not adapt, so the ownership guard cannot compare against it. " + err.Error())
		return
	}

	if blocked := caddyfileForbiddenChanges(existing.Result, proposed.Result); len(blocked) > 0 {
		page.Forbidden = blocked
		refuse("Refusing to save: this edit changes what the model owns on :443. Those routes are rebuilt from the proxy-host rows on every sync, so a change here would be reverted or fought over. Nothing was written.")
		return
	}

	// Summarise the permitted part of the change for the success panel.
	page.Allowed = caddyfileAllowedSummary(indexConfig(existing.Result), indexConfig(proposed.Result))

	snap, err := s.snapshotCaddyfile(current)
	if err != nil {
		refuse("Nothing was written: the pre-save snapshot could not be created (" + err.Error() + ").")
		return
	}

	normalized := normalizeCaddyfileEOL(content, string(current))
	if err := writeInPlace(s.CaddyfilePath, normalized); err != nil {
		refuse("The write failed: " + err.Error() + ". The previous contents were restored from the snapshot at " + filepath.Base(snap) + ".")
		_ = writeInPlace(s.CaddyfilePath, string(current))
		return
	}

	if err := cl.LoadCaddyfile(normalized); err != nil {
		rbErr := writeInPlace(s.CaddyfilePath, string(current))
		_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "caddyfile_save", s.CaddyfilePath, "reload rejected; rolled back: "+err.Error(), false)
		if rbErr != nil {
			page.SaveErr = "Caddy rejected the reload AND the automatic rollback failed (" + rbErr.Error() + "). The file on disk is the rejected edit; the previous version is " + snap + ". Fix this by hand."
			finish()
			return
		}
		refuse("Caddy rejected the reload, so the file was rolled back to its previous contents — the front door is unchanged. " + err.Error())
		return
	}

	// The model is the last writer: srv0 goes back to the rows' shape and route
	// set, and the reload's Caddyfile-shaped srv0 never outlives this request.
	syncErr := s.syncCaddy(s.currentServerID(r), false)

	// A /load from the Caddyfile replaces the WHOLE document, including the
	// top-level `logging` block CaddyUI installs for its own access and
	// certificate streams. Startup reconciles those; a save must too, or the
	// first save silently stops both telemetry feeds until the next restart.
	var loggerErrs []string
	if err := s.ReconcileAnalyticsAccessLogs(); err != nil {
		loggerErrs = append(loggerErrs, "access logger: "+err.Error())
	}
	if err := s.ReconcileCertificateLogs(); err != nil {
		loggerErrs = append(loggerErrs, "certificate logger: "+err.Error())
	}

	detail := fmt.Sprintf("reloaded %s (%d lines, %d bytes); snapshot %s", s.CaddyfilePath, strings.Count(normalized, "\n")+1, len(normalized), filepath.Base(snap))
	if syncErr != nil {
		detail += "; follow-up model sync failed: " + syncErr.Error()
	}
	if len(loggerErrs) > 0 {
		detail += "; logger reconcile: " + strings.Join(loggerErrs, "; ")
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "caddyfile_save", s.CaddyfilePath, detail, syncErr == nil)

	// syncCaddy returns nil for a skip as well as for a write, so the message is
	// chosen from the reason, not from the error. Claiming "the model re-asserted
	// srv0" when the sync was skipped is exactly the kind of false success this
	// page exists to avoid.
	switch {
	case syncErr != nil:
		page.SaveOK = "Saved and reloaded. The follow-up model sync failed, so srv0 may still be in the Caddyfile's shape until the next sync: " + syncErr.Error()
	default:
		if len(loggerErrs) > 0 {
			page.SaveOK = "Saved and reloaded, but the logging reconciliation failed (" + strings.Join(loggerErrs, "; ") + "). Access and certificate telemetry stay off until it succeeds."
		} else if willPush, why := s.modelWillPush(s.currentServerID(r)); willPush {
			page.SaveOK = "Saved, reloaded, the model re-asserted srv0 (proxy-host rows are the last writer), and the access + certificate loggers were reinstalled."
		} else {
			page.SaveOK = "Saved and reloaded. The model did NOT re-assert srv0 (" + why + "), so the live config keeps the Caddyfile's shape — the :443 routes it carries are the ones this file just loaded."
		}
	}
	finish()
}

// caddyfileAllowedSummary describes the permitted part of an edit: what changed
// on the listeners the file owns. Empty means the buffer is a no-op for them.
func caddyfileAllowedSummary(before, after map[string]serverIndex) []string {
	var out []string
	for name, a := range after {
		b, ok := before[name]
		if !ok {
			out = append(out, fmt.Sprintf("%s (%s) added", name, a.listenString()))
			continue
		}
		if isHTTPSListener(a.Listen) {
			continue
		}
		for _, h := range missingKeys(b.Hosts, a.Hosts) {
			out = append(out, fmt.Sprintf("%s: route removed from %s", h, name))
		}
		for _, h := range missingKeys(a.Hosts, b.Hosts) {
			out = append(out, fmt.Sprintf("%s: route added to %s", h, name))
		}
		for _, h := range sharedKeys(b.Hosts, a.Hosts) {
			if d := b.Hosts[h].diff(a.Hosts[h]); len(d) > 0 {
				out = append(out, fmt.Sprintf("%s: %s", h, strings.Join(d, ", ")))
			}
		}
	}
	for name, b := range before {
		if _, ok := after[name]; !ok && !isHTTPSListener(b.Listen) {
			out = append(out, fmt.Sprintf("%s (%s) removed", name, b.listenString()))
		}
	}
	sort.Strings(out)
	return out
}

// modelWillPush reports whether a managed sync for this server would actually
// write srv0, and why not when it would not. syncCaddy returns nil for every
// skip path (external record, post-apply hold, empty database), so its error is
// not evidence that the model wrote anything.
func (s *Server) modelWillPush(serverID int64) (bool, string) {
	srv, err := models.GetCaddyServer(s.DB, serverID)
	if err != nil || srv == nil {
		return false, "no Caddy server record matches this request"
	}
	if srv.Type != models.CaddyServerTypeManaged {
		return false, "the server record is type " + srv.Type + ", so the model never pushes"
	}
	if s.syncHoldFor(serverID) != nil {
		return false, "a post-apply hold is set after a failed check"
	}
	rows, err := models.ListProxyHosts(s.DB, serverID, 0, true, nil)
	if err != nil {
		return false, "the proxy-host rows could not be read: " + err.Error()
	}
	if len(rows) == 0 {
		return false, "the model holds no proxy-host rows for this server, so the sync refuses to push empty routes"
	}
	return true, ""
}
