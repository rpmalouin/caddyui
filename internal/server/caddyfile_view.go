// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// errNoAdminAPI is reported when no Caddy server record resolves to a usable
// admin client, so the drift comparison is skipped instead of guessing.
var errNoAdminAPI = errors.New("no Caddy admin API is configured for the selected server")

// Caddyfile view (read-only).
//
// CaddyUI's `managed` server type owns srv0: the app rebuilds its route set from
// the proxy_hosts rows on every start and every save. The mounted Caddyfile
// (CADDYFILE_PATH) is therefore NOT the source of truth for :443 — it is read at
// boot and by a by-hand `caddy reload`, and nothing reconciles it against the
// model. That gap produced real drift (a site block destroyed, another never
// added, two upstreams dialling plain HTTP at TLS backends), and every
// regression was invisible until someone reloaded.
//
// This page makes the file legible and the drift measurable without giving the
// app a write path:
//
//   - the file's bytes, line count, hash and line endings;
//   - POST /adapt of its contents — Caddy's adapter, which runs NO config — plus
//     the adapter's warnings;
//   - a per-host comparison of what the file would serve against what is live;
//   - per-block ownership: which site blocks the model owns, which it has
//     DISABLED (a reload would resurrect them), which it does not know at all.
//
// INVARIANT: nothing in this file may call /load or any config-writing endpoint.
// /load?validate_only=true is NOT a dry run — Caddy ignores the parameter and
// applies the config (see caddy.Client.Validate's caution). A "validate" button
// that posts to /load would deploy whatever is in the textarea. /adapt is the
// only validation call here, and TestCaddyfileViewNeverLoadsConfig enforces it.

// caddyfilePage is the template model for /caddyfile.
type caddyfilePage struct {
	Path      string
	Bytes     int
	Lines     int
	SHA256    string
	CRLF      bool
	ReadErr   string
	FromBuf   bool
	Buffer    string
	Adapted   bool
	AdaptErr  string
	AdminErr  string
	Warnings  []string
	Cosmetic  []string
	LiveErr   string
	Live      []serverIndex
	Drift     []serverDrift
	DriftOK   bool
	Blocks    []caddyfileBlock
	BaseSHA   string
	SaveOK    string
	SaveErr   string
	Forbidden []string
	Allowed   []string
	ServerID  int64
	ServerNm  string
	ServerTyp string
}

// routeSignature is what one route actually serves, in the shape the per-host
// diff compares. It mirrors scripts/diff-caddy-configs.py so the page and the
// CLI check cannot disagree.
type routeSignature struct {
	Handlers []string
	Dial     []string
	Auth     []string
	HeaderUp []string
}

func (s routeSignature) empty() bool {
	return len(s.Handlers) == 0 && len(s.Dial) == 0 && len(s.Auth) == 0 && len(s.HeaderUp) == 0
}

// diff returns the field-level differences between two signatures, one short
// human-readable fragment per differing field.
func (s routeSignature) diff(o routeSignature) []string {
	var out []string
	if !equalStrings(s.Handlers, o.Handlers) {
		out = append(out, "handlers "+strings.Join(orDash(s.Handlers), ",")+" -> "+strings.Join(orDash(o.Handlers), ","))
	}
	if !equalStrings(s.Dial, o.Dial) {
		out = append(out, "dial "+strings.Join(orDash(s.Dial), ",")+" -> "+strings.Join(orDash(o.Dial), ","))
	}
	if !equalStrings(s.Auth, o.Auth) {
		out = append(out, "basicauth "+strings.Join(orDash(s.Auth), ",")+" -> "+strings.Join(orDash(o.Auth), ","))
	}
	if !equalStrings(s.HeaderUp, o.HeaderUp) {
		out = append(out, "header_up "+strings.Join(orDash(s.HeaderUp), ",")+" -> "+strings.Join(orDash(o.HeaderUp), ","))
	}
	return out
}

func orDash(v []string) []string {
	if len(v) == 0 {
		return []string{"-"}
	}
	return v
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// serverIndex is one HTTP server of a Caddy config, indexed by host.
type serverIndex struct {
	Name        string
	Listen      []string
	RouteCount  int
	Hosts       map[string]routeSignature
	Order       []string
	Matcherless int
	Dupes       []string
}

func (s serverIndex) listenString() string {
	if len(s.Listen) == 0 {
		return "-"
	}
	return strings.Join(s.Listen, ",")
}

// hostDelta is one host's verdict inside a serverDrift.
type hostDelta struct {
	Host   string
	Status string // "differs" | "only-in-file" | "only-in-live"
	Detail []string
}

type serverDrift struct {
	Name        string
	ListenFile  string
	ListenLive  string
	HostsFile   int
	HostsLive   int
	RoutesFile  int
	RoutesLive  int
	OnlyFile    []string
	OnlyLive    []string
	Changed     []hostDelta
	Matcherless int
	Dupes       []string
}

func (d serverDrift) equivalent() bool {
	return len(d.OnlyFile) == 0 && len(d.OnlyLive) == 0 && len(d.Changed) == 0
}

// caddyfileBlock is one top-level block of the file, with its ownership verdict.
type caddyfileBlock struct {
	Head  string
	Kind  string // snippet | global | plain-http | https
	Owner string // what the model says about it
	Note  string
}

// --- config indexing (pure) -------------------------------------------------

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func asStrings(v any) []string {
	var out []string
	for _, item := range asSlice(v) {
		if str, ok := item.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

// flattenHandlers unwraps route-group handlers (subroute, and the bare
// {"routes": ...} form Caddyfile adaptation compiles `handle_path` into) and
// returns the handlers that actually run.
func flattenHandlers(v any) []map[string]any {
	var out []map[string]any
	for _, item := range asSlice(v) {
		h := asMap(item)
		if h == nil {
			continue
		}
		name, _ := h["handler"].(string)
		if name == "subroute" || (name == "" && h["routes"] != nil) {
			for _, inner := range asSlice(h["routes"]) {
				out = append(out, flattenHandlers(asMap(inner)["handle"])...)
			}
			continue
		}
		out = append(out, h)
	}
	return out
}

func routeHosts(route map[string]any) []string {
	var hosts []string
	for _, m := range asSlice(route["match"]) {
		hosts = append(hosts, asStrings(asMap(m)["host"])...)
	}
	return hosts
}

// signatureFor summarises what a route serves: the handler set, the upstream
// dials, the basicauth accounts (hashed — the page never prints a password) and
// the request headers it sets.
func signatureFor(route map[string]any) routeSignature {
	var sig routeSignature
	handlers := flattenHandlers(route["handle"])
	names := make([]string, 0, len(handlers))
	for _, h := range handlers {
		name, _ := h["handler"].(string)
		if name == "" {
			name = "?"
		}
		names = append(names, name)
		switch name {
		case "reverse_proxy":
			for _, u := range asSlice(h["upstreams"]) {
				dial, _ := asMap(u)["dial"].(string)
				if dial == "" {
					dial = "?"
				}
				sig.Dial = append(sig.Dial, dial)
			}
		case "authentication":
			basic := asMap(asMap(h["providers"])["http_basic"])
			for _, a := range asSlice(basic["accounts"]) {
				acc := asMap(a)
				user, _ := acc["username"].(string)
				pw, _ := acc["password"].(string)
				sum := sha256.Sum256([]byte(pw))
				sig.Auth = append(sig.Auth, fmt.Sprintf("%s:%s", user, hex.EncodeToString(sum[:])[:8]))
			}
		case "headers":
			for _, x := range asSlice(asMap(h["request"])["set"]) {
				field, _ := asMap(x)["field"].(string)
				sig.HeaderUp = append(sig.HeaderUp, field+"="+strings.Join(asStrings(asMap(x)["value"]), "|"))
			}
		}
	}
	sort.Strings(names)
	sort.Strings(sig.Dial)
	sort.Strings(sig.Auth)
	sort.Strings(sig.HeaderUp)
	sig.Handlers = names
	return sig
}

// indexConfig indexes every HTTP server of a Caddy JSON config by host.
func indexConfig(cfg map[string]any) map[string]serverIndex {
	out := map[string]serverIndex{}
	servers := asMap(asMap(asMap(cfg["apps"])["http"])["servers"])
	for name, v := range servers {
		srv := asMap(v)
		idx := serverIndex{
			Name:   name,
			Listen: asStrings(srv["listen"]),
			Hosts:  map[string]routeSignature{},
		}
		seen := map[string]int{}
		for _, rv := range asSlice(srv["routes"]) {
			r := asMap(rv)
			if r == nil {
				continue
			}
			idx.RouteCount++
			hosts := routeHosts(r)
			if len(hosts) == 0 {
				idx.Matcherless++
			}
			sig := signatureFor(r)
			for _, h := range hosts {
				idx.Hosts[strings.ToLower(h)] = sig
				seen[strings.ToLower(h)]++
				idx.Order = append(idx.Order, strings.ToLower(h))
			}
		}
		for h, n := range seen {
			if n > 1 {
				idx.Dupes = append(idx.Dupes, h)
			}
		}
		sort.Strings(idx.Dupes)
		out[name] = idx
	}
	return out
}

// driftBetween compares the servers of two configs (the file's adaptation
// against the live config) host by host.
func driftBetween(file, live map[string]serverIndex) []serverDrift {
	names := map[string]bool{}
	for n := range file {
		names[n] = true
	}
	for n := range live {
		names[n] = true
	}
	var out []serverDrift
	for name := range names {
		f, hasFile := file[name]
		l, hasLive := live[name]
		d := serverDrift{
			Name:       name,
			ListenFile: f.listenString(),
			ListenLive: l.listenString(),
			HostsFile:  len(f.Hosts),
			HostsLive:  len(l.Hosts),
			RoutesFile: f.RouteCount,
			RoutesLive: l.RouteCount,
			Dupes:      l.Dupes,
		}
		if !hasFile {
			d.ListenFile = "-(absent)"
		}
		if !hasLive {
			d.ListenLive = "-(absent)"
		}
		for h := range f.Hosts {
			if _, ok := l.Hosts[h]; !ok {
				d.OnlyFile = append(d.OnlyFile, h)
			}
		}
		for h := range l.Hosts {
			if _, ok := f.Hosts[h]; !ok {
				d.OnlyLive = append(d.OnlyLive, h)
			}
		}
		for h, fsig := range f.Hosts {
			lsig, ok := l.Hosts[h]
			if !ok {
				continue
			}
			if detail := fsig.diff(lsig); len(detail) > 0 {
				d.Changed = append(d.Changed, hostDelta{Host: h, Status: "differs", Detail: detail})
			}
		}
		sort.Strings(d.OnlyFile)
		sort.Strings(d.OnlyLive)
		sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].Host < d.Changed[j].Host })
		d.Matcherless = l.Matcherless
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// --- page assembly ----------------------------------------------------------

// sha256Hex is the file hash the editor round-trips as its concurrency token.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (p *caddyfilePage) fillMeta(content string) {
	p.Bytes = len(content)
	if content == "" {
		p.Lines = 0
	} else {
		p.Lines = strings.Count(content, "\n") + 1
		if strings.HasSuffix(content, "\n") {
			p.Lines--
		}
	}
	p.CRLF = strings.Contains(content, "\r\n")
	sum := sha256.Sum256([]byte(content))
	p.SHA256 = hex.EncodeToString(sum[:])
}

// isCaddyfileAdapterError reports whether an /adapt failure came from Caddy's
// Caddyfile adapter (the text is wrong) rather than from the transport or the
// admin API's host check (the wiring is wrong). Only the former is a fact about
// the file.
func isCaddyfileAdapterError(msg string) bool {
	return strings.Contains(msg, "adapting config using caddyfile adapter")
}

// adaptWarnings splits the adapter's warnings into ones that change how the
// file is read and cosmetic formatting notices. Only the first kind deserves an
// alarm: "not formatted" says nothing about what the file serves (a formatted
// copy adapts to a byte-identical config), so it is reduced to one collapsed
// line instead of a warning card on every visit.
func adaptWarnings(warnings []map[string]any) (substantive, cosmetic []string) {
	for _, w := range warnings {
		msg, _ := w["message"].(string)
		file, _ := w["file"].(string)
		line := ""
		if v, ok := w["line"].(float64); ok && v > 0 {
			line = fmt.Sprintf("%s:%d: ", file, int(v))
		}
		if msg == "" {
			continue
		}
		if strings.Contains(msg, "not formatted") {
			cosmetic = append(cosmetic, line+msg)
			continue
		}
		substantive = append(substantive, line+msg)
	}
	return substantive, cosmetic
}

// getCaddyfileView renders the mounted Caddyfile read-only, adapted, and
// compared against the config the production Caddy is actually serving.
func (s *Server) getCaddyfileView(w http.ResponseWriter, r *http.Request) {
	page := &caddyfilePage{Path: s.CaddyfilePath}
	content := ""
	if page.Path == "" {
		page.ReadErr = "CADDYFILE_PATH is not set for this instance, so there is no mounted Caddyfile to show."
	} else if b, err := os.ReadFile(page.Path); err != nil {
		page.ReadErr = "Could not read " + page.Path + ": " + err.Error()
	} else {
		content = string(b)
	}
	page.Buffer = content
	s.renderCaddyfilePage(w, r, page, content)
}

// postCaddyfileValidate adapts the submitted buffer instead of the file, so an
// edit can be checked before it is written anywhere. Read-only by construction:
// the only Caddy calls are /adapt and GET /config/.
func (s *Server) postCaddyfileValidate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "could not read the submitted Caddyfile", http.StatusBadRequest)
		return
	}
	page := &caddyfilePage{
		Path:    s.CaddyfilePath,
		Buffer:  r.PostFormValue("content"),
		FromBuf: true,
	}
	s.renderCaddyfilePage(w, r, page, page.Buffer)
}

// renderCaddyfilePage fills the page model and renders it. `content` is what
// gets adapted; the file's own bytes when the page is first opened.
func (s *Server) renderCaddyfilePage(w http.ResponseWriter, r *http.Request, page *caddyfilePage, content string) {
	if page.Path != "" {
		if b, err := os.ReadFile(page.Path); err == nil {
			page.fillMeta(string(b))
			// The save path is optimistic: this is the hash of the file the page
			// was rendered from, and a save whose base no longer matches is refused.
			page.BaseSHA = page.SHA256
		}
	}
	if page.ReadErr == "" && page.Path != "" {
		if _, err := os.Stat(page.Path); err != nil {
			page.ReadErr = "Could not read " + page.Path + ": " + err.Error()
		}
	}
	if page.ReadErr != "" && content == "" {
		s.render(w, r, "caddyfile_view.html", map[string]any{
			"User": s.currentUser(r), "Section": "caddyfile", "Page": page,
		})
		return
	}

	if srv, err := models.GetCaddyServer(s.DB, s.currentServerID(r)); err == nil && srv != nil {
		page.ServerID, page.ServerNm, page.ServerTyp = srv.ID, srv.Name, srv.Type
	}

	cl := s.caddyForRequest(r)
	var liveCfg map[string]any
	var liveErr error
	if cl == nil {
		liveErr = errNoAdminAPI
	} else {
		liveCfg, _, liveErr = cl.FetchConfig()
	}
	if liveErr != nil {
		page.LiveErr = liveErr.Error()
	} else if liveCfg == nil {
		page.LiveErr = "no Caddy admin API is configured for the selected server"
	}
	liveIdx := indexConfig(liveCfg)
	if liveErr == nil {
		for _, idx := range liveIdx {
			page.Live = append(page.Live, idx)
		}
		sort.Slice(page.Live, func(i, j int) bool { return page.Live[i].Name < page.Live[j].Name })
	}

	if cl != nil && strings.TrimSpace(content) != "" {
		res, err := cl.Adapt(content)
		switch {
		case err != nil:
			// Only Caddy's own adapter messages mean the file is wrong. A
			// transport failure or the admin API's host check is an
			// environment problem, and blaming the Caddyfile for it is exactly
			// the false signal this page exists to avoid.
			if isCaddyfileAdapterError(err.Error()) {
				page.AdaptErr = err.Error()
			} else {
				page.AdminErr = err.Error()
			}
		case res == nil:
			page.AdaptErr = "Caddy returned an empty adapt result"
		default:
			page.Adapted = true
			page.Warnings, page.Cosmetic = adaptWarnings(res.Warnings)
			fileIdx := indexConfig(res.Result)
			if liveErr == nil && liveCfg != nil {
				page.Drift = driftBetween(fileIdx, liveIdx)
				page.DriftOK = true
			}
			page.Blocks = s.classifyCaddyfileBlocks(r, content, fileIdx, liveIdx)
		}
	}

	s.render(w, r, "caddyfile_view.html", map[string]any{
		"User": s.currentUser(r), "Section": "caddyfile", "Page": page,
	})
}

// classifyCaddyfileBlocks labels each top-level block by who owns it: the
// model (an enabled proxy_hosts row), the model but DISABLED (a reload would
// resurrect it), nobody (the next sync would drop it), or the Caddyfile itself
// (:80 tunnel origins and snippets).
func (s *Server) classifyCaddyfileBlocks(r *http.Request, content string, fileIdx, liveIdx map[string]serverIndex) []caddyfileBlock {
	modelState := map[string]string{}
	if s.DB != nil {
		if rows, err := models.ListProxyHosts(s.DB, s.currentServerID(r), 0, true, nil); err == nil {
			for _, h := range rows {
				state := "disabled"
				if h.Enabled {
					state = "enabled"
				}
				for _, domain := range strings.FieldsFunc(h.Domains, func(c rune) bool { return c == ',' || c == ' ' || c == '\n' }) {
					modelState[strings.ToLower(strings.TrimSpace(domain))] = state
				}
			}
		}
	}

	var out []caddyfileBlock
	for _, block := range caddy.SplitCaddyfileBlocks(content) {
		head, kind := caddyfileBlockHead(block)
		if head == "" {
			continue
		}
		row := caddyfileBlock{Head: head, Kind: kind}
		switch kind {
		case "snippet":
			row.Owner = "snippet"
			row.Note = "definition only — imported by site blocks, serves nothing on its own"
		case "global":
			row.Owner = "global options"
			row.Note = "applies to the whole file; the app does not manage this block"
		case "plain-http":
			row.Owner = "Caddyfile (:80)"
			row.Note = "plain-HTTP listener — the tunnel origin; the app leaves :80 to its owner"
		default:
			row.Owner, row.Note = caddyfileHTTPSOwnership(head, modelState, liveIdx)
		}
		out = append(out, row)
	}
	return out
}

// caddyfileBlockHead returns a one-line handle for a block plus its kind.
// Leading blank and comment lines are skipped: SplitCaddyfileBlocks attaches a
// run of comments to the block that follows it, and a comment-only tail becomes
// a block of its own — neither is a site block.
func caddyfileBlockHead(block string) (string, string) {
	lines := strings.Split(block, "\n")
	start := 0
	for start < len(lines) {
		t := strings.TrimSpace(strings.TrimSuffix(lines[start], "\r"))
		if t == "" || strings.HasPrefix(t, "#") {
			start++
			continue
		}
		break
	}
	if start == len(lines) {
		return "", ""
	}
	trimmed := strings.TrimLeft(strings.Join(lines[start:], "\n"), " 	\r\n")
	if strings.HasPrefix(trimmed, "(") {
		name := trimmed
		if i := strings.IndexAny(name, "){"); i > 0 {
			name = name[:i+1]
		}
		return name, "snippet"
	}
	first := trimmed
	if i := strings.IndexAny(first, "\r\n"); i >= 0 {
		first = first[:i]
	}
	first = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(first), "{"))
	if first == "" || strings.HasPrefix(trimmed, "{") {
		return "(global options)", "global"
	}
	if strings.Contains(first, "http://") {
		return first, "plain-http"
	}
	return first, "https"
}

// caddyfileHTTPSOwnership explains, per site block, whether the model owns the
// route the block describes.
func caddyfileHTTPSOwnership(head string, modelState map[string]string, liveIdx map[string]serverIndex) (string, string) {
	hosts := blockHosts(head)
	if len(hosts) == 0 {
		return "unclassified", "no host could be read from this block's address line"
	}
	enabled, disabled, unknown := 0, 0, 0
	live := 0
	for _, h := range hosts {
		switch modelState[h] {
		case "enabled":
			enabled++
		case "disabled":
			disabled++
		default:
			unknown++
		}
		for _, idx := range liveIdx {
			if _, ok := idx.Hosts[h]; ok {
				live++
				break
			}
		}
	}
	switch {
	case disabled > 0:
		return "model row DISABLED", "a by-hand reload of this file would put the route back; the model's next sync drops it again"
	case enabled == len(hosts):
		if live == len(hosts) {
			return "model (enabled)", "the row is what serves this :443 route — this block only matters if the file is reloaded"
		}
		return "model (enabled)", "the row is enabled but this host is not in the live config — check the last sync"
	case enabled > 0:
		return "mixed", "some hosts are model rows and some are not; the sync drops the ones it does not know"
	case unknown == len(hosts):
		return "not in the model", "no proxy_hosts row knows this host — a managed sync would drop this :443 route"
	}
	return "unclassified", ""
}

// blockHosts extracts host names from a site-address line, dropping schemes and
// ports so they can be matched against the model and the live config.
func blockHosts(head string) []string {
	var out []string
	for _, part := range strings.Split(head, ",") {
		h := strings.TrimSpace(part)
		h = strings.TrimPrefix(h, "https://")
		h = strings.TrimPrefix(h, "http://")
		if i := strings.IndexAny(h, " \t"); i >= 0 {
			h = h[:i]
		}
		if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
			h = h[:i]
		}
		h = strings.Trim(strings.ToLower(h), "{} ")
		if h != "" && !strings.ContainsAny(h, "*/") {
			out = append(out, h)
		}
	}
	return out
}
