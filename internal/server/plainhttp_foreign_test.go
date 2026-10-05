// SPDX-License-Identifier: Apache-2.0

package server

import "testing"

// A Caddyfile that declares a site as `http://host` makes Caddy create its own
// server on :80 (srv1), and Caddy allows only one server per listener. The sync
// must therefore never create caddyui_http alongside it — doing so made Caddy
// reject every proposal with `listener address repeated: tcp/:80` and no route
// could ever be pushed. That shape is exactly what a Cloudflare-tunnelled origin
// looks like, so this behaviour is load-bearing: getting it wrong means either
// no syncs at all, or a sync that rewrites the operator's :80 server.
func TestPlainHTTPPort(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{":80", true},
		{"0.0.0.0:80", true},
		{"[::]:80", true},
		{"127.0.0.1:80", true},
		{":443", false},
		{":8080", false},
		{"https://:80", false},
		{"", false},
	} {
		if got := plainHTTPPort(tc.addr); got != tc.want {
			t.Errorf("plainHTTPPort(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestForeignPlainHTTPListener(t *testing.T) {
	foreign := map[string]any{"srv1": map[string]any{"listen": []any{":80"}}}
	ours := map[string]any{"caddyui_http": map[string]any{"listen": []any{":80"}}}
	httpsOnly := map[string]any{"srv0": map[string]any{"listen": []any{":443"}}}
	mixed := map[string]any{
		"caddyui_http": map[string]any{"listen": []any{":80"}},
		"srv1":         map[string]any{"listen": []any{":80"}},
	}
	for name, tc := range map[string]struct {
		servers map[string]any
		want    bool
	}{
		"operator server on :80":  {foreign, true},
		"only our own :80 server": {ours, false},
		"https only":              {httpsOnly, false},
		"ours plus a foreign :80": {mixed, true},
		"no servers":              {map[string]any{}, false},
	} {
		if got := foreignPlainHTTPListener(tc.servers); got != tc.want {
			t.Errorf("%s: foreignPlainHTTPListener = %v, want %v", name, got, tc.want)
		}
	}
}

func TestApplyPlainHTTPServerLeavesForeignPortAlone(t *testing.T) {
	routes := []any{map[string]any{"match": []any{map[string]any{"host": []any{"home.malouin.com"}}}}}

	// The live shape: the operator's own :80 server, with the app wanting a
	// redirect route of its own.
	cfg := map[string]any{"apps": map[string]any{"http": map[string]any{"servers": map[string]any{
		"srv0": map[string]any{"listen": []any{":443"}},
		"srv1": map[string]any{"listen": []any{":80"},
			"routes": []any{map[string]any{"match": []any{map[string]any{"host": []any{"owner.malouin.com"}}}}}},
	}}}}
	applyPlainHTTPServer(cfg, routes)

	servers := httpServersMap(cfg)
	if _, ok := servers["caddyui_http"]; ok {
		t.Fatal("caddyui_http was created next to a foreign :80 server — Caddy would reject the config")
	}
	srv1, _ := servers["srv1"].(map[string]any)
	if got := len(srv1["routes"].([]any)); got != 1 {
		t.Fatalf("the operator's :80 server was modified: it now has %d routes, want 1", got)
	}

	// With no foreign server, behaviour is unchanged: we own the port.
	cfg2 := map[string]any{"apps": map[string]any{"http": map[string]any{"servers": map[string]any{
		"srv0": map[string]any{"listen": []any{":443"}},
	}}}}
	applyPlainHTTPServer(cfg2, routes)
	if _, ok := httpServersMap(cfg2)["caddyui_http"]; !ok {
		t.Fatal("caddyui_http should still be created when nothing else owns :80")
	}

	// And an empty route set still removes our own server.
	applyPlainHTTPServer(cfg2, nil)
	if _, ok := httpServersMap(cfg2)["caddyui_http"]; ok {
		t.Fatal("caddyui_http should be deleted when there are no plain-HTTP routes")
	}
}
