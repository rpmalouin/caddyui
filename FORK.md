# FORK.md — rpmalouin/caddyui

Personal fork of [X4Applegate/caddyui](https://github.com/X4Applegate/caddyui), kept by Ron Malouin
for the homelab it manages.

**Standing policy: no upstream pull requests.** This fork is a destination, not a staging area.
Upstream issues and fixes belong upstream; this copy carries local work only.

- Fork: `rpmalouin/caddyui` (public fork, default branch `main`)
- Upstream: `X4Applegate/caddyui`, branch `main`
- Fork point: `f0f4b64` — "fix(scripts): publish description via a pipe"
- Fork delta published: 2026-10-04
- Last catch-up merge: `c43126a` (upstream v2.65.1-2), 2026-10-17 — 36 upstream commits
  absorbed, two review fixes dropped because upstream fixed them independently

## Why this fork exists

The homelab's reverse proxy is Caddy, and this is the UI used to drive it. The fork exists to carry
a security review of the checkout at `f0f4b64` plus its remediation, so the running version is not
simply whatever upstream's latest tag happens to be.

The review itself came out of a full pass (provenance → secrets → dependencies → SAST → CI/Docker
posture → live-deployment checks). Its report lives outside this repo, on the machine that ran it:
`/appdata/caddyui-security-audit/SECURITY-REVIEW-caddyui-2026-10-04.md`.

## Fork delta: the security patch set

Two of the four findings are still fork-only. **F2 and F4 were fixed upstream while this fork sat
still, and were dropped at the v2.65.1 catch-up merge** rather than carried as a second, weaker copy
— the rows below say what upstream now does instead.

| Finding | What was wrong | Fix |
|---|---|---|
| F1 2FA gate coverage (Medium) | `require_2fa` exempted every `/api/*` path (`internal/server/server.go`), so a session user who never enrolled TOTP kept full use of the JSON API — including write endpoints. **Still true upstream at v2.65.1**, which excludes `/api/` on purpose ("a JSON caller has no use for a redirect to an HTML page") — the exclusion is the hole, not the redirect it avoids. | `/api/*` callers now get a JSON `403`; `/totp/`, `/static/`, `/logout` stay reachable so enrolment is possible; bearer-token requests never reach the gate at all (they return earlier in `requireAuth`). Re-applied on top of upstream's v2.64.1 single-check rewrite of the same block. |
| F2 Upstream tester reachable by readers (Medium) | `POST /api/proxy-hosts/test-upstream` was registered outside the `requireWrite` group, and the handler only checked "is there a session" — any viewer could make the app issue an HTTP GET to an arbitrary `host:port` with TLS verification disabled (port scan / cloud-metadata probe from inside the container network). | **Fixed upstream (v2.57.1) — fork patch dropped 2026-10-17.** The route is inside `requireWrite`, and for non-admins the handler refuses non-plain host/port and runs `dialBlockedForTenant` (loopback, link-local, cloud metadata, and the Caddy admin API). Stronger than this fork's `forbidLinkLocalTarget`, which only refused link-local. |
| F3 Unvalidated `Referer` as redirect target (Low) | Five handlers redirected to `r.Header.Get("Referer")` verbatim. One shape is worse than it looks: `/..//evil.example` is local-looking but a browser normalises it to the protocol-relative `//evil.example`. **Still true upstream at v2.65.1** — five raw reads remain (`proxy_hosts.go` ×3, `caddy_servers.go`, `server.go`). | One shared `safeLocalReferer(r, fallback)`: only the referrer's path is used, `//host` is rejected, and the path is `path.Clean`ed and re-checked. `expectations.go` already did this for one handler and now shares the helper. |
| F4 Password change did not revoke sessions (Medium) | `models.UpdateUserPassword` only rewrote the hash; sessions live 7 days by default, so the account-recovery path left stolen sessions alive. | **Fixed upstream (v2.57.1) — fork patch dropped 2026-10-17.** `UpdateUserPassword` now deletes every session of the user, and the profile page keeps the caller's own via `auth.DeleteOtherSessions`. Covers all four sites this fork had patched (reset, invite acceptance, admin-set password, profile). |

Files touched by the remaining patch set:

```
internal/models/models.go          (nothing left — F4's helper is gone)
internal/server/server.go          2FA gate: /api/ gets a JSON 403, safeLocalReferer
internal/server/proxy_hosts.go     3 Referer redirects -> safeLocalReferer
internal/server/caddy_servers.go   Referer redirect -> safeLocalReferer
internal/server/expectations.go    redirectBack folded into the shared helper
internal/server/twofa_gate_test.go        fork — gate across pages/API/bearer/enrolment
internal/server/referer_test.go           fork — referrer sanitiser table + invariant
```

## Fork delta: hosts whose own name this deployment cannot resolve (the `.home` case)

Two behavioural fixes, unrelated to the security review. They are here because
almost every proxy host in this homelab is internally named (`paperless-gpt.home`,
`beets.home`, …) and the app reported the lot of them as down.

| Symptom | Cause | Fix |
|---|---|---|
| Dashboard shows a critical "Upstreams are down — 54 enabled proxy host(s) have failing health checks" while every container is up and every site answers. | The 5-minute public health checker (`internal/server/upstream_health_notifier.go`, `checkProxyHost`) probes `https://<first-domain>/` by name and persisted `ok=false` for *any* error, including a name-resolution failure. Inside the container `*.home` does not exist in DNS (`dial tcp: lookup <host>.home on 127.0.0.11:53: no such host`), so all 54 hosts were stored as failures and the dashboard's down count read straight from that table. The App-dot probe next to it (`app_health.go`) already refused to judge in exactly this case — DNS error or private-only resolution → "unknown", never "down" — so the two probes disagreed. | `checkProxyHost` applies the same rule: a resolution failure records no verdict and no row, and the rows that case already wrote are removed (`models.DeleteResolutionFailureProxyHealth`). A resolving-but-refused / TLS / timeout probe is still a recorded failure. Commit `ad62b73`. |
| The `:443` hosts then read grey "unknown" — honest, but not an answer the operator can act on. | The probe insisted on asking DNS where the vhost is. DNS is the one part of the path this container cannot see: the names resolve on the operator's own clients, not here. | The probe now falls back to the **front door by address**: dial the address that serves the vhosts and send the request with the vhost's name in `Host` **and** the TLS SNI, so Caddy matches the same site block the operator's browser matches. That walks the whole serving path — Caddy, routes, basicauth, upstream — and skips only the lookup that was never possible. Follow-up to `ad62b73`. |

Address discovery (`internal/server/frontdoor_probe.go`): the server record's
public IP first (the same value the managed-DNS flow writes A records from, and
editable per server in Settings → DNS/IPs), then the admin URL's host — the admin
API and the front door are the same machine. Loopback admin URLs contribute
nothing. A front door that does not answer yields no verdict again, never a
"down": a probe failure that is really about this container must not be charged
to the vhost. The SNI is not optional — an HTTPS request addressed to a bare IP
fails the handshake with no response at all against a `tls internal` front door
(measured), which would look like an outage rather than a mistake.

```
internal/server/frontdoor_probe.go               new — address discovery, Host+SNI request, client
internal/server/upstream_health_notifier.go      no-verdict rule + front-door fallback (Public check)
internal/server/app_health.go                    same fallback for the App dot; classification shared
internal/models/models.go                        DeleteResolutionFailureProxyHealth
internal/server/public_health_resolution_test.go new — no-verdict, real-failure and row-set invariants
internal/server/frontdoor_probe_test.go          new — address discovery, Host+SNI, fallback limits
```

The same gap exists in upstream (`X4Applegate/caddyui`) — its `checkProxyHost`
has no DNS branch either — but this fork carries local work only.

## Fork delta: reading and editing the Caddyfile (`/caddyfile`)

The app in `managed` mode owns `srv0`: it rebuilds the `:443` route set from the `proxy_hosts`
rows on every start and save. The Caddyfile on disk is therefore read only at boot or by a
by-hand `caddy reload`, nothing reconciles it against the model, and it drifts silently — on
2026-10-17 it had lost two live site blocks and was still dialling two TLS upstreams over plain
HTTP, so the reload that looked like a no-op would have been a regression. Upstream has no view
of that file at all; this fork adds one, and gives it a scoped write path.

### Stage 1 — read-only view, validation and drift (commits `309a137`, `5b5abe0`)

`GET /caddyfile` (admin) shows the file at `CADDYFILE_PATH` with its line count, bytes, sha256 and
line endings, adapts it through Caddy's **`/adapt`** (which runs no configuration), and compares
the result against the live `/config/` **per host**: host set, upstream dials, basicauth accounts
(sha256-prefixed, never the value) and `header_up` sets. Every top-level block is labelled by who
owns it — `model (enabled)`, `model row DISABLED` (a reload would resurrect it), `not in the
model` (the next sync drops it), `Caddyfile (:80)`, snippet, global options.

`POST /caddyfile/validate` adapts the textarea's buffer, so an edit can be checked before it
exists anywhere. Formatting-only adapter warnings are collapsed into one line; anything that
changes how the file is read stays an open warning.

### Stage 2 — a save path scoped to what the file owns (commits `f2979b6`, `2714586`)

`POST /caddyfile/save` (admin, CSRF from the rendered form) writes the file, and the scope is
enforced by a guard rather than trusted:

| Step | What it does |
|---|---|
| stale check | the page carries the file's sha256 as `base_sha`; a mismatch refuses the save, so a stale tab cannot clobber a concurrent edit |
| adapt | the buffer goes to `/adapt`; adapter rejections and admin-API refusals are reported separately (a wiring failure must not read as a bad file) |
| ownership guard | adapts the file on disk too and refuses when any `:443` listener's host set or per-host signature moves, or when `apps.http.automatic_https` / `apps.tls` changes — those are rebuilt from the rows |
| snapshot | one timestamped copy per save, `CADDYUI_CADDYFILE_SNAPSHOT_DIR` (default `/data/caddyfile-snapshots`) |
| write | in place (`O_TRUNC`, same inode — a rename would move it out from under Caddy's own bind), line endings normalised to the file's existing style |
| reload | `POST /load` as `text/caddyfile`, i.e. this **applies** the file |
| re-sync | a managed sync follows immediately, so the rows are the last writer and the Caddyfile-shaped `srv0` does not outlive the request |
| loggers | `ReconcileAnalyticsAccessLogs` + `ReconcileCertificateLogs` run after the sync (see below) |
| record | `activity_log` row `caddyfile_save` with lines, bytes, snapshot name and any failure |

A rejected reload restores the file from the snapshot and says so. A refused snapshot or write
never reaches Caddy. The success message is derived from whether the model will actually push —
`syncCaddy` returns nil for a *skip* as well as for a write, so a skip reads as "the model did
NOT re-assert srv0 (reason)", never as a write that did not happen.

**Two traps this delta encodes, both measured here:**

- **Caddy has no `validate_only`.** The query parameter is silently ignored and `/load` applies
  whatever it accepts, for `application/json` and `text/caddyfile` alike. A probe aiming at a dry
  run took the front door down on 2026-10-17. Validation that runs nothing is `/adapt`; `/load` is
  the deploy button.
- **A `/load` from a Caddyfile replaces the whole document**, including the top-level `logging`
  block CaddyUI installs for its own access ingest and certificate lifecycle streams. The first
  real save dropped `caddyui_access` / `caddyui_certificate_events` / `caddyui_certificates` and
  every server's `logs` key, silently stopping both telemetry feeds until the next restart. The
  save path now reconciles them itself; any other raw `/load` from a Caddyfile owes the same.

Deployment requirements this delta implies: the Caddyfile mount must be writable, and the file must
be writable by the app's UID — the container runs as `10001`, and a `root:root 0644` file fails
every save (`root:10001 0664` is the working shape). The admin API is reached through the fork's
`CADDYUI_ADMIN_HOST_HEADER` patch, unchanged.

```
internal/server/caddyfile_view.go          new — read-only page, /adapt, per-host drift, block ownership
internal/server/caddyfile_write.go         new — save path, guard, snapshot, in-place write, logger reconcile
internal/server/caddyfile_view_test.go     new — index/signature/drift, no-config-write invariant, warnings
internal/server/caddyfile_save_test.go     new — guard refusals, stale/unconfirmed/unadaptable, inode+CRLF, rollback
internal/server/server.go                  routes: GET /caddyfile, POST /caddyfile/validate, POST /caddyfile/save
internal/caddy/client.go                   Adapt (already present) + LoadCaddyfile (the applying call)
web/templates/caddyfile_view.html          the page: meta, drift, ownership, editor + confirm
web/templates/layout.html, web/i18n/*      nav entry `nav.caddyfile` (en + zh-CN)
```

Verified: `gofmt` empty, `go build`/`go vet` clean, `go test ./...` green; end-to-end drill against a
throwaway `caddy:2-alpine` with a copy of the real file (`:443` edit refused, stale base refused,
unconfirmed refused, unadaptable buffer refused, `:80` dial edit saved with the inode and CRLF
preserved and a snapshot written, rejected reload rolled back); then live, where the model's sync,
the inode-preserving write and the logger restoration were each confirmed against the running Caddy.

## Fork delta: version check with a build suffix (`d621504`)

The dashboard's update notice compares Docker Hub's newest `vX.Y.Z` tag against the running build's
version stamp. `semverParts` split on `.` and ran `strconv.Atoi` over each component, so a fork
stamp like `v2.65.1-secfix` parsed as `2.65.0` and the UI advertised an update to the release it
was already running. The parser now drops a pre-release/build-metadata suffix and keeps the leading
digits of each component, so a suffixed stamp compares equal to its upstream version while a
genuinely newer tag still reports. Upstream is unaffected only because it never ships a suffixed
stamp.

## What is absent in this fork

- **GitHub Actions — absent on purpose.** `.github/workflows/*` (CI, CodeQL, Claude review, release
  binaries) was deleted from this fork: a personal fork ships with no automation and no inbound
  channel. The upstream workflow contents are one `git show origin/main:.github/workflows/<file>`
  away, and the test files themselves are all still here. Upstream's `ci.yml` ran three gates —
  `gofmt -l ./cmd ./internal ./web`, `go test ./...`, `go vet ./...` — run them locally.
- **Issues and pull requests** are turned off in the fork's settings (web UI, not a file).
- **`MEMORY.md`** is gitignored: it records machine-local facts (absolute paths, toolchain location,
  the review's outcome) that mean nothing to anyone else.

## Deliberately NOT included

- The security review report and every scanner artifact — they live in
  `/appdata/caddyui-security-audit/` on the review machine, outside this repo.
- `MEMORY.md` (machine-local notes; see above).
- Any credential, `.env`, database file or graph database: upstream's `.gitignore` already covers
  all of them and nothing here relaxes it.

## Verification performed before publishing

| Gate | Command | Result |
|---|---|---|
| Format | `gofmt -l ./cmd ./internal ./web` | empty |
| Build | `go build ./...` | clean |
| Vet | `go vet ./...` | clean |
| Tests | `go test ./...` | every package `ok` (2026-10-04) |
| Reachable dependencies | `govulncheck ./...` | 0 reachable vulnerabilities (one module-level advisory, `golang.org/x/crypto/openpgp`, is never imported) |
| SAST | `gosec -fmt=json ./...` | 162 findings before and after the patch set, identical per-rule counts |

The toolchain is not the one on this host (`/usr/bin/go` is Go 1.18, below this module's
`go 1.26.0` / `toolchain go1.27.2`). The gates above were run with Go 1.27.2 installed at
`/opt/go-toolchains/go1.27.2` — the 1.26.8 that ran the original review no longer satisfies the
module's toolchain line, and upstream moved to 1.27.2 to close 12 standard-library vulnerabilities.

Re-run of the same gates on the merged tree (2026-10-17, after the v2.65.1 catch-up): `gofmt` empty,
`go build ./...` clean, `go vet ./...` clean, `go test ./...` green — every package `ok`
(`internal/server` 130s), no failures.

Not done by the review: an end-to-end login/TOTP/API walk-through — the patch set was verified by
build, vet and unit tests. The app has since been deployed for real (it drives this homelab's
production Caddy), so the flows are exercised in daily use; the fork's own machine notes keep the
deployment specifics.

## Keeping up with upstream

`origin` is upstream, `fork` is this repo, so:

```sh
git fetch origin --tags
git branch -f backup-pre-catchup main      # rollback point
git checkout -b upstream-catchup main
git merge origin/main                      # a merge, not a rebase: this branch is published
#   run the gates with /opt/go-toolchains/go1.27.2 (PATH + GOTOOLCHAIN=local)
git checkout main && git merge --ff-only upstream-catchup
git push fork main
```

Merge rather than rebase — `main` is published to `fork`, so a rebase rewrites history other clones
have seen. Expect conflicts in the same three files upstream keeps rewriting underneath the fork's
patches: `internal/server/server.go` (2FA gate, redirects), `internal/server/upstream_health.go`
(test-upstream guard) and `internal/caddy/client.go` (admin client).

**Re-check the delta before resolving anything, and drop what upstream has fixed.** At the
2026-10-17 catch-up two of the four review fixes were already upstream under different shapes
(F2 as `requireWrite` + `dialBlockedForTenant`, F4 as a session-deleting `UpdateUserPassword`).
Carrying a second copy would have meant weaker duplicate guards and a bigger conflict surface next
time. The test for each fix is on the upstream tip, not in this file:

```sh
git show origin/main:internal/server/server.go | grep -n 'HasPrefix(path, "/api/")'   # F1 still open?
git show origin/main:internal/server/upstream_health.go | grep -n dialBlockedForTenant  # F2 fixed?
git show origin/main:internal/server/proxy_hosts.go | grep -n 'Header.Get("Referer")'   # F3 still open?
git show origin/main:internal/models/models.go | grep -n 'func UpdateUserPassword' -A 8 # F4 fixed?
```

Also: the merge brings back any workflow file upstream added after the fork point (it did on
2026-10-17 — `dockerhub-description.yml`, `release-docker.yml`). Delete them again before pushing;
the fork ships with no automation.

## Support

This is a personal fork. Upstream support, documentation and releases live at
[X4Applegate/caddyui](https://github.com/X4Applegate/caddyui) and its wiki. If you want these
changes, fork it yourself and support your fork.
