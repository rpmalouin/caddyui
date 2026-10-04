# FORK.md — rpmalouin/caddyui

Personal fork of [X4Applegate/caddyui](https://github.com/X4Applegate/caddyui), kept by Ron Malouin
for the homelab it manages.

**Standing policy: no upstream pull requests.** This fork is a destination, not a staging area.
Upstream issues and fixes belong upstream; this copy carries local work only.

- Fork: `rpmalouin/caddyui` (public fork, default branch `main`)
- Upstream: `X4Applegate/caddyui`, branch `main`
- Fork point: `f0f4b64` — "fix(scripts): publish description via a pipe"
- Fork delta published: 2026-10-04

## Why this fork exists

The homelab's reverse proxy is Caddy, and this is the UI used to drive it. The fork exists to carry
a security review of the checkout at `f0f4b64` plus its remediation, so the running version is not
simply whatever upstream's latest tag happens to be.

The review itself came out of a full pass (provenance → secrets → dependencies → SAST → CI/Docker
posture → live-deployment checks). Its report lives outside this repo, on the machine that ran it:
`/appdata/caddyui-security-audit/SECURITY-REVIEW-caddyui-2026-10-04.md`.

## Fork delta: the security patch set

Four findings were fixed, each with a regression test. Nothing else about the app was altered.

| Finding | What was wrong | Fix |
|---|---|---|
| F1 2FA gate coverage (Medium) | `require_2fa` exempted every `/api/*` path (`internal/server/server.go`), so a session user who never enrolled TOTP kept full use of the JSON API — including write endpoints. `require_totp` had no such exemption, so the two settings disagreed. | `/api/*` callers now get a JSON `403`; `/totp/`, `/static/`, `/logout` stay reachable so enrolment is possible; bearer-token requests are exempt from both gates. |
| F2 Upstream tester reachable by readers (Medium) | `POST /api/proxy-hosts/test-upstream` was registered outside the `requireWrite` group, and the handler only checked "is there a session" — any viewer could make the app issue an HTTP GET to an arbitrary `host:port` with TLS verification disabled (port scan / cloud-metadata probe from inside the container network). | Writer-only (`view` role → JSON `403`), plus `forbidLinkLocalTarget()` refusing targets that resolve into link-local space (`169.254.169.254`, `fe80::/10`). |
| F3 Unvalidated `Referer` as redirect target (Low) | Five handlers redirected to `r.Header.Get("Referer")` verbatim. One shape is worse than it looks: `/..//evil.example` is local-looking but a browser normalises it to the protocol-relative `//evil.example`. | One shared `safeLocalReferer(r, fallback)`: only the referrer's path is used, `//host` is rejected, and the path is `path.Clean`ed and re-checked. `expectations.go` already did this for one handler and now shares the helper. |
| F4 Password change did not revoke sessions (Medium) | `models.UpdateUserPassword` only rewrote the hash; sessions live 7 days by default, so the account-recovery path left stolen sessions alive. | New `models.DeleteSessionsForUser(db, userID, keepToken)`, called on password reset, invite acceptance, admin-set password, and from the profile page with the caller's own session preserved. |

Files touched by the patch set:

```
internal/models/models.go          DeleteSessionsForUser + password-change docs
internal/server/server.go          2FA gate, safeLocalReferer, session revocation
internal/server/proxy_hosts.go     3 Referer redirects -> safeLocalReferer
internal/server/caddy_servers.go   Referer redirect -> safeLocalReferer
internal/server/expectations.go    redirectBack folded into the shared helper
internal/server/upstream_health.go forbidLinkLocalTarget + writer-only guard
internal/server/twofa_gate_test.go        new — gate across pages/API/bearer/enrolment
internal/server/referer_test.go           new — referrer sanitiser table + invariant
internal/server/upstream_target_test.go   new — link-local refusal
internal/models/session_revoke_test.go    new — session eviction semantics
```

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
`go 1.26.0` / `toolchain go1.26.6`). The gates above were run with Go 1.26.8 installed at
`/opt/go-toolchains/go1.26.8`.

Not done: the app was never started — no login, TOTP or API flow has been exercised end to end.
The patch set is verified by build, vet and unit tests only.

## Keeping up with upstream

`origin` is upstream, `fork` is this repo, so:

```sh
git fetch origin
git merge origin/main      # or: git rebase origin/main
git push fork main
```

If upstream ever changes a file this fork also touches, the merge conflict will be in the six files
listed above and nowhere else.

## Support

This is a personal fork. Upstream support, documentation and releases live at
[X4Applegate/caddyui](https://github.com/X4Applegate/caddyui) and its wiki. If you want these
changes, fork it yourself and support your fork.
