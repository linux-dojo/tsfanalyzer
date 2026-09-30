# Security

This tool ingests archives produced by someone else's device — running configs,
addressing, serial numbers, usernames, sometimes credentials-adjacent material.
Both the input and the data at rest deserve to be treated as sensitive.

This document records what was reviewed, what was found, what was fixed, and
what is knowingly still open.

---

## 1. Dependency advisories (from the Socket SCA scan)

Four alerts, all against `vite` / `esbuild`, all in `devDependencies`.

| Advisory | Severity | Package |
|---|---|---|
| [CVE-2026-53571](https://github.com/advisories/GHSA-fx2h-pf6j-xcff) — `server.fs.deny` bypass on Windows alternate paths (NTFS ADS, 8.3 short names) | High | vite |
| [GHSA-67mh-4wv8-2f99](https://github.com/advisories/GHSA-67mh-4wv8-2f99) — any website can send requests to the dev server and read the response | Medium | esbuild |
| Path traversal in optimized-deps `.map` handling | Medium | vite |
| [CVE-2026-53632](https://github.com/advisories/GHSA-v6wh-96g9-6wx3) — launch-editor NTLMv2 hash disclosure via UNC paths on Windows | Medium | launch-editor (via vite) |

### Exposure

**None of the four is reachable in a deployed instance.** The production image is
multi-stage: `node:22-alpine` builds, `nginx:1.27-alpine` serves the built
assets. Vite, esbuild and launch-editor exist only in the build stage and are
not present in the shipped image. There is no dev server in production.

They are reachable **on a developer's machine running `npm run dev`** — and
CVE-2026-53632 is genuinely nasty there: it leaks the developer's NTLMv2 hash to
an attacker-controlled SMB server, on Windows, for offline cracking. So they are
worth fixing regardless of production exposure.

### Fix

Vite 5.x is end-of-life and will not be patched. Fixed lines are 6.4.3, 7.3.5 and
8.0.16. We moved to the nearest one:

```diff
- "@vitejs/plugin-react": "^4.3.1",
- "vite": "^5.4.0"
+ "@vitejs/plugin-react": "^4.3.4",
+ "vite": "^6.4.3"
+ "overrides": { "esbuild": ">=0.25.0" }
```

Vite 6 keeps `@vitejs/plugin-react` 4.x compatibility, so the blast radius is one
major version rather than three. Vite 8 is the longer-term target and needs
`@vitejs/plugin-react` 6.x.

### Two things the scan did not report

**No lockfile existed.** `npm install` in both the Dockerfile and CI re-resolved
every `^` range on each run, so two builds of the same commit could ship
different dependency trees, and a compromised patch release would land silently
with no diff. The Dockerfile now prefers `npm ci` when a lockfile is present:

```dockerfile
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
```

**Commit the lockfile.** Run `npm install` once and commit `package-lock.json`.
Until that happens the reproducibility problem is unchanged.

**Node 20 reached end-of-life in April 2026.** Build image and CI moved to Node 22.

---

## 2. Application review

Scanners read your manifest. They do not read your code. The most serious issue
found was in our own five lines, not in any dependency.

### 2.1 CORS wildcard on an unauthenticated API — **High** — fixed

```go
// before
w.Header().Set("Access-Control-Allow-Origin", "*")
```

`Access-Control-Allow-Origin: *` is the header that switches off the browser's
same-origin protection. This API has no authentication. Together that meant:

> Any web page the user visited, while the tool was running on their machine,
> could `fetch("http://localhost:8081/api/v1/files")`, enumerate every archive
> they had uploaded, read the full text of every file inside them, and `DELETE`
> them — silently, with no interaction beyond loading the page.

This is the same vulnerability class as the esbuild advisory in the scan
("enables any website to send any requests to the development server and read
the response"), present in our own code, and invisible to the scanner.

Neither supported deployment needs CORS. nginx serves the SPA and proxies
`/api/` — same origin. Vite's dev proxy forwards `/api` — also same origin.

**Fixed:** no CORS headers by default. `CORS_ALLOW_ORIGIN` opts in a single
concrete origin, echoed only on exact match, with `Vary: Origin`. Never a
wildcard.

Pinned by `TestNoWildcardCORS`, `TestCORSOnlyEchoesTheConfiguredOrigin`.

### 2.2 DNS rebinding — **Medium** — fixed

With the wildcard gone, rebinding is the remaining route from a hostile page: an
attacker resolves a name they control to `127.0.0.1`, and the browser treats
requests to it as same-origin.

Script cannot set the `Host` header, so checking it defeats the attack. The API
now answers only for `localhost`, `127.0.0.1`, `::1`, bare IP literals, and the
compose service names. Anything else gets a 403 naming the fix.

> **If you reach the tool by a hostname** — `http://myworkstation:8080` rather
> than `localhost` — set `ALLOWED_HOSTS=myworkstation` in `docker-compose.yml`.
> `ALLOWED_HOSTS=*` disables the check for a deployment behind a proxy that
> rewrites `Host`. The 403 body says this, so the failure is loud and
> self-explaining rather than silent.

Pinned by `TestHostCheckBlocksDNSRebinding`, `TestHostCheckAllowsTheRealDeployments`.

### 2.3 Unbounded XML recursion → fatal process crash — **High** — fixed

`ConfigNode.decode` recursed once per element nesting level with no limit. Go
grows a goroutine stack to 1 GB and then kills the **process** with
`goroutine stack exceeds` — a fatal runtime error, not a recoverable panic. So a
config file of a few hundred thousand nested open tags, which compresses to
almost nothing inside an uploaded archive, would take down the whole API and
every other in-flight request with it.

**Fixed:** depth capped at 512 (`ErrXMLTooDeep`). Real PAN-OS configs nest around
15 levels; the deepest observed across our sample archives is under 30.

Go's `encoding/xml` does not expand DTD entities, so billion-laughs does not
apply.

Pinned by `TestDeeplyNestedXMLIsRejectedNotFatal`, `TestRealisticNestingStillParses`.

### 2.4 Decompression bombs — **Medium/High** — fixed

The 512 MiB upload cap bounds *compressed* bytes. Gzip reaches ~1000:1 on
repetitive input, so 10 MiB of zeroes inflates to ~10 GiB. Three paths were
uncapped:

| Path | Effect |
|---|---|
| `openTar` — every parse pass | The index pass must inflate content merely to skip to the next header. Unbounded CPU and time. |
| `ConvertZipToTgz` | Wrote the inflated stream straight to the upload volume. **Disk exhaustion.** |
| `readEntry` in config.go | `io.ReadAll` with no limit, on a size taken from an attacker-controlled tar header. **Container OOM kill.** |

**Fixed:** a 32 GiB inflated-bytes budget in `openTar`, so every pass — present
and future — inherits it; the same budget in the zip conversion, checked both
against the declared member size and against the bytes actually produced; and a
bounded `io.ReadAll` for the config.

One detail worth noting: the limiter reports `ErrArchiveTooLarge`, not `io.EOF`.
`io.LimitedReader` returns `io.EOF` at its limit, and every tar consumer here
reads `io.EOF` as "the archive ended normally" — so a bomb would have been
reported as a short but perfectly valid archive, and partial results would have
been presented as complete. Silently wrong output is worse than a refused
upload.

Pinned by `TestGzipBombIsCappedNotSilentlyTruncated`, `TestZipBombIsRejected`,
`TestConfigReadIsBounded`.

### 2.5 No HTTP server timeouts — **Medium** — fixed

`http.ListenAndServe` applies none. A client sending request headers one byte at
a time holds a goroutine and a file descriptor indefinitely — slowloris.

**Fixed:** `ReadHeaderTimeout: 20s` closes that hole. `ReadTimeout` and
`WriteTimeout` are 30 minutes rather than absent, because real requests here are
legitimately long: a 512 MiB upload over a slow link, or a search that runs to
its 20-second deadline and then streams a large result. `MaxHeaderBytes: 1 MiB`.

### 2.6 Missing response headers — **Low** — fixed

nginx now sends a CSP with no `unsafe-eval` and no remote origins (the build is
fully self-contained — one bundle, one stylesheet, no CDN), plus `nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a `Permissions-Policy`,
and `server_tokens off`. The API sets the same three headers itself, before any
early return, so a 403 carries them too.

`style-src` needs `unsafe-inline`: dygraphs positions its canvas layers with
inline style attributes.

---

## 3. Reviewed and found sound

These were checked and needed no change. Recorded so the next review does not
have to rediscover them.

**No zip-slip or tar-slip.** Archive member names never reach the filesystem.
The only writes are `<id>.tgz` and `<id>.tgz.sblob`, both named from a
`crypto/rand` identifier. Names like `../../../../etc/passwd` survive as opaque
map keys and display strings, which is harmless. `TestArchiveMemberNamesNeverReachTheFilesystem`
pins this so that a future change which starts extracting to disk has to
confront it.

**No XSS.** No `dangerouslySetInnerHTML`, no `innerHTML`, no `eval` anywhere in
the frontend. React escapes log text, config values and file paths by default.
The API serves archive content as `text/plain; charset=utf-8`, so a log line
containing markup is not interpreted even when the URL is opened directly.

**No ReDoS.** Go's `regexp` is RE2 — linear time, no backtracking — so a
user-supplied search pattern cannot be made to blow up. This was a deliberate
constraint, and it is also why signatures use an explicit `Exclude` field instead
of negative lookahead.

**No XXE.** `encoding/xml` does not resolve external entities.

**Identifiers are unguessable.** `crypto/rand`, 128 bits, hex-encoded. Not
that it matters much while there is no auth, but it stops a URL being guessed
from another.

**Upload is type-checked by content, not extension.** `LooksLikeZip` reads the
magic bytes.

**Memory is bounded per parse.** `parseSlot` (capacity 1) serialises archive
parsing, `GOMEMLIMIT` 3 GiB sits under `mem_limit` 4 GiB, the search blob is
capped at 6 GiB and the postings budget at ~96 MB.

**Container runs as non-root.** `adduser -D app`, `USER app`, static binary,
`CGO_ENABLED=0`.

---

## 4. Knowingly open

| Issue | Position |
|---|---|
| **No authentication or authorization** | Anyone who can reach the port can upload, read and delete every archive. Acceptable on a laptop or a trusted internal host; a blocker for a shared deployment. This is the single largest gap and it is a product decision, not an oversight. |
| **No TLS** | Plain HTTP. Terminate TLS at a reverse proxy if this is ever exposed beyond localhost. |
| **No quotas or rate limiting** | One user can fill the upload volume with legitimate archives. |
| **Archives are not encrypted at rest** | They sit on a Docker volume as uploaded. |
| **No audit log** | Uploads and deletes are logged to stdout; nothing is retained. |
| **Lockfile not yet committed** | Run `npm install` and commit `package-lock.json`. |

The first item governs the rest: none of them matter much for a local tool, and
all of them matter before this becomes a shared service. That decision is the one
worth making explicitly.

---

## 5. Verifying

```bash
bash .verify/all.sh          # 9 static checks, no Go toolchain needed
cd backend && go vet ./... && go test ./...
cd frontend && npm install && npm run build
```

Security-specific tests live in `backend/internal/api/security_test.go` and
`backend/internal/parser/security_test.go`.

## 6. Reporting

Open a private issue, or contact the maintainer directly. Please do not file a
public issue for anything affecting data confidentiality.
