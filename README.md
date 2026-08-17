# PAN TechSupport Analyzer

Browser-based tool to upload, parse, and analyze Palo Alto Networks firewall tech-support files (`.tgz`).

## Architecture

```
browser ── nginx ──► api (Go) ──► postgres + timescaledb   (metadata, parsed values, counter time-series)
                       │     ──► minio                     (raw .tgz blobs)
                       └────────► redis ──► worker (Go)    (async extraction + regex parsers)
```

- **api** — Go HTTP API: uploads, file registry, parsed-data queries, graph data
- **worker** — Go: extracts `.tgz`, runs pluggable regex parsers, writes results to DB
- **postgres (TimescaleDB)** — file metadata, system info, logs index, counter hypertables
- **minio** — S3-compatible object storage for raw uploads
- **redis** — job queue (asynq)
- **frontend** — React + TypeScript (Vite), tabs: System Info · Logs · Graphs · Config · My Files

> **Current state (vs. target above).** The diagram is the target. As built today,
> the **api** is the only backend process doing real work: it stores raw `.tgz` files
> on a **local disk volume** (not MinIO), keeps the file registry and all parsed data
> in an **in-memory store** (not Postgres/TimescaleDB), and runs the parsers **inline
> in a goroutine** right after upload (not via Redis/asynq in the **worker**, which is
> still a stub). The store sits behind a `store.Store` interface so a Postgres-backed
> implementation can drop in without touching the API or parsers. The Go backend is
> currently **stdlib-only** (empty `go.mod` dependencies).

### Search syntax

```
ospf AND down             AND / OR / NOT, also && || !, with parentheses
"exact phrase"            quoted terms match literally; bare terms are regexes
failed -A 3 -B 2          grep-style context lines after / before a match
pkt_recv | $2 > 10000     awk-style field filter on the lines found
sessions | -F',' $3 > 500 …with an explicit separator
```

The pipe clause is the `| awk` half: `$1`, `$2`… are fields counted **from the
message**, with a leading timestamp and severity/subsystem label skipped, so on
`2026/08/04 21:00:20 medium general pkt_recv 4523` `$1` is `pkt_recv` and `$2` is
`4523`. `$0` is the whole line. Operators are `> >= < <= == != ~ !~`, combined with
`AND` / `OR`. Values carrying units parse as numbers (`1400000kB`, `85%`, `4523,`).

Fields are whitespace-separated by default. `-F` changes that, following awk's own
rule: one character is a literal separator, anything longer is a regular expression,
and a space means runs of whitespace.

```
sessions | -F',' $3 > 500        comma-separated
route    | -F: $2 ~ down         colon; quotes optional
counters | -F'\t' $2 > 1000      tab
route    | -F'\s*:\s*' $2 ~ down separator with padding, as a regex
```

`-F` changes only what a field *is*, never where the message starts, so field numbers
mean the same thing with or without it. Empty fields are preserved (`a,,b` has three,
so numbering does not shift across a gap) and each field is trimmed.

Like the pipeline it imitates, the filter applies to matched lines **and** their
`-A`/`-B` context, so `pkt_recv -A 10 | $2 > 10000` works when the match is a section
header and the values are underneath it: the header is kept as the anchor, dimmed,
and the block disappears only if nothing in it survives. A clause that cannot be
parsed is ignored entirely rather than half-applied, and the UI says so.

### Search index

Searching the `.tgz` directly meant inflating the whole archive per query, which
made broad searches time out. Parsing now builds two artefacts up front:

- a **blob** (`<archive>.sblob`, beside the upload) holding every text file's bytes
  uncompressed, with a span table — searching a file becomes a read at an offset;
- a **trigram index** mapping each 3-byte sequence to the files containing it, so a
  query's required trigrams narrow thousands of files to the few that could match.

The index may only *narrow* a search. Anything the planner cannot prove is required
— alternation, `NOT`, a bare character class — degrades to "every file is a
candidate", and equivalence tests assert the indexed path returns exactly what a full
scan returns. If the blob is missing, search falls back to scanning the archive.

Cost: the blob is roughly the uncompressed size of the archive (a 100 MB `.tgz` is
around 1 GB), stored in the `upload-data` volume and deleted with its file. Stale
blobs are cleared at startup, since the in-memory registry does not survive a restart.

## Quickstart (dev)

```bash
cp .env.example .env
docker compose up --build
# frontend: http://localhost:8080   api: http://localhost:8081/healthz
```

Without Docker:

```bash
cd backend && go run ./cmd/api      # api on :8081
cd frontend && npm install && npm run dev
```

## Roadmap

Legend: `[x]` done · `[~]` partial (works in-memory; production backing store still pending) · `[ ]` not started

- [x] Phase 1 — scaffold, CI, stub upload endpoint, frontend shell
- [~] Phase 2 — file registry + upload storage
  - [x] file registry behind `store.Store` interface, upload/list/get/delete API
  - [ ] back the registry with Postgres and move raw blobs to MinIO (today: in-memory + local disk)
- [~] Phase 3 — extraction + system-info parser
  - [x] archive indexer, `show system info` extractor (version, serial, licenses, …)
  - [ ] move extraction into the **worker** via Redis/asynq (today: inline goroutine in the api)
- [x] Phase 4 — log viewer + log parsing (archive browser, search, monitor-log structurer, time-range filter, virtualized viewer)
- [~] Phase 5 — counters → graphs
  - [x] counter parsers (global/per-task/CPU/cache/ifconfig/memory/logrcvr/netstat) and ECharts plotting
  - [ ] persist counters to a TimescaleDB hypertable (today: in-memory series)
- [ ] Phase 6 — config tab, cascade delete, auth/quotas

## Repository layout

```
backend/    Go API (active) + worker (stub). Currently stdlib-only;
            pgx/asynq/minio land when Phases 2–3 move off the in-memory store.
frontend/   React + TS (Vite)
.github/    CI pipeline
```
