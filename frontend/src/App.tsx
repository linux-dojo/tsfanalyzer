import { useEffect, useMemo, useRef, useState } from "react";
import * as echarts from "echarts";

type Tab = "system" | "logs" | "graphs" | "config";

interface TsFile {
  id: string;
  filename: string;
  size_bytes: number;
  status: string; // parsing | parsed | failed
  error?: string;
  uploaded_at: string;
}

interface KV {
  key: string;
  value: string;
}

interface Entry {
  path: string;
  size: number;
}

interface SearchResult {
  type: "file" | "line";
  path: string;
  line_no?: number;
  text?: string;
}

interface LogEntryRow {
  ts: string;
  label: string;
  msg: string;
}

interface ViewItem {
  path: string;
  line?: number; // jump target from a search hit
}

const TABS: { id: Tab; label: string }[] = [
  { id: "system", label: "System Info" },
  { id: "logs", label: "Log Files" },
  { id: "graphs", label: "Graphs" },
  { id: "config", label: "Config" },
];

export default function App() {
  const logs = window.location.pathname.match(/^\/files\/([0-9a-f]+)\/logs$/);
  if (logs) return <LogViewerPage fileId={logs[1]} />;
  const m = window.location.pathname.match(/^\/files\/([0-9a-f]+)$/);
  if (m) return <FileView id={m[1]} />;
  return <FilesPage />;
}

/* ---------- landing page: file list + upload ---------- */

function FilesPage() {
  const [files, setFiles] = useState<TsFile[]>([]);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = () =>
    fetch("/api/v1/files")
      .then((r) => r.json())
      .then((d) => setFiles(d.files ?? []))
      .catch(() => setError("API unreachable"));

  useEffect(() => {
    refresh();
  }, []);

  // poll while anything is still parsing
  const parsing = files.some((f) => f.status === "parsing");
  useEffect(() => {
    if (!parsing) return;
    const t = setInterval(refresh, 1500);
    return () => clearInterval(t);
  }, [parsing]);

  const upload = (f: File) => {
    setError(null);
    setProgress(0);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/v1/files");
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) setProgress(Math.round((e.loaded / e.total) * 100));
    };
    xhr.onload = () => {
      setProgress(null);
      if (xhr.status !== 201) {
        try {
          setError(JSON.parse(xhr.responseText).error ?? "upload failed");
        } catch {
          setError("upload failed");
        }
      }
      refresh();
    };
    xhr.onerror = () => {
      setProgress(null);
      setError("upload failed — network error");
    };
    const fd = new FormData();
    fd.append("file", f);
    xhr.send(fd);
  };

  const del = async (id: string) => {
    await fetch(`/api/v1/files/${id}`, { method: "DELETE" });
    refresh();
  };

  return (
    <div className="page">
      {progress !== null && (
        <div className="progress-track">
          <div className="progress-fill" style={{ width: `${progress}%` }} />
        </div>
      )}
      <main className="content">
        <h1 className="brand">PAN TechSupport Analyzer</h1>
        <h2>My Files</h2>
        <label className="upload">
          {progress !== null ? `Uploading… ${progress}%` : "Upload .tgz"}
          <input
            type="file"
            accept=".tgz,.tar.gz"
            hidden
            disabled={progress !== null}
            onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])}
          />
        </label>
        {error && <p className="error">{error}</p>}
        <table>
          <thead>
            <tr>
              <th>Filename</th>
              <th>Size</th>
              <th>Status</th>
              <th>Uploaded</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {files.map((f) => (
              <tr key={f.id}>
                <td>
                  {f.status === "parsed" ? (
                    <a className="file-link" href={`/files/${f.id}`}>
                      {f.filename}
                    </a>
                  ) : (
                    f.filename
                  )}
                </td>
                <td>{(f.size_bytes / 1024 / 1024).toFixed(1)} MB</td>
                <td>
                  <StatusIcon status={f.status} error={f.error} />
                  {f.status === "failed" && f.error && (
                    <div className="parse-err">{f.error}</div>
                  )}
                </td>
                <td>{new Date(f.uploaded_at).toLocaleString()}</td>
                <td>
                  <button onClick={() => del(f.id)}>Delete</button>
                </td>
              </tr>
            ))}
            {files.length === 0 && (
              <tr>
                <td colSpan={5}>No files uploaded yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </main>
    </div>
  );
}

function StatusIcon({ status, error }: { status: string; error?: string }) {
  if (status === "parsing") return <span className="spinner" title="Parsing…" />;
  if (status === "parsed") return <span className="status-ok" title="Parsed">✓</span>;
  if (status === "failed")
    return <span className="status-fail" title={error || "Parsing failed"}>✕</span>;
  return <span title={status}>•</span>;
}

/* ---------- per-file view: sidebar tabs ---------- */

function FileView({ id }: { id: string }) {
  const [file, setFile] = useState<TsFile | null>(null);
  const [tab, setTab] = useState<Tab>("system");
  const [missing, setMissing] = useState(false);

  useEffect(() => {
    fetch(`/api/v1/files/${id}`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then(setFile)
      .catch(() => setMissing(true));
  }, [id]);

  if (missing) {
    return (
      <div className="page">
        <main className="content">
          <h2>File not found</h2>
          <p>
            <a className="file-link" href="/">← Back to My Files</a>
          </p>
        </main>
      </div>
    );
  }

  return (
    <div className="layout">
      <aside className="sidebar">
        <h1>PAN-TS</h1>
        <a className="back-link" href="/">← My Files</a>
        <div className="sidebar-file" title={file?.filename}>
          {file?.filename ?? "…"}
        </div>
        {TABS.map((t) => (
          <button
            key={t.id}
            className={tab === t.id ? "active" : ""}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </aside>
      <main className="content">
        {tab === "system" && <SystemInfo fileId={id} />}
        {tab === "logs" && <LogFiles fileId={id} />}
        {tab === "graphs" && <Graphs fileId={id} />}
        {tab === "config" && <Placeholder name="Config" phase={6} />}
      </main>
    </div>
  );
}

/* ---------- Graphs tab ---------- */

interface CounterMeta {
  name: string;
  points: number;
}

interface CounterPoint {
  name: string;
  ts: string;
  value: number;
}

const MAX_PLOT = 8;

function Graphs({ fileId }: { fileId: string }) {
  const [counters, setCounters] = useState<CounterMeta[]>([]);
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [series, setSeries] = useState<Record<string, CounterPoint[]> | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const chartRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    fetch(`/api/v1/files/${fileId}/counters`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => setCounters(d.counters ?? []))
      .catch(() => setErr("No counters available — was a dp/mp-monitor.log present in this archive?"));
  }, [fileId]);

  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase();
    const list = f
      ? counters.filter((c) => c.name.toLowerCase().includes(f))
      : counters;
    return list.slice(0, 400);
  }, [counters, filter]);

  const toggle = (name: string) =>
    setSelected((s) =>
      s.includes(name)
        ? s.filter((n) => n !== name)
        : s.length >= MAX_PLOT
          ? s
          : [...s, name]
    );

  const plot = () => {
    const q = new URLSearchParams({ names: selected.join("|") });
    if (from) q.set("from", from);
    if (to) q.set("to", to);
    setErr(null);
    fetch(`/api/v1/files/${fileId}/counters/data?${q.toString()}`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => setSeries(d.series ?? {}))
      .catch(() => setErr("Could not load counter data."));
  };

  useEffect(() => {
    if (!chartRef.current || !series) return;
    const chart = echarts.init(chartRef.current);
    chart.setOption({
      tooltip: { trigger: "axis" },
      legend: { type: "scroll", top: 0 },
      grid: { left: 70, right: 30, top: 40, bottom: 70 },
      xAxis: { type: "time" },
      yAxis: { type: "value" },
      dataZoom: [{ type: "inside" }, { type: "slider", bottom: 10 }],
      series: Object.entries(series).map(([name, pts]) => ({
        name,
        type: "line",
        showSymbol: false,
        data: (pts ?? []).map((p) => [p.ts, p.value]),
      })),
    });
    const onResize = () => chart.resize();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      chart.dispose();
    };
  }, [series]);

  return (
    <section>
      <h2>Graphs</h2>
      {err && <p className="error">{err}</p>}
      <div className="graph-layout">
        <div className="graph-picker">
          <input
            className="file-filter"
            type="search"
            placeholder={`Filter ${counters.length.toLocaleString()} counters…`}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <div className="picker-list graph-counter-list">
            {shown.map((c) => (
              <label key={c.name} className="counter-row">
                <input
                  type="checkbox"
                  checked={selected.includes(c.name)}
                  disabled={!selected.includes(c.name) && selected.length >= MAX_PLOT}
                  onChange={() => toggle(c.name)}
                />
                <span title={`${c.points} samples`}>{c.name}</span>
              </label>
            ))}
            {shown.length === 0 && <p className="muted">No matching counters</p>}
          </div>
          <div className="picker-time">
            <label>
              From
              <input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} />
            </label>
            <label>
              To
              <input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} />
            </label>
          </div>
          <button
            className="dropdown-btn"
            disabled={selected.length === 0}
            onClick={plot}
          >
            Plot {selected.length}/{MAX_PLOT} selected
          </button>
        </div>
        <div className="graph-area">
          <div ref={chartRef} className="graph-canvas" />
          {!series && <p className="muted">Select counters on the left and click Plot.</p>}
        </div>
      </div>
    </section>
  );
}

function Placeholder({ name, phase }: { name: string; phase: number }) {
  return (
    <section>
      <h2>{name}</h2>
      <p>Coming in phase {phase}.</p>
    </section>
  );
}

const prettyKey = (k: string) =>
  k.replace(/[-_]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

const fmtSize = (n: number) =>
  n >= 1024 * 1024
    ? (n / 1024 / 1024).toFixed(1) + " MB"
    : n >= 1024
      ? (n / 1024).toFixed(1) + " KB"
      : n + " B";

/* ---------- Log Files tab ---------- */

function LogFiles({ fileId }: { fileId: string }) {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [open, setOpen] = useState(false);
  const [minimized, setMinimized] = useState(false);
  const [cwd, setCwd] = useState(""); // "" = archive root
  const [selected, setSelected] = useState<string[]>([]);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [viewItems, setViewItems] = useState<ViewItem[]>([]);
  const [maximized, setMaximized] = useState(false);
  const [fileFilter, setFileFilter] = useState("");

  useEffect(() => {
    fetch(`/api/v1/files/${fileId}/archive`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => setEntries(d.entries ?? []))
      .catch(() => setEntries([]));
  }, [fileId]);

  // files at/below cwd (root shows everything)
  const visible = entries
    .filter((e) => cwd === "" || e.path === cwd || e.path.startsWith(cwd + "/"))
    .sort((a, b) => a.path.localeCompare(b.path));

  // immediate subfolders of cwd
  const folders = Array.from(
    new Set(
      visible
        .map((e) => (cwd === "" ? e.path : e.path.slice(cwd.length + 1)))
        .filter((rel) => rel.includes("/"))
        .map((rel) => rel.split("/")[0])
    )
  ).sort();

  const relPath = (p: string) => (cwd === "" ? p : p.slice(cwd.length + 1));

  const MAX_OPEN_FILES = 10;

  const toggle = (path: string) =>
    setSelected((s) =>
      s.includes(path)
        ? s.filter((p) => p !== path)
        : s.length >= MAX_OPEN_FILES
          ? s
          : [...s, path]
    );

  const timeQuery = () => {
    const q = new URLSearchParams();
    if (from) q.set("from", from);
    if (to) q.set("to", to);
    return q;
  };

  const openSameTab = () => {
    setViewItems(selected.map((p) => ({ path: p })));
    setMinimized(true);
    setMaximized(true);
  };

  const openNewTab = () => {
    const q = timeQuery();
    q.set("paths", selected.join("|"));
    window.open(`/files/${fileId}/logs?${q.toString()}`, "_blank");
  };

  const openFromSearch = (path: string, line?: number) => {
    setViewItems((v) => [...v.filter((it) => it.path !== path), { path, line }]);
  };

  return (
    <section>
      <h2>Log Files</h2>
      <ArchiveSearch fileId={fileId} onOpen={openFromSearch} />
      <button className="dropdown-btn" onClick={() => { setOpen(!open); setMinimized(false); }}>
        Select log files {open ? "▴" : "▾"}
      </button>

      {open && minimized && (
        <div className="minimized-bar">
          <span>
            {viewItems.length} file{viewItems.length === 1 ? "" : "s"} open
            {from || to ? " (time-filtered)" : ""}
          </span>
          <button onClick={() => setMinimized(false)}>Expand</button>
        </div>
      )}

      {open && !minimized && (
        <div className="picker">
          <div className="picker-time">
            <label>
              From
              <input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} />
            </label>
            <label>
              To
              <input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} />
            </label>
            {(from || to) && (
              <button className="link-btn" onClick={() => { setFrom(""); setTo(""); }}>
                clear
              </button>
            )}
          </div>

          <div className="picker-cols">
            <div className="picker-col">
              <h3>Folder Location</h3>
              <button className="nav-btn" onClick={() => setCwd(cwd.split("/").slice(0, -1).join("/"))} disabled={cwd === ""}>
                ..
              </button>
              <button className="nav-btn" onClick={() => setCwd("")} disabled={cwd === ""}>
                /
              </button>
              <div className="picker-path">/{cwd}</div>
              <div className="picker-list">
                {folders.map((f) => (
                  <button key={f} className="folder-btn" onClick={() => setCwd(cwd ? `${cwd}/${f}` : f)}>
                    📁 {f}
                  </button>
                ))}
                {folders.length === 0 && <p className="muted">No subfolders</p>}
              </div>
            </div>

            <div className="picker-col">
              <h3>File Name</h3>
              <input
                className="file-filter"
                type="search"
                placeholder="Filter files…"
                value={fileFilter}
                onChange={(e) => setFileFilter(e.target.value)}
              />
              <div className="picker-list">
                <div className="file-row file-row-head">
                  <span />
                  <span>File Size</span>
                  <span>File Name</span>
                </div>
                {visible
                  .filter(
                    (e) =>
                      !fileFilter ||
                      e.path.toLowerCase().includes(fileFilter.toLowerCase())
                  )
                  .map((e) => (
                  <label key={e.path} className="file-row">
                    <input
                      type="checkbox"
                      checked={selected.includes(e.path)}
                      disabled={
                        !selected.includes(e.path) &&
                        selected.length >= MAX_OPEN_FILES
                      }
                      onChange={() => toggle(e.path)}
                    />
                    <span className="muted">{fmtSize(e.size)}</span>
                    <span title={e.path}>{relPath(e.path)}</span>
                  </label>
                ))}
                {visible.length === 0 && <p className="muted">No files</p>}
              </div>
            </div>

            <div className="picker-col">
              <h3>
                Selected Files ({selected.length}/{MAX_OPEN_FILES})
              </h3>
              <div className="picker-list">
                {selected.map((p) => (
                  <div key={p} className="selected-row">
                    <span title={p}>{p}</span>
                    <button className="link-btn" onClick={() => toggle(p)}>✕</button>
                  </div>
                ))}
                {selected.length === 0 && <p className="muted">Check files to add them</p>}
              </div>
              <div className="picker-actions">
                <button disabled={selected.length === 0} onClick={openSameTab}>
                  Open
                </button>
                <button disabled={selected.length === 0} onClick={openNewTab}>
                  Open files in new tab
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {viewItems.length > 0 && !maximized && (
        <div className="viewer-bar">
          <span>
            {viewItems.length} file{viewItems.length === 1 ? "" : "s"} open
          </span>
          <button onClick={() => setMaximized(true)}>Maximize</button>
          <button onClick={() => setViewItems([])}>Close all</button>
        </div>
      )}

      {!maximized &&
        viewItems.map((it) => (
          <LogContent
            key={it.path}
            fileId={fileId}
            path={it.path}
            from={from}
            to={to}
            highlightLine={it.line}
          />
        ))}

      {maximized && viewItems.length > 0 && (
        <MaxViewer
          fileId={fileId}
          items={viewItems}
          from={from}
          to={to}
          onMinimize={() => setMaximized(false)}
        />
      )}
    </section>
  );
}

/* Full-page split viewer: selected files on the left, active log on the right. */
function MaxViewer({
  fileId,
  items,
  from,
  to,
  onMinimize,
}: {
  fileId: string;
  items: ViewItem[];
  from: string;
  to: string;
  onMinimize: () => void;
}) {
  const [activePath, setActivePath] = useState(items[0]?.path ?? "");
  const active = items.find((it) => it.path === activePath) ?? items[0];

  return (
    <div className="viewer-max">
      <div className="viewer-max-bar">
        <span>
          {items.length} file{items.length === 1 ? "" : "s"}
          {from || to ? " (time-filtered)" : ""}
        </span>
        <button onClick={onMinimize}>Minimize</button>
      </div>
      <div className="viewer-split">
        <aside className="viewer-files">
          {items.map((it) => (
            <button
              key={it.path}
              className={it.path === active?.path ? "active" : ""}
              onClick={() => setActivePath(it.path)}
              title={it.path}
            >
              {it.path.split("/").pop()}
            </button>
          ))}
        </aside>
        <div className="viewer-pane">
          {/* all panes stay mounted; switching is just a display toggle */}
          {items.map((it) => (
            <div
              key={it.path}
              style={{ display: it.path === active?.path ? "block" : "none" }}
            >
              <LogContent
                fileId={fileId}
                path={it.path}
                from={from}
                to={to}
                highlightLine={it.line}
              />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ArchiveSearch({
  fileId,
  onOpen,
}: {
  fileId: string;
  onOpen: (path: string, line?: number) => void;
}) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[] | null>(null);
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    if (query.trim().length < 2) {
      setResults(null);
      return;
    }
    setSearching(true);
    const t = setTimeout(() => {
      fetch(`/api/v1/files/${fileId}/search?q=${encodeURIComponent(query.trim())}`)
        .then((r) => (r.ok ? r.json() : Promise.reject()))
        .then((d) => setResults(d.results ?? []))
        .catch(() => setResults([]))
        .finally(() => setSearching(false));
    }, 500);
    return () => clearTimeout(t);
  }, [query, fileId]);

  return (
    <div className="search-wrap">
      <input
        className="search-input"
        type="search"
        placeholder="Search log files and log lines…"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      {searching && <p className="muted">Searching…</p>}
      {results !== null && !searching && (
        <div className="search-results">
          {results.map((r, i) => (
            <button
              key={i}
              className="result-row"
              onClick={() => onOpen(r.path, r.type === "line" ? r.line_no : undefined)}
              title={r.type === "line" ? `${r.path} (line ${r.line_no})` : r.path}
            >
              <span className="result-main">
                <span className="result-path">{r.path}</span>
                {r.type === "line" && (
                  <span className="result-text">
                    {r.line_no}: {r.text}
                  </span>
                )}
              </span>
              <span className={r.type === "file" ? "tag tag-file" : "tag tag-line"}>
                {r.type === "file" ? "log file" : "log line"}
              </span>
            </button>
          ))}
          {results.length === 0 && <p className="muted">No matches.</p>}
        </div>
      )}
    </div>
  );
}

const MSG_CHUNK = 160;
const ROW_H = 22; // px, fixed row height for virtualization
const PAGE_LIMIT = 50000; // lines per server page (matches backend)

interface FlatRow {
  ts: string;
  label: string;
  msg: string;
  entryIdx: number;
  first: boolean;
}

/* Fetched log content cache: keeps the last N opened files in memory so
   minimize/maximize and pane switching don't refetch. */
const CACHE_MAX_FILES = 15;
interface CacheVal {
  text?: string;
  entries?: LogEntryRow[];
  total?: number;
}
const contentCache = new Map<string, CacheVal>();

function cacheGet(key: string) {
  return contentCache.get(key);
}

function cachePut(key: string, value: CacheVal) {
  if (contentCache.has(key)) contentCache.delete(key);
  contentCache.set(key, value);
  while (contentCache.size > CACHE_MAX_FILES) {
    const oldest = contentCache.keys().next().value;
    if (oldest === undefined) break;
    contentCache.delete(oldest);
  }
}

function LogContent({
  fileId,
  path,
  from,
  to,
  highlightLine,
}: {
  fileId: string;
  path: string;
  from: string;
  to: string;
  highlightLine?: number;
}) {
  const [text, setText] = useState<string | null>(null);
  const [entries, setEntries] = useState<LogEntryRow[] | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(() =>
    highlightLine ? Math.floor((highlightLine - 1) / PAGE_LIMIT) * PAGE_LIMIT : 0
  );
  const [err, setErr] = useState<string | null>(null);
  const [structured, setStructured] = useState(true);
  const [scrollTop, setScrollTop] = useState(0);
  const viewRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const cacheKey = [fileId, path, from, to, structured ? "t" : "r", offset].join("|");
    const hit = cacheGet(cacheKey);
    setErr(null);
    if (hit) {
      setText(hit.text ?? null);
      setEntries(hit.entries ?? null);
      setTotal(hit.total ?? hit.entries?.length ?? 0);
      return;
    }
    setText(null);
    setEntries(null);

    const q = new URLSearchParams({ path });
    if (from) q.set("from", from);
    if (to) q.set("to", to);

    if (structured) {
      q.set("format", "structured");
      q.set("offset", String(offset));
      fetch(`/api/v1/files/${fileId}/content?${q.toString()}`)
        .then((r) => (r.ok ? r.json() : Promise.reject()))
        .then((d) => {
          const entries = d.entries ?? [];
          const total = d.total ?? entries.length;
          cachePut(cacheKey, { entries, total });
          setEntries(entries);
          setTotal(total);
        })
        .catch(() => setErr("Could not load file."));
    } else {
      fetch(`/api/v1/files/${fileId}/content?${q.toString()}`)
        .then((r) => (r.ok ? r.text() : Promise.reject()))
        .then((t) => {
          cachePut(cacheKey, { text: t });
          setText(t);
        })
        .catch(() => setErr("Could not load file."));
    }
  }, [fileId, path, from, to, structured, offset]);

  // follow the highlight to the right page when a new search hit targets
  // an already-open file
  useEffect(() => {
    if (highlightLine !== undefined) {
      setOffset(Math.floor((highlightLine - 1) / PAGE_LIMIT) * PAGE_LIMIT);
    }
  }, [highlightLine]);

  // flatten entries into uniform-height display rows (long messages become
  // continuation rows with blank ts/label)
  const rows: FlatRow[] = useMemo(() => {
    if (!entries) return [];
    const out: FlatRow[] = [];
    entries.forEach((e, i) => {
      const chunks =
        e.msg.length > MSG_CHUNK
          ? e.msg.match(new RegExp(`.{1,${MSG_CHUNK}}`, "g")) ?? [e.msg]
          : [e.msg];
      chunks.forEach((c, j) =>
        out.push({ ts: j === 0 ? e.ts : "", label: j === 0 ? e.label : "", msg: c, entryIdx: i, first: j === 0 })
      );
    });
    return out;
  }, [entries]);

  const hlEntryIdx = highlightLine !== undefined ? highlightLine - 1 - offset : -1;
  const hlRowIdx = useMemo(
    () => (hlEntryIdx < 0 ? -1 : rows.findIndex((r) => r.entryIdx === hlEntryIdx && r.first)),
    [rows, hlEntryIdx]
  );

  // jump to the highlighted row once rows are available
  useEffect(() => {
    if (hlRowIdx >= 0 && viewRef.current) {
      const el = viewRef.current;
      el.scrollTop = Math.max(0, hlRowIdx * ROW_H - el.clientHeight / 2);
      setScrollTop(el.scrollTop);
    }
  }, [hlRowIdx, rows.length]);

  // virtual window: render only rows in (and around) the viewport
  const viewH = viewRef.current?.clientHeight ?? 520;
  const winStart = Math.max(0, Math.floor(scrollTop / ROW_H) - 20);
  const winEnd = Math.min(rows.length, Math.ceil((scrollTop + viewH) / ROW_H) + 20);
  const padTop = winStart * ROW_H;
  const padBottom = (rows.length - winEnd) * ROW_H;

  return (
    <div className="log-block">
      <h3 className="log-title">
        <span>{path}</span>
        <button className="view-toggle" onClick={() => setStructured(!structured)}>
          {structured ? "Raw view" : "Table view"}
        </button>
      </h3>
      {err && <p className="error">{err}</p>}
      {text === null && entries === null && !err && <p className="muted">Loading…</p>}
      {!structured && text !== null && (
        <pre className="log-pre">{text || "(empty after filtering)"}</pre>
      )}
      {structured && entries !== null && (
        <div className="vt-wrap">
          {total > PAGE_LIMIT && (
            <div className="pager">
              <button disabled={offset === 0} onClick={() => setOffset(offset - PAGE_LIMIT)}>
                ‹ Prev
              </button>
              <span>
                lines {(offset + 1).toLocaleString()}–{Math.min(offset + PAGE_LIMIT, total).toLocaleString()} of {total.toLocaleString()}
              </span>
              <button
                disabled={offset + PAGE_LIMIT >= total}
                onClick={() => setOffset(offset + PAGE_LIMIT)}
              >
                Next ›
              </button>
            </div>
          )}
          <div className="vt-head">
            <span>Timestamp</span>
            <span>Label</span>
            <span>Message</span>
          </div>
          <div
            className="vt-body"
            ref={viewRef}
            onScroll={(e) => setScrollTop((e.target as HTMLDivElement).scrollTop)}
          >
            <div style={{ height: padTop }} />
            {rows.slice(winStart, winEnd).map((r, k) => (
              <div
                key={winStart + k}
                className={
                  "vt-row" + (r.entryIdx === hlEntryIdx && r.first ? " hl-vt" : "")
                }
              >
                <span className="lt-ts">{r.ts}</span>
                <span className="lt-label">{r.label}</span>
                <span className="lt-msg">{r.msg}</span>
              </div>
            ))}
            <div style={{ height: padBottom }} />
            {rows.length === 0 && (
              <p className="muted">(no entries — try Raw view or clear the time filter)</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function LogViewerPage({ fileId }: { fileId: string }) {
  const q = new URLSearchParams(window.location.search);
  const paths = (q.get("paths") ?? "").split("|").filter(Boolean);
  const from = q.get("from") ?? "";
  const to = q.get("to") ?? "";
  const [maximized, setMaximized] = useState(true);
  const items: ViewItem[] = paths.map((p) => ({ path: p }));

  if (paths.length === 0) {
    return (
      <div className="page">
        <main className="content">
          <h2>No files selected.</h2>
          <p>
            <a className="file-link" href={`/files/${fileId}`}>← Back to file</a>
          </p>
        </main>
      </div>
    );
  }

  if (maximized) {
    return (
      <MaxViewer
        fileId={fileId}
        items={items}
        from={from}
        to={to}
        onMinimize={() => setMaximized(false)}
      />
    );
  }

  return (
    <div className="page">
      <main className="content">
        <h1 className="brand">Log Viewer</h1>
        <p>
          <a className="file-link" href={`/files/${fileId}`}>← Back to file</a>
          <button className="link-btn" onClick={() => setMaximized(true)}>
            Maximize
          </button>
          {(from || to) && (
            <span className="muted"> — filtered {from && `from ${from.replace("T", " ")}`} {to && `to ${to.replace("T", " ")}`}</span>
          )}
        </p>
        {items.map((it) => (
          <LogContent key={it.path} fileId={fileId} path={it.path} from={from} to={to} />
        ))}
      </main>
    </div>
  );
}

function SystemInfo({ fileId }: { fileId: string }) {
  const [info, setInfo] = useState<KV[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    fetch(`/api/v1/files/${fileId}/system-info`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => setInfo(d.info ?? []))
      .catch(() => setErr("No system info extracted for this file."));
  }, [fileId]);

  return (
    <section>
      <h2>System Info</h2>
      {err && <p className="error">{err}</p>}
      {info && (
        <div className="kv-grid">
          {info.map((p) => (
            <div className="kv-row" key={p.key}>
              <span className="kv-key">{prettyKey(p.key)}</span>
              <span className="kv-value">{p.value || "—"}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
