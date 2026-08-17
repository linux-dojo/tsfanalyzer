import { Fragment, useEffect, useMemo, useRef, useState } from "react";
// aliased so it doesn't shadow the DOM MouseEvent the dygraphs interaction
// models are typed against
import type { MouseEvent as ReactMouseEvent } from "react";
import Dygraph from "dygraphs";
import "dygraphs/dist/dygraph.css";

type Tab = "system" | "logs" | "graphs" | "appstats" | "licenses" | "config";

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

interface ContextLine {
  line_no: number;
  text: string;
  before: boolean;
}

interface SearchResult {
  type: "file" | "line";
  path: string;
  line_no?: number;
  text?: string;
  context?: ContextLine[]; // grep-style -A / -B lines
  // matched the search but not the field filter; kept as the anchor for
  // context lines that did pass
  filtered?: boolean;
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

/* Everything the Log Files tab holds, cached per tech-support file so that
   navigating to another left-hand tab and back does not discard opened files,
   search results or the picker state. Mirrors graphStateCache. */
interface LogFilesState {
  open: boolean;
  minimized: boolean;
  cwd: string;
  selected: string[];
  from: string;
  to: string;
  viewItems: ViewItem[];
  maximized: boolean;
  fileFilter: string;
  query: string;
  results: SearchResult[] | null;
  scoped: string[]; // restrict the search to these paths
}

const logStateCache = new Map<string, LogFilesState>();

function logStateFor(fileId: string): LogFilesState {
  let st = logStateCache.get(fileId);
  if (!st) {
    st = {
      open: false, minimized: false, cwd: "", selected: [], from: "", to: "",
      viewItems: [], maximized: false, fileFilter: "", query: "",
      results: null, scoped: [],
    };
    logStateCache.set(fileId, st);
    while (logStateCache.size > GRAPH_CACHE_MAX_FILES) {
      const oldest = logStateCache.keys().next().value;
      if (oldest === undefined || oldest === fileId) break;
      logStateCache.delete(oldest);
    }
  }
  return st;
}

const TABS: { id: Tab; label: string }[] = [
  { id: "system", label: "System Info" },
  { id: "logs", label: "Log Files" },
  { id: "graphs", label: "Graphs" },
  { id: "appstats", label: "App Stats" },
  { id: "licenses", label: "Licenses" },
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
  const [collapsed, setCollapsed] = useState(false);

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
      <aside className={"sidebar" + (collapsed ? " sidebar-collapsed" : "")}>
        <button
          className="collapse-btn"
          onClick={() => setCollapsed(!collapsed)}
          title={collapsed ? "Expand navigation" : "Collapse navigation"}
        >
          {collapsed ? "»" : "«"}
        </button>
        {!collapsed && <h1>PAN-TS</h1>}
        <a className="back-link" href="/" title="Back to My Files">
          {collapsed ? "←" : "← My Files"}
        </a>
        {!collapsed && (
          <div className="sidebar-file" title={file?.filename}>
            {file?.filename ?? "…"}
          </div>
        )}
        {TABS.map((t) => (
          <button
            key={t.id}
            className={tab === t.id ? "active" : ""}
            onClick={() => setTab(t.id)}
            title={t.label}
          >
            {collapsed ? t.label[0] : t.label}
          </button>
        ))}
      </aside>
      <main className="content">
        {tab === "system" && <SystemInfo fileId={id} />}
        {tab === "logs" && <LogFiles fileId={id} />}
        {tab === "graphs" && <Graphs fileId={id} />}
        {tab === "appstats" && <AppStatsTab fileId={id} />}
        {tab === "licenses" && <LicensesTab fileId={id} />}
        {tab === "config" && <ConfigTab fileId={id} />}
      </main>
    </div>
  );
}

/* ---------- Graphs tab ---------- */

interface CounterMeta {
  name: string;
  points: number;
  min: number;
  max: number;
}

/* Lookup query parser: "<pattern> v <op> <number>" filters by value range,
   e.g. "mp__processes__.*_res_swap_sub_lazy v > 10000". A bare * in the
   pattern acts as ".*" when no other regex syntax is used. */
function parseLookup(q: string): {
  matches: (c: CounterMeta) => boolean;
} {
  let pat = q.trim();
  let pred: ((c: CounterMeta) => boolean) | null = null;

  const vm = pat.match(/^(.*?)\s+v\s*(>=|<=|!=|==?|>|<)\s*(-?\d+(?:\.\d+)?)\s*$/);
  if (vm) {
    pat = vm[1].trim();
    const op = vm[2];
    const x = parseFloat(vm[3]);
    pred = (c) => {
      switch (op) {
        case ">":  return c.max > x;
        case ">=": return c.max >= x;
        case "<":  return c.min < x;
        case "<=": return c.min <= x;
        case "=":
        case "==": return c.min <= x && c.max >= x;
        case "!=": return !(c.min === x && c.max === x);
        default:   return true;
      }
    };
  }

  let nameTest: (n: string) => boolean = () => true;
  if (pat) {
    const hasRegexMeta = /[.[\]()+?^$|{}\\]/.test(pat);
    const source = hasRegexMeta ? pat : pat.replace(/\*/g, ".*");
    try {
      const re = new RegExp(source, "i");
      nameTest = (n) => re.test(n);
    } catch {
      const lf = pat.toLowerCase();
      nameTest = (n) => n.toLowerCase().includes(lf);
    }
  }

  return { matches: (c) => nameTest(c.name) && (pred === null || pred(c)) };
}

/* The counter name is the key of the series map, so points don't repeat it.
   Dropping it shrank both the API payload and the server's memory use
   substantially on archives with tens of thousands of counters. */
interface CounterPoint {
  ts: string;
  value: number;
}

/* With ~30k counters in an archive, capping a panel at 8 series was the wrong
   trade-off. The only remaining limit is a high guard against plotting so
   many series that the browser stalls. */
const MAX_PLOT = 400;
// counters requested per API call (the endpoint accepts a bounded list)
const COUNTER_FETCH_BATCH = 25;
// rows rendered in the lookup list; the filter narrows things down first
const LOOKUP_LIST_MAX = 500;
// most matches that may be added in one click, and only when a filter is set
const BULK_ADD_MAX = 50;

// shadcn-style chart palette
const CHART_COLORS = [
  "#2563eb", "#16a34a", "#ea580c", "#9333ea",
  "#0891b2", "#dc2626", "#ca8a04", "#db2777",
];

interface ReadoutRow {
  name: string;
  color: string;
  value: number | null;
}

// nearest sample value at time t (binary search over sorted [ms, value] pairs)
function nearestVal(pts: [number, number][], t: number): number | null {
  if (pts.length === 0) return null;
  let lo = 0, hi = pts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (pts[mid][0] < t) lo = mid + 1;
    else hi = mid;
  }
  const b = pts[lo];
  const a = pts[Math.max(0, lo - 1)];
  return Math.abs(a[0] - t) <= Math.abs(b[0] - t) ? a[1] : b[1];
}

const fmtReadoutTs = (t: number) =>
  new Date(t).toISOString().replace("T", " ").slice(0, 19) + " UTC";

const fmtReadoutVal = (v: number) =>
  v.toLocaleString(undefined, { maximumFractionDigits: 3 });

/* ---------- shared chart behaviour ----------
   Used by every chart so panning, edge padding and resize-on-reveal work the
   same way whether you're looking at counters, anomalies or memory. */

// Inset the plotted data from the axes by this many pixels, so points at the
// very start and end of the window aren't half-clipped against the edge and
// are still clickable.
const CHART_X_PAD = 14;

// One pan step, as a fraction of the visible window.
const PAN_STEP = 0.25;

// Shifts [lo,hi] left or right by PAN_STEP, clamped so the window can't be
// dragged far off the end of the data (a little overshoot is allowed so the
// last point isn't pinned to the edge).
function pannedWindow(
  lo: number,
  hi: number,
  dir: -1 | 1,
  dataMin: number,
  dataMax: number
): [number, number] {
  const span = hi - lo;
  if (!(span > 0)) return [lo, hi];
  const pad = span * 0.05;
  let nlo = lo + span * PAN_STEP * dir;
  let nhi = nlo + span;
  if (nlo < dataMin - pad) {
    nlo = dataMin - pad;
    nhi = nlo + span;
  }
  if (nhi > dataMax + pad) {
    nhi = dataMax + pad;
    nlo = nhi - span;
  }
  return [nlo, nhi];
}

/* Container plumbing shared by every chart.

   dygraphs fixes its pixel width when it is constructed. All three Graphs
   sub-tabs stay mounted so their state survives switching, which means a
   chart can be built inside a display:none pane — measuring zero width and
   rendering into a sliver.

   Each chart therefore takes a `visible` prop from the pane that owns it and
   only builds while that is true. Deriving visibility from this observer was
   tried and did not hold: ResizeObserver does not dependably report a
   display:none transition, so a chart could keep a stale width with no
   notification to correct it. This hook now only handles genuine layout
   changes — window resizes and collapsing the left nav. */
function useChartContainer(chart: { current: Dygraph | null }) {
  const [el, setEl] = useState<HTMLDivElement | null>(null);

  // Only used to follow ordinary layout changes (window resize, collapsing
  // the left nav). Visibility is NOT inferred from here: ResizeObserver does
  // not reliably report a display:none transition, so a chart could stay laid
  // out against a stale width. Panes pass their visibility down explicitly.
  useEffect(() => {
    if (!el) return;
    const resize = () => {
      if (el.clientWidth > 0) chart.current?.resize();
    };
    window.addEventListener("resize", resize);
    let ro: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined") {
      ro = new ResizeObserver(resize);
      ro.observe(el);
    }
    return () => {
      window.removeEventListener("resize", resize);
      ro?.disconnect();
    };
  }, [el, chart]);

  return { el, setEl };
}

// Left / right pan buttons, rendered next to Reset zoom on every chart.
function PanControls({
  onPan,
  onReset,
}: {
  onPan: (dir: -1 | 1) => void;
  onReset: () => void;
}) {
  return (
    <span className="pan-controls">
      <button className="btn-outline" onClick={() => onPan(-1)} title="Pan left (earlier)">
        ‹
      </button>
      <button className="btn-outline" onClick={() => onPan(1)} title="Pan right (later)">
        ›
      </button>
      <button className="btn-outline" onClick={onReset} title="Show the whole time range">
        Reset zoom
      </button>
    </span>
  );
}

type SeriesMode = "val" | "del" | "rate";

interface SelEntry {
  name: string;
  mode: SeriesMode;
}

const selKey = (s: SelEntry) => (s.mode === "val" ? s.name : `${s.name} (${s.mode})`);

/* ---------- per-file graph state ----------
   Switching the left-hand nav (System Info / Log Files / Config) unmounts the
   Graphs tab, which would otherwise discard everything the user had plotted.
   Selections are kept in a module-level cache keyed by tech-support file, so
   they survive navigating around one file and are dropped only when a
   different file is opened. Series data is not cached — it is refetched for
   whatever is selected, which keeps memory bounded. */
interface PanelState {
  filter: string;
  sel: SelEntry[];
  hidden: string[];
}

interface GraphsState {
  view: "counters" | "anomalies" | "memory";
  panels: PanelState[];
  marks: Mark[];
}

const graphStateCache = new Map<string, GraphsState>();
const GRAPH_CACHE_MAX_FILES = 3;

function emptyPanel(): PanelState {
  return { filter: "", sel: [], hidden: [] };
}

function graphStateFor(fileId: string): GraphsState {
  let st = graphStateCache.get(fileId);
  if (!st) {
    st = { view: "counters", panels: [emptyPanel(), emptyPanel()], marks: [] };
    graphStateCache.set(fileId, st);
    while (graphStateCache.size > GRAPH_CACHE_MAX_FILES) {
      const oldest = graphStateCache.keys().next().value;
      if (oldest === undefined || oldest === fileId) break;
      graphStateCache.delete(oldest);
    }
  }
  // tolerate a cache entry written by an older build
  if (!st.panels || st.panels.length < 2) st.panels = [emptyPanel(), emptyPanel()];
  if (!st.marks) st.marks = [];
  return st;
}

// del = difference between consecutive samples; rate = del per second
function transformSeries(pts: CounterPoint[], mode: SeriesMode): CounterPoint[] {
  if (mode === "val") return pts;
  const out: CounterPoint[] = [];
  for (let i = 1; i < pts.length; i++) {
    const dv = pts[i].value - pts[i - 1].value;
    const dt = (Date.parse(pts[i].ts) - Date.parse(pts[i - 1].ts)) / 1000;
    out.push({
      ts: pts[i].ts,
      value: mode === "del" ? dv : dt > 0 ? dv / dt : 0,
    });
  }
  return out;
}

interface MarkRow {
  name: string;
  value: number | null;
}

interface Mark {
  ts: string;
  rows: MarkRow[];
}

interface AnomalyOccurrence {
  ts: string;
  description: string; // the original, un-normalized system-log text
}

interface AnomalyGroup {
  label: string;
  severity: string;
  subtype: string;
  count: number;
  sample: string;
  occurrences: AnomalyOccurrence[];
}

interface AnomalyMark {
  ts: string;
  label: string;
  lines: string[];
}

function Graphs({ fileId }: { fileId: string }) {
  const cached = graphStateFor(fileId);
  const [view, setViewState] = useState<"counters" | "anomalies" | "memory">(cached.view);
  const setView = (v: "counters" | "anomalies" | "memory") => {
    graphStateFor(fileId).view = v; // remembered across left-nav navigation
    setViewState(v);
  };

  // All three panes stay mounted and are hidden with CSS rather than
  // unmounted, so selected counters, marks, filters and zoom survive
  // switching tabs. dygraphs measures its container at creation time, so a
  // chart built while hidden has zero width — nudging a resize after the
  // switch makes it lay out correctly.
  useEffect(() => {
    const id = requestAnimationFrame(() => window.dispatchEvent(new Event("resize")));
    return () => cancelAnimationFrame(id);
  }, [view]);

  const pane = (k: typeof view) => ({ display: view === k ? "block" : "none" } as const);

  return (
    <section>
      <h2>Graphs</h2>
      <div className="cfg-subtabs graphs-subtabs">
        <button className={view === "counters" ? "active" : ""} onClick={() => setView("counters")}>
          Counters
        </button>
        <button className={view === "anomalies" ? "active" : ""} onClick={() => setView("anomalies")}>
          Anomalies
        </button>
        <button className={view === "memory" ? "active" : ""} onClick={() => setView("memory")}>
          Memory / OOM
        </button>
      </div>
      <div style={pane("counters")}>
        <CounterGraphs fileId={fileId} visible={view === "counters"} />
      </div>
      <div style={pane("anomalies")}>
        <AnomaliesView fileId={fileId} visible={view === "anomalies"} />
      </div>
      <div style={pane("memory")}>
        <MemoryView fileId={fileId} visible={view === "memory"} />
      </div>
    </section>
  );
}

/* ---------- Memory / OOM sub-tab ----------
   Renders the backend's memory verdict. The ordering of what's shown
   mirrors how the investigation actually goes: what the OOM log said (and
   why it doesn't name a culprit), then the available-memory trend, then
   which process's growth accounts for that decline, and only if none does,
   the kernel slab counters. */

interface OOMEvent {
  ts: string;
  invoked_by: string;
  killed: string;
  killed_pid: string;
  score?: string;
  source: string;
  raw: string;
}

interface MemSuspect {
  name: string;
  counter: string;
  counters?: string[]; // every PID's series, so a restart can be plotted end to end
  pids?: string[];
  start_kb: number;
  end_kb: number;
  peak_kb: number;
  growth_kb: number;
  pct_of_drop: number;
  restarted: boolean;
  post_restart_kb?: number;
  reclaimed_kb?: number;
}

interface MemTrend {
  counter: string;
  start_kb: number;
  end_kb: number;
  min_kb: number;
  drop_kb: number;
  from: string;
  to: string;
  points: number;
  span_days: number;
}

interface Finding {
  severity: string;
  title: string;
  detail: string;
}

interface MemoryAnalysis {
  oom_events: OOMEvent[];
  first_oom?: OOMEvent;
  trend?: MemTrend;
  suspects: MemSuspect[];
  kernel_suspects: MemSuspect[];
  kernel_likely: boolean;
  explained_pct: number;
  duplicates: string[];
  findings: Finding[];
}

interface MemoryReport {
  mp: MemoryAnalysis;
  dp: MemoryAnalysis;
  config: Finding[];
}

const fmtKB = (kb: number | null | undefined) => {
  if (kb === null || kb === undefined || !Number.isFinite(kb)) return "—";
  const abs = Math.abs(kb);
  if (abs >= 1024 * 1024) return (kb / 1024 / 1024).toFixed(2) + " GB";
  if (abs >= 1024) return (kb / 1024).toFixed(1) + " MB";
  return Math.round(kb).toLocaleString() + " kB";
};

const fmtPct = (v: number | null | undefined, digits = 1) =>
  v === null || v === undefined || !Number.isFinite(v) ? "—" : v.toFixed(digits) + "%";

/* Go marshals nil slices as JSON null, so an archive with (say) no OOM
   events arrives as `oom_events: null`. Normalizing once on receipt keeps
   every render path below free of null checks. */
function normalizeAnalysis(a: Partial<MemoryAnalysis> | null | undefined): MemoryAnalysis {
  return {
    oom_events: a?.oom_events ?? [],
    first_oom: a?.first_oom,
    trend: a?.trend,
    suspects: a?.suspects ?? [],
    kernel_suspects: a?.kernel_suspects ?? [],
    kernel_likely: a?.kernel_likely ?? false,
    explained_pct: a?.explained_pct ?? 0,
    duplicates: a?.duplicates ?? [],
    findings: a?.findings ?? [],
  };
}

function normalizeReport(r: Partial<MemoryReport> | null | undefined): MemoryReport {
  return {
    mp: normalizeAnalysis(r?.mp),
    dp: normalizeAnalysis(r?.dp),
    config: r?.config ?? [],
  };
}

function MemoryView({ fileId, visible }: { fileId: string; visible: boolean }) {
  const [rep, setRep] = useState<MemoryReport | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [plane, setPlane] = useState<"mp" | "dp">("mp");

  useEffect(() => {
    fetch(`/api/v1/files/${fileId}/memory`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => setRep(normalizeReport(d.memory)))
      .catch(() => setErr("No memory analysis for this file — counters and logs may not have parsed."));
  }, [fileId]);

  if (err) return <p className="error">{err}</p>;
  if (!rep) return <p className="muted">Loading…</p>;

  const a = plane === "mp" ? rep.mp : rep.dp;
  // every PID of each top suspect, so a restart shows as a continuous story
  // on the chart rather than a series that just stops
  const plotSuspects = a.suspects.slice(0, 3);

  return (
    <div className="mem-wrap">
      <div className="cfg-subtabs">
        <button className={plane === "mp" ? "active" : ""} onClick={() => setPlane("mp")}>
          Management plane
        </button>
        <button className={plane === "dp" ? "active" : ""} onClick={() => setPlane("dp")}>
          Dataplane
        </button>
      </div>

      {a.oom_events.length > 0 ? (
        <div className="mem-card">
          <h3>
            OOM events ({a.oom_events.length})
            {a.oom_events.length > 1 && <span className="mem-sub muted">first event highlighted</span>}
          </h3>
          <div className="cfg-table-wrap">
            <table className="cfg-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th title="The process that asked for memory next — not the cause">Requested by</th>
                  <th title="Chosen by OOM score — usually not the cause either">Killed</th>
                  <th>Score</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {a.oom_events.map((e, i) => (
                  <tr key={i} className={i === 0 ? "mem-first-oom" : ""}>
                    <td>{e.ts && !e.ts.startsWith("0001") ? new Date(e.ts).toLocaleString() : "—"}</td>
                    <td>{e.invoked_by || "—"}</td>
                    <td>{e.killed ? `${e.killed}${e.killed_pid ? ` (${e.killed_pid})` : ""}` : "—"}</td>
                    <td>{e.score || "—"}</td>
                    <td className="mem-src" title={e.raw}>{e.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="mem-card">
          <h3>OOM events</h3>
          <p className="muted">None found in this archive.</p>
        </div>
      )}

      {a.trend && (
        <div className="mem-card">
          <h3>
            Available memory
            <span className="mem-sub muted">{a.trend.counter}</span>
          </h3>
          <div className="mem-stats">
            <Stat label="Start" value={fmtKB(a.trend.start_kb)} />
            <Stat label="End" value={fmtKB(a.trend.end_kb)} />
            <Stat label="Low point" value={fmtKB(a.trend.min_kb)} />
            <Stat
              label="Net change"
              value={(a.trend.drop_kb > 0 ? "−" : "+") + fmtKB(Math.abs(a.trend.drop_kb))}
              bad={a.trend.drop_kb > 0}
            />
            <Stat label="Window" value={(a.trend.span_days ?? 0).toFixed(1) + " days"} />
          </div>
          <MemoryTrendChart
            fileId={fileId}
            trendCounter={a.trend.counter}
            suspects={plotSuspects}
            visible={visible}
          />
        </div>
      )}

      <div className="mem-card">
        <h3>
          Suspect processes
          <span className="mem-sub muted">
            by growth and memory reclaimed at restart · user-space explains {fmtPct(a.explained_pct)} of the decline
          </span>
        </h3>
        <SuspectTable
          suspects={a.suspects}
          showRestart
          empty="No process shows growth that accounts for the decline."
        />
      </div>

      {(a.kernel_likely || a.kernel_suspects.length > 0) && (
        <div className="mem-card">
          <h3>
            Kernel memory
            {a.kernel_likely && <span className="sev sev-high">likely source</span>}
          </h3>
          <SuspectTable suspects={a.kernel_suspects} empty="No kernel-side growth measured." />
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, bad }: { label: string; value: string; bad?: boolean }) {
  return (
    <div className="mem-stat">
      <span className="mem-stat-label">{label}</span>
      <span className={"mem-stat-value" + (bad ? " mem-stat-bad" : "")}>{value}</span>
    </div>
  );
}

function SuspectTable({
  suspects,
  empty,
  showRestart,
}: {
  suspects: MemSuspect[];
  empty: string;
  showRestart?: boolean;
}) {
  if (suspects.length === 0) return <p className="muted">{empty}</p>;
  const maxGrowth = Math.max(...suspects.map((s) => Math.abs(s.growth_kb)), 1);
  return (
    <div className="cfg-table-wrap">
      <table className="cfg-table">
        <thead>
          <tr>
            <th>Name</th>
            <th title="Growth, or memory handed back at restart — whichever is larger">Leak evidence</th>
            <th>Share of decline</th>
            <th>Peak</th>
            {showRestart && (
              <>
                <th title="Level it settled at after its last restart">After restart</th>
                <th title="Peak minus the post-restart level: memory it was holding but did not need">Reclaimed</th>
              </>
            )}
            <th>Start → End</th>
            {showRestart && <th title="All PIDs seen for this process in the window">PIDs</th>}
          </tr>
        </thead>
        <tbody>
          {suspects.map((s, i) => {
            // optional under strictNullChecks: coalesce before comparing
            const reclaimed = s.restarted ? s.reclaimed_kb ?? 0 : 0;
            return (
            <tr key={s.counter + i}>
              <td className="cfg-name">
                {s.name}
                {s.restarted && (
                  <span className="mem-restart" title="PID changed or resident memory fell sharply mid-window">
                    restarted
                  </span>
                )}
              </td>
              <td className="mem-growth">
                <span className="mem-bar" style={{ width: `${(Math.abs(s.growth_kb) / maxGrowth) * 100}%` }} />
                <span className="mem-growth-val">+{fmtKB(s.growth_kb)}</span>
              </td>
              <td>{s.pct_of_drop > 0 ? fmtPct(s.pct_of_drop) : "—"}</td>
              <td>{fmtKB(s.peak_kb)}</td>
              {showRestart && (
                <>
                  <td>{s.restarted ? fmtKB(s.post_restart_kb) : "—"}</td>
                  <td className={reclaimed > 0 ? "mem-reclaimed" : ""}>
                    {reclaimed > 0 ? fmtKB(reclaimed) : "—"}
                  </td>
                </>
              )}
              <td className="muted">
                {fmtKB(s.start_kb)} → {fmtKB(s.end_kb)}
              </td>
              {showRestart && (
                <td className="mem-src" title={(s.counters ?? []).join("\n")}>
                  {(s.pids ?? []).join(", ") || "—"}
                </td>
              )}
            </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* Overlays available memory with the top suspect processes on one chart —
   the comparison that shows whether a process's growth really tracks the
   decline. Reuses the counters-tab chart so zoom and marking behave the same. */
function MemoryTrendChart({
  fileId,
  trendCounter,
  suspects,
  visible,
}: {
  fileId: string;
  trendCounter: string;
  suspects: MemSuspect[];
  visible: boolean;
}) {
  const [series, setSeries] = useState<Record<string, CounterPoint[]>>({});
  const [hidden, setHidden] = useState<string[]>([]);
  const [xRange, setXRange] = useState<[number, number] | null>(null);
  // Alt/Option+click marks: this was previously wired to a no-op, so the
  // shortcut silently did nothing on this tab
  const [marks, setMarks] = useState<Mark[]>([]);

  const addMark = (t: number, rows: MarkRow[]) =>
    setMarks((m) => {
      const ts = fmtReadoutTs(t);
      const idx = m.findIndex((x) => x.ts === ts);
      if (idx < 0) return [...m, { ts, rows }];
      const merged = [...m];
      const seen = new Set(merged[idx].rows.map((r) => r.name));
      merged[idx] = {
        ...merged[idx],
        rows: [...merged[idx].rows, ...rows.filter((r) => !seen.has(r.name))],
      };
      return merged;
    });

  // Every PID's series for each suspect, not just one: a restart starts a
  // new counter series, so plotting a single PID cuts the timeline exactly
  // where the before/after comparison matters. The API caps a request at 12
  // series.
  const names = useMemo(() => {
    const all = [trendCounter];
    for (const s of suspects) {
      for (const c of s.counters ?? [s.counter]) {
        if (!all.includes(c)) all.push(c);
      }
    }
    return all.slice(0, 12);
  }, [trendCounter, suspects]);

  useEffect(() => {
    if (names.length === 0) return;
    const q = names.map(encodeURIComponent).join("|");
    fetch(`/api/v1/files/${fileId}/counters/data?names=${q}`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => setSeries(d.series ?? {}))
      .catch(() => setSeries({}));
  }, [fileId, names]);

  if (Object.keys(series).length === 0) return <p className="muted">Loading chart…</p>;

  return (
    <>
      <GraphChart
        series={series}
        hidden={hidden}
        onToggle={(k) => setHidden((h) => (h.includes(k) ? h.filter((x) => x !== k) : [...h, k]))}
        onMark={addMark}
        xRange={xRange}
        onXRange={setXRange}
        visible={visible}
      />
      <div className="anom-marks">
        <div className="anom-marks-head">
          <span>Noted points ({marks.length})</span>
          <button className="btn-outline" onClick={() => setMarks([])} disabled={marks.length === 0}>
            Clear
          </button>
        </div>
        {marks.length === 0 && (
          <p className="muted">
            Hold <kbd>Alt</kbd> (<kbd>Option</kbd> on Mac) and click the chart to record a point here.
          </p>
        )}
        {marks.map((m) => (
          <div key={m.ts} className="anom-mark-entry">
            <div className="mark-ts">{m.ts}</div>
            {m.rows.map((r) => (
              <div key={r.name} className="mark-line">
                <span className="mark-name">{r.name}</span>
                <span className="mark-val">{r.value === null ? "—" : fmtReadoutVal(r.value)}</span>
              </div>
            ))}
          </div>
        ))}
      </div>
    </>
  );
}

function CounterGraphs({ fileId, visible }: { fileId: string; visible: boolean }) {
  const [counters, setCounters] = useState<CounterMeta[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [marks, setMarks] = useState<Mark[]>(() => graphStateFor(fileId).marks);
  // shared x-axis window: zooming one panel zooms both
  const [xRange, setXRange] = useState<[number, number] | null>(null);

  // marks outlive left-nav navigation too
  useEffect(() => {
    graphStateFor(fileId).marks = marks;
  }, [fileId, marks]);

  useEffect(() => {
    fetch(`/api/v1/files/${fileId}/counters`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => setCounters(d.counters ?? []))
      .catch(() => setErr("No counters available — was a dp/mp-monitor.log present in this archive?"));
  }, [fileId]);

  // record the timestamp plus the value of every visible counter at that time;
  // marks from both panels at the same timestamp merge into one entry
  const addMark = (t: number, rows: MarkRow[]) =>
    setMarks((m) => {
      const ts = fmtReadoutTs(t);
      const idx = m.findIndex((x) => x.ts === ts);
      if (idx < 0) return [...m, { ts, rows }];
      const merged = [...m];
      const seen = new Set(merged[idx].rows.map((r) => r.name));
      merged[idx] = {
        ...merged[idx],
        rows: [...merged[idx].rows, ...rows.filter((r) => !seen.has(r.name))],
      };
      return merged;
    });

  return (
    <>
      {err && <p className="error">{err}</p>}
      <GraphPanel
        fileId={fileId}
        panelIdx={0}
        counters={counters}
        onMark={addMark}
        xRange={xRange}
        onXRange={setXRange}
        visible={visible}
      />
      <GraphPanel
        fileId={fileId}
        panelIdx={1}
        counters={counters}
        onMark={addMark}
        xRange={xRange}
        onXRange={setXRange}
        visible={visible}
      />
      <div className="marks-card">
        <div className="marks-head">
          <span>
            Time marks — hold <kbd>Alt</kbd> (<kbd>Option</kbd> on Mac) and click a chart to record the crosshair time
          </span>
          <button
            className="btn-outline"
            onClick={() => setMarks([])}
            disabled={marks.length === 0}
          >
            Clear
          </button>
        </div>
        <div className="marks-body">
          {marks.length === 0 && <p className="muted">No marks recorded.</p>}
          {marks.map((m) => (
            <div key={m.ts} className="mark-entry">
              <div className="mark-ts">{m.ts}</div>
              {m.rows.map((r) => (
                <div key={r.name} className="mark-line">
                  <span className="mark-name">{r.name}</span>
                  <span className="mark-val">
                    {r.value === null ? "—" : fmtReadoutVal(r.value)}
                  </span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

/* ---------- Anomalies sub-tab ----------
   Groups repeated system-log events (OSPF neighbor down, LACP down, HA
   failovers, ...) so the same underlying issue shows up once with a
   count instead of as dozens of near-identical lines. Grouping happens
   entirely on the backend (parser/anomalies.go); this just renders the
   result and, on click, a small histogram of when a given event fired. */

function severityRank(s: string): number {
  switch (s.toLowerCase()) {
    case "critical": return 5;
    case "high": return 4;
    case "medium": return 3;
    case "low": return 2;
    case "informational":
    case "info": return 1;
    default: return 0;
  }
}

/* ---------- anomaly search: AND / OR / NOT boolean queries ----------
   Supports: bare words, "quoted phrases", AND / OR / NOT (and && || !),
   parentheses, and implicit AND between adjacent terms — so
     ospf AND down
     ospf down                 (same thing)
     tunnel OR ipsec
     telemetry AND NOT "1-hr"
     (ospf OR bgp) AND down
   all work. Precedence is the conventional NOT > AND > OR. */

type QueryNode =
  | { t: "term"; v: string }
  | { t: "not"; a: QueryNode }
  | { t: "and"; a: QueryNode; b: QueryNode }
  | { t: "or"; a: QueryNode; b: QueryNode };

type QToken = { k: "and" | "or" | "not" | "(" | ")" } | { k: "term"; v: string };

function tokenizeQuery(q: string): QToken[] {
  const out: QToken[] = [];
  let i = 0;
  while (i < q.length) {
    const c = q[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === "(" || c === ")") { out.push({ k: c }); i++; continue; }
    if (c === "!") { out.push({ k: "not" }); i++; continue; }
    if (c === "&") { i += q[i + 1] === "&" ? 2 : 1; out.push({ k: "and" }); continue; }
    if (c === "|") { i += q[i + 1] === "|" ? 2 : 1; out.push({ k: "or" }); continue; }
    if (c === '"' || c === "'") {
      const end = q.indexOf(c, i + 1);
      const v = end < 0 ? q.slice(i + 1) : q.slice(i + 1, end);
      if (v) out.push({ k: "term", v: v.toLowerCase() });
      i = end < 0 ? q.length : end + 1;
      continue;
    }
    let j = i;
    while (j < q.length && !/[\s()!&|]/.test(q[j])) j++;
    const w = q.slice(i, j);
    const up = w.toUpperCase();
    if (up === "AND") out.push({ k: "and" });
    else if (up === "OR") out.push({ k: "or" });
    else if (up === "NOT") out.push({ k: "not" });
    else out.push({ k: "term", v: w.toLowerCase() });
    i = j;
  }
  return out;
}

// recursive descent: or := and (OR and)* ; and := not (AND? not)* ; not := NOT not | primary
function parseQuery(q: string): QueryNode | null {
  const toks = tokenizeQuery(q);
  let p = 0;
  const peek = () => toks[p];

  const parseOr = (): QueryNode | null => {
    let left = parseAnd();
    if (!left) return null;
    while (peek()?.k === "or") {
      p++;
      const right = parseAnd();
      if (!right) return left;
      left = { t: "or", a: left, b: right };
    }
    return left;
  };

  const parseAnd = (): QueryNode | null => {
    let left = parseNot();
    if (!left) return null;
    for (;;) {
      const tk = peek();
      if (!tk || tk.k === "or" || tk.k === ")") break;
      if (tk.k === "and") p++; // explicit AND; otherwise implicit
      const right = parseNot();
      if (!right) break;
      left = { t: "and", a: left, b: right };
    }
    return left;
  };

  const parseNot = (): QueryNode | null => {
    if (peek()?.k === "not") {
      p++;
      const a = parseNot();
      return a ? { t: "not", a } : null;
    }
    const tk = peek();
    if (!tk) return null;
    if (tk.k === "(") {
      p++;
      const inner = parseOr();
      if (peek()?.k === ")") p++;
      return inner;
    }
    if (tk.k === "term") { p++; return { t: "term", v: tk.v }; }
    p++; // stray operator: skip it
    return parseNot();
  };

  const node = parseOr();
  return node;
}

function evalQuery(n: QueryNode, haystack: string): boolean {
  switch (n.t) {
    case "term": return haystack.includes(n.v);
    case "not": return !evalQuery(n.a, haystack);
    case "and": return evalQuery(n.a, haystack) && evalQuery(n.b, haystack);
    case "or": return evalQuery(n.a, haystack) || evalQuery(n.b, haystack);
    default: return true; // unreachable; keeps the return type total
  }
}

// everything a query can match against: the group label, its category and
// severity, and every raw occurrence message (so searching an IP, filename
// or tunnel name finds the group that contains it)
function anomalyHaystack(g: AnomalyGroup): string {
  return [
    g.label,
    g.subtype,
    g.severity,
    g.sample,
    ...(g.occurrences ?? []).map((o) => o.description),
  ]
    .join("   ")
    .toLowerCase();
}

function AnomaliesView({ fileId, visible }: { fileId: string; visible: boolean }) {
  const [groups, setGroups] = useState<AnomalyGroup[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // keyed by label, not row index, so filtering the list doesn't silently
  // change which event is open
  const [selectedLabel, setSelectedLabel] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  // notes live here, not in the chart, so they survive switching between events
  const [marks, setMarks] = useState<AnomalyMark[]>([]);

  const addMark = (label: string, ts: string, lines: string[]) =>
    setMarks((m) =>
      m.some((x) => x.ts === ts && x.label === label) ? m : [...m, { ts, label, lines }]
    );

  useEffect(() => {
    fetch(`/api/v1/files/${fileId}/anomalies`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => setGroups(d.anomalies ?? []))
      .catch(() =>
        setErr("No anomalies extracted — was a tmp/cli/logs/show_log_system.txt present in this archive?")
      );
  }, [fileId]);

  // the backend already orders these; re-sorting here keeps the critical-first
  // ordering guaranteed on the screen regardless of API version
  const sorted = useMemo(() => {
    if (!groups) return null;
    return [...groups].sort((a, b) => {
      const d = severityRank(b.severity) - severityRank(a.severity);
      return d !== 0 ? d : b.count - a.count;
    });
  }, [groups]);

  const ordered = useMemo(() => {
    if (!sorted) return null;
    const q = query.trim();
    if (!q) return sorted;
    const ast = parseQuery(q);
    // unparseable query (e.g. mid-typing): fall back to a plain substring match
    if (!ast) {
      const lc = q.toLowerCase();
      return sorted.filter((g) => anomalyHaystack(g).includes(lc));
    }
    return sorted.filter((g) => evalQuery(ast, anomalyHaystack(g)));
  }, [sorted, query]);

  const active = ordered?.find((g) => g.label === selectedLabel) ?? null;

  return (
    <div className="anom-wrap">
      {err && <p className="error">{err}</p>}
      {!ordered && !err && <p className="muted">Loading…</p>}
      {sorted && sorted.length > 0 && (
        <div className="anom-search">
          <input
            className="search-input"
            type="search"
            placeholder='Search events…  e.g.  ospf AND down   ·   tunnel OR ipsec   ·   telemetry AND NOT "1-hr"'
            title={
              'Boolean search over the event name, category, severity and every raw log message.\n\n' +
              'AND / OR / NOT (also && || !), parentheses, and "quoted phrases".\n' +
              'Adjacent words are ANDed implicitly, so `ospf down` == `ospf AND down`.\n\n' +
              'Examples:\n' +
              '  ospf AND down\n' +
              '  tunnel OR ipsec OR lacp\n' +
              '  telemetry AND NOT "1-hr"\n' +
              '  (ospf OR bgp) AND down\n' +
              '  10.10.10.2'
            }
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          {query.trim() !== "" && (
            <span className="anom-search-count muted">
              {ordered?.length ?? 0} of {sorted.length} events
              {(ordered?.length ?? 0) > 0 ? "" : " — no matches"}
            </span>
          )}
        </div>
      )}
      {sorted && sorted.length === 0 && <p className="muted">No recurring events found in the system log.</p>}
      {ordered && ordered.length > 0 && (
        <div className="anom-layout">
          <div className="anom-table-wrap">
            <table className="anom-table">
              <thead>
                <tr>
                  <th>Event</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Count</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {ordered.map((g, i) => (
                  <tr
                    key={g.label + i}
                    className={"anom-row" + (g.label === selectedLabel ? " active" : "")}
                    onClick={() => setSelectedLabel(g.label)}
                  >
                    <td className="anom-label" title={g.sample}>{g.label}</td>
                    <td>{g.subtype}</td>
                    <td>
                      <span className={"sev sev-" + g.severity.toLowerCase()}>{g.severity}</span>
                    </td>
                    <td>{g.count}</td>
                    <td>
                      {(g.occurrences ?? []).length
                        ? new Date(g.occurrences[g.occurrences.length - 1].ts).toLocaleString()
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {active && (
            <div className="anom-detail">
              <h3>{active.label}</h3>
              <AnomalyChart
                group={active}
                onMark={(ts, lines) => addMark(active.label, ts, lines)}
                visible={visible}
              />
              <div className="anom-marks">
                <div className="anom-marks-head">
                  <span>Noted events ({marks.length})</span>
                  <button className="btn-outline" onClick={() => setMarks([])} disabled={marks.length === 0}>
                    Clear
                  </button>
                </div>
                {marks.length === 0 && (
                  <p className="muted">
                    Hold <kbd>Alt</kbd> (<kbd>Option</kbd> on Mac) and click a point to note it here.
                  </p>
                )}
                {marks.map((m, i) => (
                  <div key={m.label + m.ts + i} className="anom-mark-entry">
                    <div className="mark-ts">
                      {new Date(m.ts).toLocaleString()} · {m.label}
                    </div>
                    {m.lines.map((l, k) => (
                      <div key={k} className="anom-mark-line">{l}</div>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* Same dygraphs chart the Counters tab uses, in point-only mode: one dot
   per occurrence at its exact log timestamp (y = how many fired at that
   same second), so an anomaly's timing can be read — and zoomed — the
   same way as a counter series rather than being smeared into buckets. */
/* Bucket width as a function of the visible time span. Zoomed out, events
   inside half an hour of each other are one dot; as the window narrows the
   buckets shrink and clumps split apart, until each event is its own dot. */
const MIN_30 = 30 * 60_000;
const MIN_15 = 15 * 60_000;
const MIN_10 = 10 * 60_000;
const MIN_5 = 5 * 60_000;

// Stepped so each zoom level splits clumps a little further rather than
// jumping from 30 minutes straight to individual events.
function bucketForSpan(spanMs: number): number {
  if (spanMs > 12 * 3600_000) return MIN_30; // more than half a day on screen
  if (spanMs > 6 * 3600_000) return MIN_15;
  if (spanMs > 2 * 3600_000) return MIN_10;
  if (spanMs > 45 * 60_000) return MIN_5;
  return 0; // no clustering: every occurrence plotted where it happened
}

function bucketLabel(bucketMs: number): string {
  if (bucketMs >= MIN_30) return "grouped per 30 min";
  if (bucketMs >= MIN_15) return "grouped per 15 min";
  if (bucketMs >= MIN_10) return "grouped per 10 min";
  if (bucketMs >= MIN_5) return "grouped per 5 min";
  return "every event shown individually";
}

interface AnomBucket {
  ts: number; // representative time (first occurrence in the bucket)
  count: number;
  lines: string[];
}

function AnomalyChart({
  group,
  onMark,
  visible = true,
}: {
  group: AnomalyGroup;
  onMark: (ts: string, lines: string[]) => void;
  visible?: boolean;
}) {
  const chartInst = useRef<Dygraph | null>(null);
  const { el: chartEl, setEl: setChartEl } = useChartContainer(chartInst);
  const [hoverTs, setHoverTs] = useState<number | null>(null);
  const [picked, setPicked] = useState<number | null>(null);
  const [bucketMs, setBucketMs] = useState<number>(MIN_30);
  // the zoom window is preserved across the rebuild that a bucket-size
  // change forces, and guards against feedback between the two
  const winRef = useRef<[number, number] | null>(null);
  const bucketRef = useRef(bucketMs);
  bucketRef.current = bucketMs;
  const rebuildingRef = useRef(false);

  // occurrences sorted once; bucketing is derived from this
  const occ = useMemo(() => {
    const list = (group.occurrences ?? [])
      .map((o) => ({ ms: Date.parse(o.ts), description: o.description }))
      .filter((o) => !Number.isNaN(o.ms));
    list.sort((a, b) => a.ms - b.ms);
    return list;
  }, [group]);

  // pick the initial bucket size from the full data span
  useEffect(() => {
    winRef.current = null;
    setPicked(null);
    if (occ.length > 1) {
      setBucketMs(bucketForSpan(occ[occ.length - 1].ms - occ[0].ms));
    } else {
      setBucketMs(0);
    }
  }, [occ]);

  // group occurrences into buckets; y is the number of events in the bucket
  // so a busier period is both taller and (via drawPointCallback) a bigger dot
  const buckets: AnomBucket[] = useMemo(() => {
    if (occ.length === 0) return [];
    if (bucketMs <= 0) {
      const m = new Map<number, AnomBucket>();
      for (const o of occ) {
        const b = m.get(o.ms);
        if (b) {
          b.count++;
          b.lines.push(o.description);
        } else {
          m.set(o.ms, { ts: o.ms, count: 1, lines: [o.description] });
        }
      }
      return Array.from(m.values()).sort((a, b) => a.ts - b.ts);
    }
    const out: AnomBucket[] = [];
    for (const o of occ) {
      const last = out[out.length - 1];
      if (last && o.ms - last.ts < bucketMs) {
        last.count++;
        last.lines.push(o.description);
      } else {
        out.push({ ts: o.ms, count: 1, lines: [o.description] });
      }
    }
    return out;
  }, [occ, bucketMs]);

  // drawPointCallback indexes into this, so it must track the current buckets
  const bucketsRef = useRef(buckets);
  bucketsRef.current = buckets;

  const rows = useMemo(() => buckets.map((b) => [new Date(b.ts), b.count]), [buckets]);

  const nearestBucket = (t: number): AnomBucket | null => {
    let best: AnomBucket | null = null;
    let bestD = Infinity;
    for (const b of buckets) {
      const d = Math.abs(b.ts - t);
      if (d < bestD) {
        bestD = d;
        best = b;
      }
    }
    return best;
  };

  useEffect(() => {
    const el = chartEl;
    // built only while the pane is actually on screen: dygraphs fixes its
    // width at construction, and a hidden container measures zero
    if (!el || !visible || el.clientWidth === 0 || rows.length === 0) return;

    const D = Dygraph as unknown as {
      startZoom: (e: MouseEvent, g: Dygraph, ctx: unknown) => void;
      moveZoom: (e: MouseEvent, g: Dygraph, ctx: unknown) => void;
      endZoom: (e: MouseEvent, g: Dygraph, ctx: unknown) => void;
    };
    interface ZoomCtx {
      isZooming: boolean;
      initializeMouseDown(e: MouseEvent, g: Dygraph, ctx: ZoomCtx): void;
    }
    const interactionModel = {
      mousedown: (e: MouseEvent, g: Dygraph, ctx: ZoomCtx) => {
        if (!e.shiftKey) return;
        ctx.initializeMouseDown(e, g, ctx);
        D.startZoom(e, g, ctx);
      },
      mousemove: (e: MouseEvent, g: Dygraph, ctx: ZoomCtx) => {
        if (ctx.isZooming) D.moveZoom(e, g, ctx);
      },
      mouseup: (e: MouseEvent, g: Dygraph, ctx: ZoomCtx) => {
        if (ctx.isZooming) D.endZoom(e, g, ctx);
      },
      dblclick: (_e: MouseEvent, g: Dygraph) => {
        g.resetZoom();
      },
    };

    const maxY = Math.max(...rows.map((r) => r[1] as number), 1);
    const g = new Dygraph(el, rows as unknown as number[][], {
      labels: ["time", "Events"],
      colors: ["#dc2626"],
      labelsUTC: true,
      legend: "never",
      // point-only: the dots are the data, lines between them would imply
      // a continuous series that doesn't exist
      strokeWidth: 0,
      drawPoints: true,
      pointSize: 3,
      highlightCircleSize: 6,
      includeZero: true,
      valueRange: [0, maxY + 1],
      axisLineColor: "#d4d4d8",
      gridLineColor: "#ececef",
      axisLabelFontSize: 11,
      // dots at the extremes stay inside the plot area and clickable
      xRangePad: CHART_X_PAD,
      dateWindow: winRef.current ?? undefined,
      interactionModel: interactionModel as unknown as Record<string, unknown>,
      // Dot radius grows with how many events the bucket holds, so a busy
      // period reads as a big dot rather than a taller one you have to squint
      // at. dygraphs 2.x passes the row index as an 8th argument, but
      // @types/dygraphs only declares 7 parameters, so this is written as a
      // variadic function and the index read positionally — annotating the
      // 8th parameter makes the options object unassignable to Options.
      drawPointCallback: (...args: unknown[]) => {
        const ctx = args[2] as CanvasRenderingContext2D;
        const cx = args[3] as number;
        const cy = args[4] as number;
        const color = args[5] as string;
        const idx = typeof args[7] === "number" ? (args[7] as number) : -1;
        const b = idx >= 0 ? bucketsRef.current[idx] : undefined;
        const n = b ? b.count : 1;
        const radius = Math.min(14, 3 + Math.sqrt(n) * 2.2);
        ctx.beginPath();
        ctx.fillStyle = color;
        ctx.globalAlpha = n > 1 ? 0.75 : 1;
        ctx.arc(cx, cy, radius, 0, 2 * Math.PI, false);
        ctx.fill();
        ctx.globalAlpha = 1;
      },
      highlightCallback: (_e, x) => setHoverTs(x),
      unhighlightCallback: () => setHoverTs(null),
      // re-bucket as the zoom level changes: wide window = coarse buckets,
      // narrow window = individual events
      drawCallback: (gg: Dygraph, isInitial: boolean) => {
        if (rebuildingRef.current) return;
        const r = gg.xAxisRange();
        if (!r || !Number.isFinite(r[0]) || !Number.isFinite(r[1])) return;
        winRef.current = gg.isZoomed("x") ? [r[0], r[1]] : null;
        if (isInitial) return;
        const want = bucketForSpan(r[1] - r[0]);
        if (want !== bucketRef.current) {
          rebuildingRef.current = true;
          setBucketMs(want);
          // cleared once the rebuild effect has run
          setTimeout(() => {
            rebuildingRef.current = false;
          }, 0);
        }
      },
    } as ConstructorParameters<typeof Dygraph>[2]);
    chartInst.current = g;

    return () => {
      g.destroy();
      chartInst.current = null;
    };
  }, [rows, chartEl, visible]);

  if (rows.length === 0) return <p className="muted">No timestamps to plot.</p>;

  const pickedBucket = picked !== null ? buckets.find((b) => b.ts === picked) ?? null : null;
  const pickedLines = pickedBucket?.lines ?? [];

  const handleClick = (e: ReactMouseEvent) => {
    if (hoverTs === null) return;
    const b = nearestBucket(hoverTs);
    if (!b) return;
    if (e.altKey) {
      onMark(new Date(b.ts).toISOString(), b.lines);
      return;
    }
    setPicked(b.ts);
  };

  const resetZoom = () => {
    winRef.current = null;
    chartInst.current?.resetZoom();
    if (occ.length > 1) setBucketMs(bucketForSpan(occ[occ.length - 1].ms - occ[0].ms));
  };

  const pan = (dir: -1 | 1) => {
    const g = chartInst.current;
    if (!g || occ.length === 0) return;
    const r = g.xAxisRange();
    if (!r || !Number.isFinite(r[0]) || !Number.isFinite(r[1])) return;
    const next = pannedWindow(r[0], r[1], dir, occ[0].ms, occ[occ.length - 1].ms);
    winRef.current = next;
    g.updateOptions({ dateWindow: next });
  };

  return (
    <div className="anom-chart">
      {/* the clicked incident's original log text sits above the graph */}
      <div className={"anom-picked" + (picked === null ? " anom-picked-empty" : "")}>
        {picked === null ? (
          <span className="muted">Click a dot to see the original system-log messages behind it.</span>
        ) : (
          <>
            <div className="anom-picked-ts">
              {new Date(picked).toLocaleString()}
              {pickedLines.length > 1 && (
                <span className="anom-picked-count">{pickedLines.length} events in this group</span>
              )}
            </div>
            {pickedLines.slice(0, 40).map((l, i) => (
              <div key={i} className="anom-picked-msg">{l}</div>
            ))}
            {pickedLines.length > 40 && (
              <div className="muted">…and {pickedLines.length - 40} more — zoom in to split this group.</div>
            )}
          </>
        )}
      </div>
      <div className="anom-chart-head">
        <span className="muted">
          {group.count} events · {bucketLabel(bucketMs)} · dot size = events in that group
        </span>
        <span className="graph-hover-ts">{hoverTs !== null ? fmtReadoutTs(hoverTs) : ""}</span>
        <PanControls onPan={pan} onReset={resetZoom} />
      </div>
      <div onClick={handleClick}>
        <div ref={setChartEl} className="anom-chart-canvas" />
      </div>
      <div className="graph-hint">
        Click a dot for the underlying log messages · <kbd>Shift</kbd> + drag to zoom in (clumps split apart as
        you go) · <kbd>‹</kbd> <kbd>›</kbd> to pan · double-click to reset · <kbd>Alt</kbd>/<kbd>Option</kbd> +
        click to note it
      </div>
    </div>
  );
}

/* one lookup → selected → plot row, monparse-style */
function GraphPanel({
  fileId,
  panelIdx,
  counters,
  onMark,
  xRange,
  onXRange,
  visible,
}: {
  fileId: string;
  panelIdx: number;
  counters: CounterMeta[];
  onMark: (t: number, rows: MarkRow[]) => void;
  xRange: [number, number] | null;
  onXRange: (r: [number, number] | null) => void;
  visible: boolean;
}) {
  const saved = graphStateFor(fileId).panels[panelIdx];
  const [filter, setFilter] = useState(saved.filter);
  const [sel, setSel] = useState<SelEntry[]>(saved.sel);
  const [data, setData] = useState<Record<string, CounterPoint[]>>({});
  const [hidden, setHidden] = useState<string[]>(saved.hidden);
  const [err, setErr] = useState<string | null>(null);

  // persist the picks for this file so they survive leaving the Graphs tab
  useEffect(() => {
    const st = graphStateFor(fileId).panels[panelIdx];
    st.filter = filter;
    st.sel = sel;
    st.hidden = hidden;
  }, [fileId, panelIdx, filter, sel, hidden]);

  // Fetch whatever is selected but not yet loaded. This covers both adding a
  // counter and coming back to a restored selection, and batches so a large
  // selection doesn't turn into hundreds of requests.
  useEffect(() => {
    const missing = Array.from(new Set(sel.map((e) => e.name))).filter((n) => !data[n]);
    if (missing.length === 0) return;
    let cancelled = false;
    (async () => {
      for (let i = 0; i < missing.length; i += COUNTER_FETCH_BATCH) {
        const batch = missing.slice(i, i + COUNTER_FETCH_BATCH);
        try {
          const q = batch.map(encodeURIComponent).join("|");
          const r = await fetch(`/api/v1/files/${fileId}/counters/data?names=${q}`);
          if (!r.ok) throw new Error(String(r.status));
          const d = await r.json();
          if (cancelled) return;
          setData((prev) => ({ ...prev, ...(d.series ?? {}) }));
        } catch {
          if (!cancelled) setErr(`Could not load ${batch.length} counter(s)`);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [fileId, sel, data]);

  const shown = useMemo(() => {
    const f = filter.trim();
    const list = f ? counters.filter(parseLookup(f).matches) : counters;
    return list.slice(0, LOOKUP_LIST_MAX);
  }, [counters, filter]);

  const add = (name: string, mode: SeriesMode) => {
    setErr(null);
    setSel((s) => {
      if (s.length >= MAX_PLOT || s.some((e) => e.name === name && e.mode === mode)) return s;
      return [...s, { name, mode }];
    });
  };

  // Bulk add is only offered once a filter has narrowed things to a set small
  // enough to plot. Unfiltered, "add all" would mean tens of thousands of
  // series and a dead browser tab.
  const filtered = filter.trim() !== "";
  const bulkAllowed = filtered && shown.length > 1 && shown.length <= BULK_ADD_MAX;
  const bulkWhy = !filtered
    ? "Add a filter first — without one this would add every counter in the archive"
    : shown.length > BULK_ADD_MAX
      ? `${shown.length} matches is too many to add at once; narrow the filter to ${BULK_ADD_MAX} or fewer`
      : shown.length <= 1
        ? "Nothing to bulk-add"
        : "";

  const addAllShown = (mode: SeriesMode) => {
    if (!bulkAllowed) return; // guard, in case the button is somehow reachable
    setErr(null);
    setSel((s) => {
      const next = [...s];
      for (const c of shown) {
        if (next.length >= MAX_PLOT) break;
        if (!next.some((e) => e.name === c.name && e.mode === mode)) next.push({ name: c.name, mode });
      }
      return next;
    });
  };

  const remove = (key: string) => {
    setSel((s) => s.filter((e) => selKey(e) !== key));
    setHidden((h) => h.filter((k) => k !== key));
  };

  const toggleHidden = (key: string) =>
    setHidden((h) => (h.includes(key) ? h.filter((k) => k !== key) : [...h, key]));

  const chartSeries = useMemo(() => {
    const out: Record<string, CounterPoint[]> = {};
    for (const e of sel) {
      const pts = data[e.name];
      if (pts) out[selKey(e)] = transformSeries(pts, e.mode);
    }
    return out;
  }, [sel, data]);

  return (
    <div className="panel-grid">
      <div className="lookup-card">
        <input
          className="file-filter"
          type="search"
          placeholder="lookup regex… (add: v > 10000)"
          title={'Pattern, optionally followed by a value filter.\nExamples:\n  dp__gc__pkt\n  mp__processes__*_res_swap_sub_lazy v > 10000\nOperators: > >= < <= = !='}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        {shown.length > 1 && (
          <div className="lookup-bulk" title={bulkWhy}>
            <span className="muted">
              {shown.length}
              {shown.length >= LOOKUP_LIST_MAX ? "+" : ""} match{shown.length === 1 ? "" : "es"}
            </span>
            <span className="lookup-actions">
              {(["val", "del", "rate"] as SeriesMode[]).map((m) => (
                <button
                  key={m}
                  disabled={!bulkAllowed}
                  className={bulkAllowed ? "" : "bulk-off"}
                  onClick={() => addAllShown(m)}
                  title={bulkAllowed ? `Add all ${shown.length} matches as ${m}` : bulkWhy}
                >
                  + all {m}
                </button>
              ))}
            </span>
          </div>
        )}
        <div className="lookup-list">
          {shown.map((c) => (
            <div key={c.name} className="lookup-row">
              <span
                className="lookup-name"
                title={`${c.points} samples · min ${c.min.toLocaleString()} · max ${c.max.toLocaleString()} — click to plot value`}
                onClick={() => add(c.name, "val")}
              >
                {c.name}
              </span>
              <span className="lookup-actions">
                <button onClick={() => add(c.name, "val")}>val</button>
                <button onClick={() => add(c.name, "del")}>del</button>
                <button onClick={() => add(c.name, "rate")}>rate</button>
              </span>
            </div>
          ))}
          {shown.length === 0 && <p className="muted">No matches</p>}
        </div>
      </div>

      <div className="selected-card">
        <div className="selected-head">
          <span>Selected ({sel.length})</span>
          {sel.length > 0 && (
            <button className="link-btn" onClick={() => { setSel([]); setHidden([]); }}>
              Clear
            </button>
          )}
        </div>
        {err && <p className="error">{err}</p>}
        <div className="selected-list">
          {sel.map((e, i) => {
            const key = selKey(e);
            return (
              <button
                key={key}
                className="selected-item"
                onClick={() => remove(key)}
                title="Click to remove from the graph"
              >
                <span className="readout-dot" style={{ background: CHART_COLORS[i % CHART_COLORS.length] }} />
                <span className="selected-name">{key}</span>
                <span className="selected-x">✕</span>
              </button>
            );
          })}
          {sel.length === 0 && (
            <p className="muted">Click a counter (or val / del / rate) to plot it.</p>
          )}
        </div>
      </div>

      {Object.keys(chartSeries).length > 0 ? (
        <GraphChart
          series={chartSeries}
          hidden={hidden}
          onToggle={toggleHidden}
          onMark={onMark}
          xRange={xRange}
          onXRange={onXRange}
          visible={visible}
        />
      ) : (
        <div className="graph-area">
          <p className="muted graph-empty">No counters plotted.</p>
        </div>
      )}
    </div>
  );
}

/* GraphChart is deliberately its own component: crosshair hover updates state
   at mousemove frequency, and keeping that out of Graphs means the (large)
   counter picker list never re-renders while you sweep the chart. */
function GraphChart({
  series,
  hidden,
  onToggle,
  onMark,
  xRange,
  onXRange,
  visible = true,
}: {
  series: Record<string, CounterPoint[]>;
  hidden: string[];
  onToggle: (key: string) => void;
  onMark: (t: number, rows: MarkRow[]) => void;
  xRange: [number, number] | null;
  onXRange: (r: [number, number] | null) => void;
  visible?: boolean;
}) {
  const [hoverTs, setHoverTs] = useState<number | null>(null);
  const chartInst = useRef<Dygraph | null>(null);
  const { el: chartEl, setEl: setChartEl } = useChartContainer(chartInst);
  const applyingRef = useRef(false); // true while applying a remote x-range
  const onXRangeRef = useRef(onXRange);
  onXRangeRef.current = onXRange;

  // sorted [ms, value] arrays per counter, for the readout panel
  const msData = useMemo(() => {
    const out: Record<string, [number, number][]> = {};
    for (const [name, pts] of Object.entries(series)) {
      out[name] = (pts ?? []).map((p) => [Date.parse(p.ts), p.value] as [number, number]);
    }
    return out;
  }, [series]);

  const readout: ReadoutRow[] = useMemo(() => {
    return Object.keys(msData).map((name, i) => {
      const pts = msData[name];
      let value: number | null = null;
      if (pts.length > 0) {
        value = hoverTs === null ? pts[pts.length - 1][1] : nearestVal(pts, hoverTs);
      }
      return { name, color: CHART_COLORS[i % CHART_COLORS.length], value };
    });
  }, [msData, hoverTs]);

  // merge all series into dygraphs native rows: [Date, v1, v2, ...] on the
  // union of timestamps (missing samples are null; points get connected)
  const dyData = useMemo(() => {
    const names = Object.keys(series);
    const byTs = new Map<number, (number | null)[]>();
    names.forEach((name, i) => {
      for (const p of series[name] ?? []) {
        const t = Date.parse(p.ts);
        let row = byTs.get(t);
        if (!row) {
          row = new Array(names.length).fill(null);
          byTs.set(t, row);
        }
        row[i] = p.value;
      }
    });
    const rows = Array.from(byTs.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([t, vals]) => [new Date(t), ...vals]);
    return { names, rows };
  }, [series]);

  useEffect(() => {
    const el = chartEl;
    // built only while the pane is actually on screen (see AnomalyChart)
    if (!el || !visible || el.clientWidth === 0 || dyData.rows.length === 0) return;

    // dygraphs' default model is drag=zoom / shift-drag=pan; ours is
    // shift-drag=zoom and everything else inert (no accidental zooms/pans)
    const D = Dygraph as unknown as {
      startZoom: (e: MouseEvent, g: Dygraph, ctx: unknown) => void;
      moveZoom: (e: MouseEvent, g: Dygraph, ctx: unknown) => void;
      endZoom: (e: MouseEvent, g: Dygraph, ctx: unknown) => void;
    };
    interface ZoomCtx {
      isZooming: boolean;
      initializeMouseDown(e: MouseEvent, g: Dygraph, ctx: ZoomCtx): void;
    }
    const interactionModel = {
      mousedown: (e: MouseEvent, g: Dygraph, ctx: ZoomCtx) => {
        if (!e.shiftKey) return;
        ctx.initializeMouseDown(e, g, ctx);
        D.startZoom(e, g, ctx);
      },
      mousemove: (e: MouseEvent, g: Dygraph, ctx: ZoomCtx) => {
        if (ctx.isZooming) D.moveZoom(e, g, ctx);
      },
      mouseup: (e: MouseEvent, g: Dygraph, ctx: ZoomCtx) => {
        if (ctx.isZooming) D.endZoom(e, g, ctx);
      },
      dblclick: (_e: MouseEvent, g: Dygraph) => {
        g.resetZoom();
      },
    };

    const g = new Dygraph(el, dyData.rows as unknown as number[][], {
      labels: ["time", ...dyData.names],
      colors: CHART_COLORS.slice(0, Math.max(1, dyData.names.length)),
      // log timestamps are wall-clock stored as UTC; render them unshifted
      labelsUTC: true,
      legend: "never", // the readout panel is the legend
      strokeWidth: 1.3,
      connectSeparatedPoints: true,
      highlightCircleSize: 3,
      axisLineColor: "#d4d4d8",
      gridLineColor: "#ececef",
      axisLabelFontSize: 11,
      // keep the first/last points off the axes so they stay clickable
      xRangePad: CHART_X_PAD,
      interactionModel: interactionModel as unknown as Record<string, unknown>,
      highlightCallback: (_e, x) => setHoverTs(x),
      unhighlightCallback: () => setHoverTs(null),
      // propagate zooms so all panels stay on the same x window
      drawCallback: (gg: Dygraph, isInitial: boolean) => {
        if (isInitial || applyingRef.current) return;
        if (gg.isZoomed("x")) {
          const r = gg.xAxisRange();
          onXRangeRef.current([r[0], r[1]]);
        } else {
          onXRangeRef.current(null);
        }
      },
    } as ConstructorParameters<typeof Dygraph>[2]);
    chartInst.current = g;

    return () => {
      g.destroy();
      chartInst.current = null;
    };
  }, [dyData, chartEl, visible]);

  // hide/show without rebuilding the chart
  useEffect(() => {
    const g = chartInst.current;
    if (!g) return;
    dyData.names.forEach((n, i) => g.setVisibility(i, !hidden.includes(n)));
  }, [hidden, dyData]);

  // follow the shared x window (skip if we already match it)
  useEffect(() => {
    const g = chartInst.current;
    if (!g) return;
    if (xRange) {
      const cur = g.xAxisRange();
      if (Math.abs(cur[0] - xRange[0]) < 500 && Math.abs(cur[1] - xRange[1]) < 500) return;
      applyingRef.current = true;
      g.updateOptions({ dateWindow: xRange });
      applyingRef.current = false;
    } else if (g.isZoomed("x")) {
      applyingRef.current = true;
      g.updateOptions({ dateWindow: null });
      applyingRef.current = false;
    }
  }, [xRange, dyData]);

  const resetZoom = () => chartInst.current?.resetZoom();

  // full extent of the plotted data, used to clamp panning
  const dataBounds = useMemo<[number, number] | null>(() => {
    const rows = dyData.rows;
    if (rows.length === 0) return null;
    const first = rows[0][0] as Date;
    const last = rows[rows.length - 1][0] as Date;
    return [first.getTime(), last.getTime()];
  }, [dyData]);

  const pan = (dir: -1 | 1) => {
    const g = chartInst.current;
    if (!g || !dataBounds) return;
    const r = g.xAxisRange();
    if (!r || !Number.isFinite(r[0]) || !Number.isFinite(r[1])) return;
    g.updateOptions({ dateWindow: pannedWindow(r[0], r[1], dir, dataBounds[0], dataBounds[1]) });
  };

  return (
    <div className="graph-area">
      <div className="graph-toolbar">
        <div className="chip-row">
          {readout.map((r) => (
            <button
              key={r.name}
              className={"chip" + (hidden.includes(r.name) ? " chip-off" : "")}
              onClick={() => onToggle(r.name)}
              title={hidden.includes(r.name) ? "Click to show" : "Click to hide"}
            >
              <span className="readout-dot" style={{ background: r.color }} />
              <span className="chip-name">{r.name}</span>
              <span className="chip-val">
                {r.value === null ? "—" : fmtReadoutVal(r.value)}
              </span>
            </button>
          ))}
        </div>
        <div className="graph-side">
          <span className="graph-hover-ts">
            {hoverTs !== null ? fmtReadoutTs(hoverTs) : ""}
          </span>
          <PanControls onPan={pan} onReset={resetZoom} />
        </div>
      </div>
      <div
        onClick={(e) => {
          if (e.altKey && hoverTs !== null) {
            onMark(
              hoverTs,
              readout
                .filter((r) => !hidden.includes(r.name))
                .map((r) => ({ name: r.name, value: r.value }))
            );
          }
        }}
      >
        <div ref={setChartEl} className="graph-canvas" />
      </div>
      <div className="graph-hint graph-hint-bottom">
        Hold <kbd>Shift</kbd> + drag to zoom (both charts follow) · <kbd>‹</kbd> <kbd>›</kbd> to pan ·
        double-click to reset · <kbd>Alt</kbd>/<kbd>Option</kbd> + click records a time mark
      </div>
    </div>
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

/* ---------- Config tab ----------
   PAN-OS's running config is a deeply nested but very regular XML tree:
   almost everything is a repeated <entry name="..."> list under a section
   tag (<address>, <zone>, <security>, ...), with policy rulebases adding
   one extra <rules> wrapper around their entries. Rather than parse it
   into dozens of bespoke shapes, the backend hands over the raw tree and
   this tab walks it the same way a user would click through the
   firewall's own Policies / Objects / Network / Device tabs. */

interface ConfigNode {
  tag: string;
  attrs?: Record<string, string>;
  text?: string;
  children?: ConfigNode[];
}

interface ConfigCandidate {
  path: string;
  size: number;
  picked: boolean;
  reason?: string;
}

interface ConfigDoc {
  root: ConfigNode | null;
  path: string;
  size: number;
  panorama_managed: boolean;
  markers?: string[];
  candidates: ConfigCandidate[];
}

/* Panorama pushes policy into pre- and post-rulebases that sit either side
   of the device's own rules; only the middle one is locally defined. The
   firewall's own UI shades the pushed rules to make that obvious, so rules
   are tagged with their origin here too — without this, a Panorama-managed
   device shows empty policy tables, because nothing lives under <rulebase>. */
type RuleOrigin = "local" | "pre" | "post";

const RULEBASE_PARENTS: { parent: string; origin: RuleOrigin }[] = [
  { parent: "pre-rulebase", origin: "pre" },
  { parent: "rulebase", origin: "local" },
  { parent: "post-rulebase", origin: "post" },
];

const ORIGIN_LABEL: Record<RuleOrigin, string> = {
  pre: "Panorama · pre",
  local: "Local",
  post: "Panorama · post",
};

interface EntryRow {
  node: ConfigNode;
  origin?: RuleOrigin;
}

function findAllByTag(root: ConfigNode | undefined, tag: string): ConfigNode[] {
  const out: ConfigNode[] = [];
  const walk = (n?: ConfigNode) => {
    if (!n) return;
    if (n.tag === tag) out.push(n);
    n.children?.forEach(walk);
  };
  walk(root);
  return out;
}

// Like findAllByTag, but only matches nodes whose immediate parent has
// parentTag — needed for the handful of PAN-OS tags reused in more than
// one place (e.g. "vlan" is both a Network > VLANs object and an
// interface type under Network > Interfaces; "qos" is both a policy
// rulebase and a network interface profile).
function findAllByTagUnderParent(root: ConfigNode | undefined, tag: string, parentTag: string): ConfigNode[] {
  const out: ConfigNode[] = [];
  const walk = (n?: ConfigNode) => {
    if (!n) return;
    n.children?.forEach((c) => {
      if (c.tag === tag && n.tag === parentTag) out.push(c);
      walk(c);
    });
  };
  walk(root);
  return out;
}

// Resolves a section tag to its list of <entry> nodes, whether the
// entries sit directly under the section (objects: address, zone, ...) or
// one <rules> wrapper down (policy rulebases: security, nat, ...). A
// container only contributes entries if it actually has entry/rules>entry
// children, which is what keeps this from also matching a rule's own
// field-level reference to the same tag name (e.g. a rule's
// <tag><member>prod</member></tag> vs. the Objects > Tags definition
// list — only the latter has <entry> children).
function sectionEntries(root: ConfigNode | undefined, tag: string, parentTag?: string): ConfigNode[] {
  const containers = parentTag ? findAllByTagUnderParent(root, tag, parentTag) : findAllByTag(root, tag);
  const out: ConfigNode[] = [];
  for (const c of containers) {
    const direct = c.children?.filter((ch) => ch.tag === "entry") ?? [];
    const rules = c.children?.find((ch) => ch.tag === "rules");
    const wrapped = rules?.children?.filter((ch) => ch.tag === "entry") ?? [];
    out.push(...direct, ...wrapped);
  }
  return Array.from(new Set(out));
}

// Collects a policy rulebase from all three parents, tagging each rule with
// where it came from and keeping Panorama's evaluation order: pre-rules,
// then the device's own rules, then post-rules.
function policyEntries(root: ConfigNode | undefined, tag: string): EntryRow[] {
  const out: EntryRow[] = [];
  for (const { parent, origin } of RULEBASE_PARENTS) {
    for (const node of sectionEntries(root, tag, parent)) {
      out.push({ node, origin });
    }
  }
  return out;
}

// Handles both list shapes PAN-OS uses for "many values under one field":
// <field><member>x</member></field> (zones, applications, services, ...)
// and <field><entry name="x"/></field> (IP addresses, static route hops,
// ..., where the value lives in the entry's name attribute, not its text).
function collectText(n: ConfigNode): string {
  const members = n.children?.filter((c) => c.tag === "member");
  if (members && members.length) return members.map((m) => m.text ?? "").join(", ");
  const entryKids = n.children?.filter((c) => c.tag === "entry");
  if (entryKids && entryKids.length) return entryKids.map((e) => e.attrs?.name ?? collectText(e)).join(", ");
  if (n.text) return n.text;
  return (n.children ?? []).map(collectText).filter(Boolean).join(", ");
}

function fieldNode(entry: ConfigNode | undefined, tag: string): ConfigNode | undefined {
  return entry?.children?.find((c) => c.tag === tag);
}

function fieldText(entry: ConfigNode | undefined, tag: string): string {
  const n = fieldNode(entry, tag);
  return n ? collectText(n) : "";
}

const prettyTag = (tag: string) => tag.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

interface ColumnSpec {
  header: string;
  // root is only needed by columns that do a reverse lookup across the
  // whole tree (e.g. which zone an interface belongs to); most columns
  // just read a field off the entry itself and can ignore it.
  get: (e: ConfigNode, root?: ConfigNode) => string;
}

const col = (header: string, tag: string): ColumnSpec => ({ header, get: (e) => fieldText(e, tag) });

// Fallback for sections without a curated column list: show every
// immediate field seen on the first handful of entries, so nothing in the
// config is ever fully hidden even if it isn't specially handled below.
function genericColumns(list: ConfigNode[]): ColumnSpec[] {
  const tags: string[] = [];
  const seen = new Set<string>();
  list.slice(0, 25).forEach((e) =>
    e.children?.forEach((c) => {
      if (c.tag !== "entry" && !seen.has(c.tag)) {
        seen.add(c.tag);
        tags.push(c.tag);
      }
    })
  );
  return tags.map((t) => col(prettyTag(t), t));
}

/* -- interfaces: IP addresses live as entry *names* under layer3/ip, and
   zone / logical-router membership is stored on the zone / virtual-router
   objects themselves (a reverse lookup), not on the interface entry — the
   firewall UI computes the same "which zone is this in" answer the same
   way. Non-L3 interfaces (loopback/vlan/tunnel) skip the layer3 wrapper
   PAN-OS uses on ethernet/aggregate-ethernet, so every getter here falls
   back to reading straight off the entry when there's no layer3 node. */
function ipAddressText(entry: ConfigNode): string {
  const layer3 = fieldNode(entry, "layer3");
  const ipNode = fieldNode(layer3 ?? entry, "ip");
  if (ipNode?.children?.length) {
    return ipNode.children.map((e) => e.attrs?.name ?? "").filter(Boolean).join(", ");
  }
  if (fieldNode(layer3 ?? entry, "dhcp-client")) return "DHCP Client";
  return "";
}

function zoneForInterface(root: ConfigNode, ifaceName: string): string {
  for (const z of sectionEntries(root, "zone")) {
    const net = fieldNode(z, "network");
    for (const kind of ["layer3", "layer2", "virtual-wire", "tap"]) {
      const members = fieldNode(net, kind)?.children?.filter((c) => c.tag === "member") ?? [];
      if (members.some((m) => m.text === ifaceName)) return z.attrs?.name ?? "";
    }
  }
  return "";
}

function logicalRouterForInterface(root: ConfigNode, ifaceName: string): string {
  for (const vr of sectionEntries(root, "virtual-router")) {
    const members = fieldNode(vr, "interface")?.children?.filter((c) => c.tag === "member") ?? [];
    if (members.some((m) => m.text === ifaceName)) return vr.attrs?.name ?? "";
  }
  return "";
}

const IFACE_COLUMNS: ColumnSpec[] = [
  { header: "Interface Type", get: (e) => (fieldNode(e, "layer3") ? "Layer3" : fieldNode(e, "virtual-wire") ? "Virtual Wire" : fieldNode(e, "layer2") ? "Layer2" : "") },
  { header: "IP Address", get: (e) => ipAddressText(e) },
  { header: "Zone", get: (e, root) => (root ? zoneForInterface(root, e.attrs?.name ?? "") : "") },
  { header: "Logical Router", get: (e, root) => (root ? logicalRouterForInterface(root, e.attrs?.name ?? "") : "") },
  { header: "Tag", get: (e) => fieldText(e, "tag") },
  { header: "Mgmt Profile", get: (e) => fieldText(fieldNode(e, "layer3") ?? e, "interface-management-profile") },
  { header: "Comment", get: (e) => fieldText(e, "comment") },
];

const INTERFACE_KINDS: { label: string; tag: string; parentTag: string }[] = [
  { label: "Ethernet", tag: "ethernet", parentTag: "interface" },
  { label: "VLAN", tag: "vlan", parentTag: "interface" },
  { label: "Loopback", tag: "loopback", parentTag: "interface" },
  { label: "Tunnel", tag: "tunnel", parentTag: "interface" },
  { label: "SD-WAN", tag: "sdwan", parentTag: "interface" },
];

function zoneTypeText(entry: ConfigNode): string {
  const net = fieldNode(entry, "network");
  if (!net) return "";
  const kinds: [string, string][] = [
    ["layer3", "Layer3"], ["layer2", "Layer2"], ["virtual-wire", "Virtual Wire"], ["tap", "Tap"], ["external", "External"],
  ];
  for (const [tag, label] of kinds) if (fieldNode(net, tag)) return label;
  return "";
}

const ZONE_COLUMNS: ColumnSpec[] = [
  { header: "Type", get: (e) => zoneTypeText(e) },
  { header: "Interfaces", get: (e) => fieldText(e, "network") },
];

/* -- logical (virtual) routers: the table shows quick yes/no/count
   summaries — matching what the firewall's own Network > Routing list
   shows — and clicking a row expands the full nested config (interfaces,
   static routes, OSPF/BGP/RIP/multicast settings and everything else)
   as a generic key/value tree, since the deep routing-protocol schema
   has more version-to-version variation than is worth hand-modeling. */
function vrProtoEnabled(entry: ConfigNode, proto: string): string {
  const node = fieldNode(fieldNode(entry, "protocol"), proto);
  if (!node) return "";
  const v = fieldText(node, "enable");
  return v === "yes" || v === "no" ? v : "yes";
}

function vrStaticRouteCount(entry: ConfigNode): string {
  const rt = fieldNode(entry, "routing-table");
  const v4 = fieldNode(fieldNode(rt, "ip"), "static-route")?.children?.filter((c) => c.tag === "entry").length ?? 0;
  const v6 = fieldNode(fieldNode(rt, "ipv6"), "static-route")?.children?.filter((c) => c.tag === "entry").length ?? 0;
  return v4 + v6 > 0 ? String(v4 + v6) : "";
}

const LOGICAL_ROUTER_COLUMNS: ColumnSpec[] = [
  { header: "Interfaces", get: (e) => fieldText(e, "interface") },
  { header: "OSPF", get: (e) => vrProtoEnabled(e, "ospf") },
  { header: "OSPFv3", get: (e) => vrProtoEnabled(e, "ospfv3") },
  { header: "BGP", get: (e) => vrProtoEnabled(e, "bgp") },
  { header: "RIPv2", get: (e) => vrProtoEnabled(e, "rip") },
  { header: "Multicast", get: (e) => vrProtoEnabled(e, "multicast") },
  { header: "Static Routes", get: (e) => vrStaticRouteCount(e) },
];

interface SectionDef {
  label: string;
  tag: string;
  parentTag?: string;
  columns?: ColumnSpec[];
  kv?: boolean; // Device sections: render as a key/value tree instead of a rule table
  expandable?: boolean; // clicking a row reveals its full config as a key/value tree
  group?: string; // sidebar sub-heading this item nests under (Routing, GlobalProtect, ...)
}

const POLICY_SECTIONS: SectionDef[] = [
  {
    label: "Security", tag: "security", parentTag: "rulebase",
    columns: [
      col("Tags", "tag"), col("Type", "rule-type"),
      col("From Zone", "from"), col("Source", "source"), col("Source User", "source-user"),
      col("To Zone", "to"), col("Destination", "destination"),
      col("Application", "application"), col("Service", "service"), col("Action", "action"),
    ],
  },
  {
    label: "NAT", tag: "nat", parentTag: "rulebase",
    columns: [
      col("Tags", "tag"), col("From Zone", "from"), col("To Zone", "to"), col("Destination Interface", "to-interface"),
      col("Source", "source"), col("Destination", "destination"), col("Service", "service"),
      col("Translated Source", "source-translation"), col("Translated Destination", "destination-translation"),
    ],
  },
  {
    label: "QoS", tag: "qos", parentTag: "rulebase",
    columns: [
      col("From Zone", "from"), col("Source", "source"), col("Destination", "destination"),
      col("Application", "application"), col("Class", "class"),
    ],
  },
  { label: "Policy Based Forwarding", tag: "pbf", parentTag: "rulebase" },
  { label: "Decryption", tag: "decryption", parentTag: "rulebase" },
  { label: "Application Override", tag: "application-override", parentTag: "rulebase" },
  { label: "Authentication", tag: "authentication", parentTag: "rulebase" },
  { label: "DoS Protection", tag: "dos", parentTag: "rulebase" },
  { label: "Tunnel Inspection", tag: "tunnel-inspect", parentTag: "rulebase" },
  { label: "SD-WAN", tag: "sdwan", parentTag: "rulebase" },
];

const OBJECT_SECTIONS: SectionDef[] = [
  {
    label: "Addresses", tag: "address",
    columns: [col("Value", "ip-netmask"), col("FQDN", "fqdn"), col("Range", "ip-range"), col("Tags", "tag")],
  },
  {
    label: "Address Groups", tag: "address-group",
    columns: [col("Static Members", "static"), col("Dynamic Filter", "dynamic"), col("Tags", "tag")],
  },
  { label: "Regions", tag: "region" },
  { label: "Dynamic User Groups", tag: "dynamic-user-group" },
  { label: "Applications", tag: "application" },
  { label: "Application Groups", tag: "application-group" },
  { label: "Application Filters", tag: "application-filter" },
  { label: "Services", tag: "service", columns: [col("Protocol", "protocol"), col("Tags", "tag")] },
  { label: "Service Groups", tag: "service-group", columns: [col("Members", "members"), col("Tags", "tag")] },
  { label: "Tags", tag: "tag", columns: [col("Color", "color"), col("Comments", "comments")] },
  { label: "Devices", tag: "device" },
  { label: "HIP Objects", tag: "hip-object", parentTag: "global-protect", group: "GlobalProtect" },
  { label: "HIP Profiles", tag: "hip-profile", parentTag: "global-protect", group: "GlobalProtect" },
  { label: "Host Compliance Objects", tag: "host-compliance-object", group: "Host Compliance" },
  { label: "Host Compliance Profiles", tag: "host-compliance-profile", group: "Host Compliance" },
  { label: "External Dynamic Lists", tag: "external-list" },
  { label: "URL Category", tag: "custom-url-category", group: "Custom Objects" },
  { label: "Antivirus", tag: "virus", parentTag: "profiles", group: "Security Profiles" },
  { label: "Anti-Spyware", tag: "spyware", parentTag: "profiles", group: "Security Profiles" },
  { label: "Vulnerability Protection", tag: "vulnerability", parentTag: "profiles", group: "Security Profiles" },
  { label: "URL Filtering", tag: "url-filtering", parentTag: "profiles", group: "Security Profiles" },
  { label: "File Blocking", tag: "file-blocking", parentTag: "profiles", group: "Security Profiles" },
  { label: "WildFire Analysis", tag: "wildfire-analysis", parentTag: "profiles", group: "Security Profiles" },
  { label: "DoS Protection", tag: "dos-protection", parentTag: "profiles", group: "Security Profiles" },
  { label: "Security Profile Groups", tag: "profile-group", parentTag: "profiles" },
  { label: "Log Forwarding", tag: "log-settings", parentTag: "profiles" },
  { label: "Authentication", tag: "authentication-profile" },
  { label: "Decryption Profile", tag: "decryption-profile", group: "Decryption" },
  { label: "Path Quality Profile", tag: "path-quality-profile", group: "SD-WAN Link Management" },
  { label: "SaaS Quality Profile", tag: "saas-quality-profile", group: "SD-WAN Link Management" },
  { label: "Traffic Distribution Profile", tag: "traffic-distribution-profile", group: "SD-WAN Link Management" },
  { label: "Error Correction Profile", tag: "error-correction-profile", group: "SD-WAN Link Management" },
  { label: "Schedules", tag: "schedule" },
];

const NETWORK_SECTIONS: SectionDef[] = [
  { label: "Interfaces", tag: "__interfaces__" }, // special-cased: has its own Ethernet/VLAN/Loopback/Tunnel/SD-WAN sub-tabs
  { label: "Zones", tag: "zone", columns: ZONE_COLUMNS },
  { label: "VLANs", tag: "vlan", parentTag: "network" },
  { label: "Virtual Wires", tag: "virtual-wire" },
  { label: "Logical Routers", tag: "virtual-router", columns: LOGICAL_ROUTER_COLUMNS, expandable: true, group: "Routing" },
  { label: "IPSec Tunnels", tag: "ipsec" },
  { label: "GRE Tunnels", tag: "gre" },
  { label: "DHCP", tag: "interface", parentTag: "dhcp" },
  { label: "DNS Proxy", tag: "dns-proxy" },
  { label: "Proxy", tag: "proxy" },
  { label: "Portals", tag: "portal", parentTag: "global-protect", group: "GlobalProtect" },
  { label: "Gateways", tag: "gateway", parentTag: "global-protect", group: "GlobalProtect" },
  { label: "MDM", tag: "mdm", parentTag: "global-protect", group: "GlobalProtect" },
  { label: "Clientless Apps", tag: "clientless-app", parentTag: "global-protect", group: "GlobalProtect" },
  { label: "Clientless App Groups", tag: "clientless-app-group", parentTag: "global-protect", group: "GlobalProtect" },
  { label: "DHCP Profile", tag: "dhcp-profile", parentTag: "global-protect", group: "GlobalProtect" },
  { label: "QoS", tag: "qos", parentTag: "network" },
  { label: "LLDP", tag: "lldp" },
  { label: "GlobalProtect IPSec Crypto", tag: "global-protect-ipsec-crypto-profiles", group: "Network Profiles" },
  { label: "IKE Gateways", tag: "gateway", parentTag: "ike", group: "Network Profiles" },
  { label: "IPSec Crypto", tag: "ipsec-crypto-profiles", parentTag: "ike", group: "Network Profiles" },
  { label: "IKE Crypto", tag: "ike-crypto-profiles", parentTag: "ike", group: "Network Profiles" },
  { label: "Monitor", tag: "monitor-profile", group: "Network Profiles" },
  { label: "Interface Mgmt", tag: "interface-management-profile", group: "Network Profiles" },
  { label: "Zone Protection", tag: "zone-protection-profile", group: "Network Profiles" },
  { label: "QoS Profile", tag: "qos-profile", group: "Network Profiles" },
  { label: "LLDP Profile", tag: "lldp-profile", group: "Network Profiles" },
  { label: "SD-WAN Interface Profile", tag: "sdwan-interface-profile" },
];

const DEVICE_SECTIONS: SectionDef[] = [
  { label: "Setup — General", tag: "system", parentTag: "deviceconfig", kv: true },
  { label: "High Availability", tag: "high-availability", parentTag: "deviceconfig", kv: true },
  { label: "Certificates", tag: "certificate" },
];

const CONFIG_GROUPS: { id: string; label: string; sections: SectionDef[] }[] = [
  { id: "policies", label: "Policies", sections: POLICY_SECTIONS },
  { id: "objects", label: "Objects", sections: OBJECT_SECTIONS },
  { id: "network", label: "Network", sections: NETWORK_SECTIONS },
  { id: "device", label: "Device", sections: DEVICE_SECTIONS },
];

// Renders the left-hand section list for whichever top-level group
// (Policies/Objects/Network/Device) is active, inserting a non-clickable
// sub-heading whenever a run of items shares the same `group` — mirroring
// how the firewall nests things like Routing or GlobalProtect under
// Network in its own left nav.
function renderSidebar(sections: SectionDef[], activeIdx: number, onSelect: (i: number) => void): JSX.Element[] {
  const nodes: JSX.Element[] = [];
  let lastGroup: string | undefined;
  sections.forEach((s, i) => {
    if (s.group !== lastGroup) {
      lastGroup = s.group;
      if (s.group) nodes.push(<div key={"g-" + s.group} className="cfg-nav-group">{s.group}</div>);
    }
    nodes.push(
      <button
        key={s.label + i}
        className={"cfg-nav-item" + (i === activeIdx ? " active" : "") + (s.group ? " cfg-nav-nested" : "")}
        onClick={() => onSelect(i)}
      >
        {s.label}
      </button>
    );
  });
  return nodes;
}

interface KvRow {
  key: string;
  value: string;
  depth: number;
}

function flattenKv(n: ConfigNode, depth = 0): KvRow[] {
  const out: KvRow[] = [];
  for (const c of n.children ?? []) {
    if (c.tag === "entry") {
      out.push({ key: c.attrs?.name ?? "entry", value: collectText(c), depth });
      continue;
    }
    const hasElementChildren = (c.children ?? []).some((cc) => cc.tag !== "member");
    if (hasElementChildren) {
      out.push({ key: prettyTag(c.tag), value: "", depth });
      out.push(...flattenKv(c, depth + 1));
    } else {
      out.push({ key: prettyTag(c.tag), value: collectText(c), depth });
    }
  }
  return out;
}

function ConfigTab({ fileId }: { fileId: string }) {
  const [doc, setDoc] = useState<ConfigDoc | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [groupId, setGroupId] = useState("policies");
  const [sectionIdx, setSectionIdx] = useState(0);
  const [showSources, setShowSources] = useState(false);

  useEffect(() => {
    fetch(`/api/v1/files/${fileId}/config`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => setDoc(d.config ?? null))
      .catch(() =>
        setErr("No config extracted for this file — no XML under /opt/pancfg/mgmt parsed as a PAN-OS <config>.")
      );
  }, [fileId]);

  const group = CONFIG_GROUPS.find((g) => g.id === groupId) ?? CONFIG_GROUPS[0];
  const section = group.sections[sectionIdx] ?? group.sections[0];
  const config = doc?.root ?? null;

  return (
    <section>
      <h2>Config</h2>
      {err && <p className="error">{err}</p>}
      {!doc && !err && <p className="muted">Loading…</p>}

      {doc && (
        <div className="cfg-source">
          <span className="cfg-source-path" title={doc.path}>{doc.path || "—"}</span>
          {doc.size > 0 && <span className="muted">{fmtSize(doc.size)}</span>}
          {doc.panorama_managed ? (
            <span className="cfg-pano-badge" title={"Panorama fingerprints: " + (doc.markers ?? []).join(", ")}>
              Panorama-managed
            </span>
          ) : (
            <span className="cfg-local-badge">Locally managed</span>
          )}
          {(doc.candidates ?? []).length > 1 && (
            <button className="link-btn" onClick={() => setShowSources(!showSources)}>
              {showSources ? "hide" : "show"} {doc.candidates.length} candidate files
            </button>
          )}
        </div>
      )}
      {doc && showSources && (
        <div className="cfg-candidates">
          {doc.candidates.map((c, i) => (
            <div key={i} className={"cfg-cand" + (c.picked ? " cfg-cand-picked" : "")}>
              <span className="cfg-cand-path">{c.path}</span>
              <span className="muted">{fmtSize(c.size)}</span>
              <span className="muted">{c.picked ? "used" : c.reason ?? ""}</span>
            </div>
          ))}
        </div>
      )}

      {config && (
        <div className="cfg-shell">
          <div className="cfg-groups">
            {CONFIG_GROUPS.map((g) => (
              <button
                key={g.id}
                className={g.id === groupId ? "active" : ""}
                onClick={() => {
                  setGroupId(g.id);
                  setSectionIdx(0);
                }}
              >
                {g.label}
              </button>
            ))}
          </div>
          <div className="cfg-body">
            <nav className="cfg-sidebar">{renderSidebar(group.sections, sectionIdx, setSectionIdx)}</nav>
            <div className="cfg-content">
              {section.tag === "__interfaces__" ? (
                <InterfacesView config={config} />
              ) : section.kv ? (
                <ConfigKvView config={config} section={section} />
              ) : (
                <SectionView config={config} section={section} />
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function SectionView({ config, section }: { config: ConfigNode; section: SectionDef }) {
  // policy rulebases are gathered from pre-/local/post- parents; everything
  // else is a plain object list
  const rows = useMemo<EntryRow[]>(() => {
    if (section.parentTag === "rulebase") return policyEntries(config, section.tag);
    return sectionEntries(config, section.tag, section.parentTag).map((node) => ({ node }));
  }, [config, section]);
  const columns = useMemo(
    () => section.columns ?? genericColumns(rows.map((r) => r.node)),
    [section, rows]
  );
  return <ConfigEntryTable rows={rows} columns={columns} root={config} expandable={section.expandable} />;
}

function InterfacesView({ config }: { config: ConfigNode }) {
  const [kind, setKind] = useState(0);
  const entries = useMemo(
    () => sectionEntries(config, INTERFACE_KINDS[kind].tag, INTERFACE_KINDS[kind].parentTag),
    [config, kind]
  );
  return (
    <div>
      <div className="cfg-subtabs">
        {INTERFACE_KINDS.map((k, i) => (
          <button key={k.label} className={i === kind ? "active" : ""} onClick={() => setKind(i)}>
            {k.label}
          </button>
        ))}
      </div>
      <ConfigEntryTable rows={entries.map((node) => ({ node }))} columns={IFACE_COLUMNS} root={config} />
    </div>
  );
}

function ConfigKvView({ config, section }: { config: ConfigNode; section: SectionDef }) {
  const containers = section.parentTag
    ? findAllByTagUnderParent(config, section.tag, section.parentTag)
    : findAllByTag(config, section.tag);
  if (containers.length === 0) {
    return <p className="muted">Not present in this config.</p>;
  }
  const rows = flattenKv(containers[0]);
  return (
    <div className="cfg-kv">
      {rows.length === 0 && <p className="muted">(empty)</p>}
      {rows.map((r, i) => (
        <div key={i} className="cfg-kv-row" style={{ paddingLeft: r.depth * 16 }}>
          <span className="cfg-kv-key">{r.key}</span>
          <span className="cfg-kv-val">{r.value}</span>
        </div>
      ))}
    </div>
  );
}

function ConfigEntryTable({
  rows,
  columns,
  root,
  expandable,
}: {
  rows: EntryRow[];
  columns: ColumnSpec[];
  root?: ConfigNode;
  expandable?: boolean;
}) {
  const [expanded, setExpanded] = useState<number | null>(null);
  if (rows.length === 0) {
    return <p className="muted">Not present in this config (or none configured).</p>;
  }
  // only show the Origin column where it means something (policy rulebases)
  const showOrigin = rows.some((r) => r.origin !== undefined);
  const span = columns.length + 1 + (showOrigin ? 1 : 0);
  return (
    <div className="cfg-table-wrap">
      <table className="cfg-table">
        <thead>
          <tr>
            {showOrigin && <th title="Panorama pushes pre- and post-rules around the device's own rules">Origin</th>}
            <th>Name</th>
            {columns.map((c) => (
              <th key={c.header}>{c.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => {
            const e = r.node;
            const pano = r.origin === "pre" || r.origin === "post";
            return (
              <Fragment key={(e.attrs?.name ?? "") + "_" + i}>
                <tr
                  className={
                    (expandable ? "cfg-row-clickable" : "") + (pano ? " cfg-row-pano" : "")
                  }
                  onClick={expandable ? () => setExpanded(expanded === i ? null : i) : undefined}
                >
                  {showOrigin && (
                    <td>
                      {r.origin && (
                        <span className={"cfg-origin cfg-origin-" + r.origin}>{ORIGIN_LABEL[r.origin]}</span>
                      )}
                    </td>
                  )}
                  <td className="cfg-name">{e.attrs?.name ?? "—"}</td>
                  {columns.map((c) => (
                    <td key={c.header}>{c.get(e, root) || "—"}</td>
                  ))}
                </tr>
                {expandable && expanded === i && (
                  <tr>
                    <td colSpan={span} className="cfg-expand-cell">
                      <div className="cfg-kv">
                        {flattenKv(e).map((kv, k) => (
                          <div key={k} className="cfg-kv-row" style={{ paddingLeft: kv.depth * 16 }}>
                            <span className="cfg-kv-key">{kv.key}</span>
                            <span className="cfg-kv-val">{kv.value}</span>
                          </div>
                        ))}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
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

/* ---------- shared search query language ----------
   Same grammar as the backend (parser/search.go) so the archive-wide search
   and the in-file search behave identically:
     ospf AND down · tunnel OR ipsec · NOT · "exact phrase" · regex terms
     · parentheses · grep-style -A / -B / -C context
   Bare terms are regular expressions; quoted terms match literally. */

/* Two results continue one another when they are consecutive lines of the
   same file — anything else starts a new block and gets a rule above it, the
   way grep separates groups with "--". */
function continuesPrevious(prev: SearchResult, cur: SearchResult): boolean {
  if (prev.path !== cur.path) return false;
  if (prev.type !== "line" || cur.type !== "line") return false;
  const prevEnd = (prev.context ?? []).reduce(
    (m, c) => Math.max(m, c.line_no),
    prev.line_no ?? 0
  );
  const curStart = (cur.context ?? []).reduce(
    (m, c) => Math.min(m, c.line_no),
    cur.line_no ?? 0
  );
  return curStart <= prevEnd + 1;
}

interface LineQuery {
  empty: boolean;
  before: number;
  after: number;
  match: (line: string) => boolean;
  /* the trailing "| $2 > 10" clause: keeps lines whose fields pass a test */
  keep: (line: string) => boolean;
  filterText: string;
  filterError: string;
}

const CONTEXT_FLAG_RE = /(^|\s)-([ABC])\s*(\d+)/gi;
const MAX_CONTEXT = 30;

/* ---------- awk-style field filter (mirrors parser/fieldfilter.go) ----------
   Fields are counted from the message: a leading timestamp and severity /
   subsystem label are skipped, so on
     2026/08/04 21:00:20 medium general pkt_recv 4523
   $1 is "pkt_recv" and $2 is "4523". $0 is the whole line. */

const TS_DATE_RE = /^\d{4}[-/]\d{2}[-/]\d{2}([T ]|$)/;
const TS_TIME_RE = /^\d{1,2}:\d{2}(:\d{2})?([.,]\d+)?$/;
const TS_MON_RE = /^(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)$/i;
const TS_DAY_RE = /^\d{1,2}$/;
const LOG_LABEL_RE =
  /^(critical|high|medium|low|informational|info|debug|warn|warning|error|err|notice|alert|emerg)$/i;
const BARE_WORD_RE = /^[A-Za-z_-][A-Za-z0-9_-]*$/;

/* offset at which the message begins, past any timestamp and severity label */
function messageStart(line: string): number {
  const toks: { s: string; off: number }[] = [];
  const re = /[^\s]+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line)) !== null) toks.push({ s: m[0], off: m.index });

  let i = 0;
  if (i < toks.length && TS_DATE_RE.test(toks[i].s)) i++;
  else if (i + 1 < toks.length && TS_MON_RE.test(toks[i].s) && TS_DAY_RE.test(toks[i + 1].s)) i += 2;
  if (i < toks.length && TS_TIME_RE.test(toks[i].s)) i++;
  if (i > 0 && i < toks.length && LOG_LABEL_RE.test(toks[i].s)) {
    i++;
    if (i < toks.length && BARE_WORD_RE.test(toks[i].s)) i++;
  }
  return i >= toks.length ? line.length : toks[i].off;
}

function messageFields(line: string): string[] {
  const msg = line.slice(messageStart(line));
  return msg.trim() === "" ? [] : msg.split(/\s+/).filter(Boolean);
}

/* -F splitting: empty fields are kept (with an explicit separator an empty
   field is data), and each field is trimmed. */
function messageFieldsSep(line: string, sep: RegExp): string[] {
  const msg = line.slice(messageStart(line));
  if (msg === "") return [];
  return msg.split(sep).map((s) => s.trim());
}

/* Follows awk's rule: a single character is literal, anything longer is a
   regex, and a space means runs of whitespace. */
function parseSeparator(arg: string): { re: RegExp | null; shown: string; error: string } {
  const shown = arg;
  let a = arg;
  if (a.length >= 2 && (a[0] === "'" || a[0] === '"') && a[a.length - 1] === a[0]) {
    a = a.slice(1, -1);
  }
  a = a.replace(/\\t/g, "\t").replace(/\\n/g, "\n").replace(/\\\\/g, "\\");
  if (a === "") return { re: null, shown, error: "empty -F separator" };
  if (a === " " || a === "\t") return { re: /\s+/, shown, error: "" };
  const quote = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if ([...a].length === 1) return { re: new RegExp(quote(a)), shown, error: "" };
  try {
    return { re: new RegExp(a), shown, error: "" };
  } catch {
    // a multi-character separator that is not a valid regex is still a
    // perfectly reasonable literal, e.g. -F'::'
    return { re: new RegExp(quote(a)), shown, error: "" };
  }
}

const SEP_FLAG_RE = /^-F\s*('[^']*'|"[^"]*"|\S+)\s*/;

/* accepts the shapes counters appear in: "4523", "4523,", "1400000kB", "85%" */
function fieldNumber(s: string): number | null {
  const m = /^[+-]?[\d.]+/.exec(s.trim());
  if (!m) return null;
  const v = parseFloat(m[0].replace(/[.+-]+$/, ""));
  return Number.isFinite(v) ? v : null;
}

interface FieldCond {
  field: number;
  op: string;
  num: number | null;
  str: string;
  re: RegExp | null;
}

function splitKeyword(s: string, kw: string): string[] {
  const out: string[] = [];
  let cur: string[] = [];
  for (const w of s.split(/\s+/).filter(Boolean)) {
    if (w.toUpperCase() === kw) { out.push(cur.join(" ")); cur = []; continue; }
    cur.push(w);
  }
  out.push(cur.join(" "));
  return out;
}

const FIELD_COND_RE = /^\$(\d+)\s*(!~|~|>=|<=|==|!=|=|>|<)\s*(.+)$/;

function parseFieldCond(s: string): FieldCond | string {
  const m = FIELD_COND_RE.exec(s.trim());
  if (!m) return s.trim() ? `expected $N followed by > >= < <= == != ~ : ${s}` : "empty condition";
  const field = parseInt(m[1], 10);
  const op = m[2] === "=" ? "==" : m[2];
  const rhs = m[3].trim().replace(/^["']|["']$/g, "");
  if (!rhs) return `missing value after ${m[2]}`;
  if (op === "~" || op === "!~") {
    try { return { field, op, num: null, str: "", re: new RegExp(rhs, "i") }; }
    catch { return `bad regex: ${rhs}`; }
  }
  const num = fieldNumber(rhs);
  return { field, op, num, str: rhs.toLowerCase(), re: null };
}

/* Returns a predicate plus the reason a clause was ignored. A clause that
   cannot be parsed is not applied at all, so a half-typed filter shows
   everything rather than an arbitrary subset. */
function parseFieldFilter(clause: string): {
  keep: (line: string) => boolean;
  error: string;
  active: boolean;
  sep: string;
} {
  const pass = { keep: () => true, error: "", active: false, sep: "" };
  let text = clause.trim();
  if (!text) return pass;

  let sepRe: RegExp | null = null;
  let sepShown = "";
  const sm = SEP_FLAG_RE.exec(text);
  if (sm) {
    const parsed = parseSeparator(sm[1]);
    if (parsed.error) return { ...pass, error: parsed.error };
    sepRe = parsed.re;
    sepShown = parsed.shown;
    text = text.slice(sm[0].length).trim();
    if (!text) return { ...pass, error: "-F given with no condition after it" };
  }

  const groups: FieldCond[][] = [];
  for (const orPart of splitKeyword(text, "OR")) {
    const group: FieldCond[] = [];
    for (const andPart of splitKeyword(orPart, "AND")) {
      const c = parseFieldCond(andPart);
      if (typeof c === "string") return { ...pass, error: c };
      group.push(c);
    }
    if (group.length === 0) return { ...pass, error: "empty condition" };
    groups.push(group);
  }
  if (groups.length === 0) return pass;

  const evalCond = (c: FieldCond, line: string, fields: string[]): boolean => {
    let val: string;
    if (c.field === 0) val = line;
    else if (c.field <= fields.length) val = fields[c.field - 1];
    else return false;

    if (c.op === "~") return c.re !== null && c.re.test(val);
    if (c.op === "!~") return c.re !== null && !c.re.test(val);

    if (c.num !== null) {
      const n = fieldNumber(val);
      if (n === null) return false;
      switch (c.op) {
        case ">": return n > c.num;
        case ">=": return n >= c.num;
        case "<": return n < c.num;
        case "<=": return n <= c.num;
        case "==": return n === c.num;
        case "!=": return n !== c.num;
      }
      return false;
    }
    const lv = val.toLowerCase();
    switch (c.op) {
      case "==": return lv === c.str;
      case "!=": return lv !== c.str;
      case ">": return lv > c.str;
      case ">=": return lv >= c.str;
      case "<": return lv < c.str;
      case "<=": return lv <= c.str;
    }
    return false;
  };

  return {
    active: true,
    error: "",
    sep: sepShown,
    keep: (line: string) => {
      const fields = sepRe ? messageFieldsSep(line, sepRe) : messageFields(line);
      return groups.some((g) => g.every((c) => evalCond(c, line, fields)));
    },
  };
}

/* Separates a query from its trailing pipe filter. The pipe must be followed
   by a "$", so the "|" the search grammar accepts as OR is not mistaken for
   a pipe. */
function splitFieldClause(raw: string): [string, string] {
  for (let i = raw.length - 1; i >= 0; i--) {
    if (raw[i] !== "|") continue;
    if (i > 0 && raw[i - 1] === "|") continue;
    const rest = raw.slice(i + 1).trim();
    if (rest.startsWith("$") || rest.startsWith("-F")) return [raw.slice(0, i).trim(), rest];
  }
  return [raw, ""];
}

function parseLineQuery(rawInput: string): LineQuery {
  const [raw, clause] = splitFieldClause(rawInput);
  const filter = parseFieldFilter(clause);
  let before = 0, after = 0;
  const body = raw
    .replace(CONTEXT_FLAG_RE, (_m, _p, flag: string, n: string) => {
      const v = Math.min(parseInt(n, 10) || 0, MAX_CONTEXT);
      const f = flag.toUpperCase();
      if (f === "A") after = v;
      else if (f === "B") before = v;
      else { before = v; after = v; }
      return " ";
    })
    .trim();

  const extras = {
    keep: filter.keep,
    filterText: filter.active ? clause.trim() : "",
    filterError: filter.error,
  };
  const noMatch = { empty: true, before, after, match: () => false, ...extras };
  if (!body) return noMatch;

  type Tok = { k: string; v?: string; quot?: boolean };
  const toks: Tok[] = [];
  let i = 0;
  while (i < body.length) {
    const c = body[i];
    if (c === " " || c === "\t") { i++; continue; }
    if (c === "(" || c === ")") { toks.push({ k: c }); i++; continue; }
    if (c === "!") { toks.push({ k: "not" }); i++; continue; }
    if (c === "&") { i += body[i + 1] === "&" ? 2 : 1; toks.push({ k: "and" }); continue; }
    if (c === "|") { i += body[i + 1] === "|" ? 2 : 1; toks.push({ k: "or" }); continue; }
    if (c === '"' || c === "'") {
      const end = body.indexOf(c, i + 1);
      const v = end < 0 ? body.slice(i + 1) : body.slice(i + 1, end);
      i = end < 0 ? body.length : end + 1;
      if (v) toks.push({ k: "term", v, quot: true });
      continue;
    }
    let j = i;
    while (j < body.length && !" \t()!&|".includes(body[j])) j++;
    const w = body.slice(i, j);
    const up = w.toUpperCase();
    toks.push(up === "AND" ? { k: "and" } : up === "OR" ? { k: "or" } : up === "NOT" ? { k: "not" } : { k: "term", v: w });
    i = j;
  }

  type Pred = (s: string) => boolean;
  const term = (t: Tok): Pred => {
    const v = t.v ?? "";
    if (t.quot) { const lit = v.toLowerCase(); return (s) => s.includes(lit); }
    try { const re = new RegExp(v, "i"); return (s) => re.test(s); }
    catch { const lit = v.toLowerCase(); return (s) => s.includes(lit); }
  };

  let p = 0;
  const peek = () => toks[p];
  const parseNot = (): Pred | null => {
    const t = peek();
    if (!t) return null;
    if (t.k === "not") { p++; const a = parseNot(); return a ? (s) => !a(s) : null; }
    if (t.k === "(") { p++; const inner = parseOr(); if (peek()?.k === ")") p++; return inner; }
    if (t.k === "term") { p++; return term(t); }
    p++; return parseNot();
  };
  const parseAnd = (): Pred | null => {
    let left: Pred | null = parseNot();
    if (!left) return null;
    for (;;) {
      const t = peek();
      if (!t || t.k === "or" || t.k === ")") break;
      if (t.k === "and") p++;
      const right = parseNot();
      if (!right) break;
      const a: Pred = left, b: Pred = right;
      left = (v: string) => a(v) && b(v);
    }
    return left;
  };
  const parseOr = (): Pred | null => {
    let left: Pred | null = parseAnd();
    if (!left) return null;
    while (peek()?.k === "or") {
      p++;
      const right = parseAnd();
      if (!right) return left;
      const a: Pred = left, b: Pred = right;
      left = (v: string) => a(v) || b(v);
    }
    return left;
  };

  let root = parseOr();
  if (!root) { const lit = body.toLowerCase(); root = (s) => s.includes(lit); }
  const fn = root;
  return { empty: false, before, after, match: (line) => fn(line.toLowerCase()), ...extras };
}

/* ---------- Log Files tab ---------- */

function LogFiles({ fileId }: { fileId: string }) {
  const saved = logStateFor(fileId);
  const [entries, setEntries] = useState<Entry[]>([]);
  const [open, setOpen] = useState(saved.open);
  const [minimized, setMinimized] = useState(saved.minimized);
  const [cwd, setCwd] = useState(saved.cwd); // "" = archive root
  const [selected, setSelected] = useState<string[]>(saved.selected);
  const [from, setFrom] = useState(saved.from);
  const [to, setTo] = useState(saved.to);
  const [viewItems, setViewItems] = useState<ViewItem[]>(saved.viewItems);
  const [maximized, setMaximized] = useState(saved.maximized);
  const [fileFilter, setFileFilter] = useState(saved.fileFilter);

  // Everything above outlives leaving this tab: the picker, the time filter,
  // which files are open and whether the viewer was maximized.
  useEffect(() => {
    const st = logStateFor(fileId);
    st.open = open;
    st.minimized = minimized;
    st.cwd = cwd;
    st.selected = selected;
    st.from = from;
    st.to = to;
    st.viewItems = viewItems;
    st.maximized = maximized;
    st.fileFilter = fileFilter;
  }, [fileId, open, minimized, cwd, selected, from, to, viewItems, maximized, fileFilter]);

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

  // Alt/Option+click on a hit opens it straight into the maximized viewer
  const openFromSearch = (path: string, line?: number, maximize?: boolean) => {
    setViewItems((v) => [...v.filter((it) => it.path !== path), { path, line }]);
    if (maximize) setMaximized(true);
  };

  const closeViewItem = (path: string) =>
    setViewItems((v) => v.filter((it) => it.path !== path));

  return (
    <section>
      <h2>Log Files</h2>
      <ArchiveSearch
        fileId={fileId}
        onOpen={openFromSearch}
        title="Global search — the whole tech-support file"
        cacheKey="global"
      />
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

          <ArchiveSearch
            fileId={fileId}
            onOpen={openFromSearch}
            title="Search within selected files"
            cacheKey="scoped"
            scopePaths={selected}
            placeholder={
              selected.length
                ? `Search the ${selected.length} selected file${selected.length === 1 ? "" : "s"}…`
                : "Check files below to restrict the search, or leave empty to search everything…"
            }
          />

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
            onClose={() => closeViewItem(it.path)}
          />
        ))}

      {maximized && viewItems.length > 0 && (
        <MaxViewer
          fileId={fileId}
          items={viewItems}
          from={from}
          to={to}
          onMinimize={() => setMaximized(false)}
          onClose={closeViewItem}
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
  onClose,
}: {
  fileId: string;
  items: ViewItem[];
  from: string;
  to: string;
  onMinimize: () => void;
  onClose?: (path: string) => void;
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
            <div key={it.path} className="viewer-file-row">
              <button
                className={it.path === active?.path ? "active" : ""}
                onClick={() => setActivePath(it.path)}
                title={it.path}
              >
                {it.path.split("/").pop()}
              </button>
              {onClose && (
                <button
                  className="viewer-file-close"
                  title="Close this file"
                  onClick={() => onClose(it.path)}
                >
                  ✕
                </button>
              )}
            </div>
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
                onClose={onClose ? () => onClose(it.path) : undefined}
              />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* Archive-wide search. Used twice: once unrestricted (global) and once
   scoped to the files chosen in the picker. Supports the shared query
   language including grep-style -A/-B/-C, which is sent to the backend. */
function ArchiveSearch({
  fileId,
  onOpen,
  title,
  cacheKey,
  scopePaths,
  placeholder,
}: {
  fileId: string;
  onOpen: (path: string, line?: number, maximize?: boolean) => void;
  title: string;
  cacheKey: "global" | "scoped";
  scopePaths?: string[];
  placeholder?: string;
}) {
  const saved = logStateFor(fileId);
  const [query, setQuery] = useState(cacheKey === "global" ? saved.query : "");
  const [results, setResults] = useState<SearchResult[] | null>(
    cacheKey === "global" ? saved.results : null
  );
  const [searching, setSearching] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  // a failed request must never look like "no matches"
  const [error, setError] = useState<string | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [cappedFiles, setCappedFiles] = useState<string[]>([]);
  // partial results because the deadline hit, rather than a dead request
  const [timedOut, setTimedOut] = useState(false);
  const [scanned, setScanned] = useState<{ scanned: number; candidates: number } | null>(null);
  // the "| $2 > 10" clause the server applied, and why it ignored a bad one
  const [filterText, setFilterText] = useState("");
  const [filterError, setFilterError] = useState("");

  // Guards against a slow earlier response overwriting a newer one. Without
  // this, changing the query or the file scope mid-flight could show stale
  // results, or clobber good results with an older empty set.
  const seqRef = useRef(0);
  const abortRef = useRef<AbortController | null>(null);

  // the global search box and its results survive leaving the tab
  useEffect(() => {
    if (cacheKey !== "global") return;
    const st = logStateFor(fileId);
    st.query = query;
    st.results = results;
  }, [cacheKey, fileId, query, results]);

  const scopeKey = (scopePaths ?? []).join("|");

  useEffect(() => {
    const trimmed = query.trim();
    if (trimmed.length < 2) {
      abortRef.current?.abort();
      seqRef.current++; // invalidate anything in flight
      setResults(null);
      setError(null);
      setSearching(false); // otherwise "Searching…" could stick forever
      return;
    }
    setSearching(true);
    setError(null);

    const t = setTimeout(() => {
      // supersede any request still running: they scan the whole archive, so
      // leaving them to finish is both slow and a source of stale results
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      const seq = ++seqRef.current;

      const p = new URLSearchParams({ q: trimmed });
      if (scopeKey) p.set("paths", scopeKey);

      fetch(`/api/v1/files/${fileId}/search?${p.toString()}`, { signal: ac.signal })
        .then(async (r) => {
          if (!r.ok) {
            let detail = `HTTP ${r.status}`;
            try {
              const body = await r.json();
              if (body?.error) detail += ` — ${body.error}`;
            } catch {
              /* not JSON; the status alone is the message */
            }
            throw new Error(detail);
          }
          return r.json();
        })
        .then((d) => {
          if (seq !== seqRef.current) return; // a newer search has taken over
          setResults(d.results ?? []);
          setTruncated(Boolean(d.truncated));
          setCappedFiles(d.capped_files ?? []);
          setTimedOut(Boolean(d.timed_out));
          setFilterText(typeof d.filter === "string" ? d.filter : "");
          setFilterError(typeof d.filter_error === "string" ? d.filter_error : "");
          setScanned(
            d.indexed
              ? { scanned: Number(d.scanned) || 0, candidates: Number(d.candidates) || 0 }
              : null
          );
          setSearching(false);
        })
        .catch((err: unknown) => {
          if (seq !== seqRef.current) return;
          const name = (err as { name?: string })?.name;
          if (name === "AbortError") return; // superseded on purpose
          setError((err as Error)?.message || "search failed");
          setResults(null); // NOT [] — an error is not "no matches"
          setSearching(false);
        });
    }, 450);

    return () => clearTimeout(t);
  }, [query, fileId, scopeKey]);

  const lineHits = (results ?? []).filter((r) => r.type === "line").length;

  return (
    <div className="search-wrap">
      <div className="search-head">
        <span className="search-title">{title}</span>
        {scopeKey && (
          <span className="search-scope">
            {(scopePaths ?? []).length} file{(scopePaths ?? []).length === 1 ? "" : "s"}
          </span>
        )}
        {results !== null && (
          <>
            <span className="muted">
              {truncated ? "first " : ""}
              {results.length} result{results.length === 1 ? "" : "s"}
              {lineHits !== results.length ? ` (${lineHits} line)` : ""}
            </span>
            {truncated && (
              <span
                className="search-capped"
                title="The result cap stopped the scan early — narrow the query or restrict it to specific files to see the rest."
              >
                more exist
              </span>
            )}
            {cappedFiles.length > 0 && (
              <span
                className="search-capped"
                title={"Per-file cap reached in:\n" + cappedFiles.join("\n")}
              >
                {cappedFiles.length} file{cappedFiles.length === 1 ? "" : "s"} capped
              </span>
            )}
            {timedOut && (
              <span
                className="search-capped"
                title="The search ran out of time and stopped early, so these results are partial. Narrow the query or restrict it to specific files."
              >
                partial — timed out
              </span>
            )}
            {filterText && (
              <span
                className="log-filter-tag"
                title="Field filter, applied to matched lines and their context alike"
              >
                | {filterText}
              </span>
            )}
            {filterError && (
              <span className="search-capped" title={filterError}>
                filter ignored
              </span>
            )}
            {scanned && (
              <span
                className="muted search-scanned"
                title={
                  "The search index narrowed the archive to " +
                  scanned.candidates +
                  " candidate file(s); " +
                  scanned.scanned +
                  " were read."
                }
              >
                {scanned.scanned} file{scanned.scanned === 1 ? "" : "s"} read
              </span>
            )}
            <button className="link-btn" onClick={() => setCollapsed(!collapsed)}>
              {collapsed ? "show" : "hide"}
            </button>
            <button className="link-btn" onClick={() => { setQuery(""); setResults(null); }}>
              clear
            </button>
          </>
        )}
      </div>
      <input
        className="search-input"
        type="search"
        placeholder={placeholder ?? 'Search…  ospf AND down · "phrase" · -A 3 -B 2 · | $2 > 10000'}
        title={
          "AND / OR / NOT (also && || !), parentheses\n" +
          'bare terms are regexes, "quoted" terms match literally\n' +
          "-A n / -B n / -C n show lines after / before / around each match\n\n" +
          "| $2 > 10000   filter by field value, like piping to awk\n" +
          "   $1, $2, … count from the message (timestamp and label skipped)\n" +
          "   $0 is the whole line; operators > >= < <= == != ~ !~\n" +
          "   combine with AND / OR:  pkt_recv -A 10 | $2 > 1000 AND $1 ~ rx\n" +
          "   -F sets the separator:  sessions | -F',' $3 > 500\n" +
          "      one character is literal, longer is a regex: -F'\\s*:\\s*'\n" +
          "   the filter applies to matched lines and their context alike\n\n" +
          "Click a hit to open it below; Alt/Option+click opens it maximized."
        }
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      {searching && <p className="muted">Searching the archive…</p>}
      {error && !searching && (
        <p className="error">
          Search failed: {error}. The archive is scanned per query, so a very
          large file can time out — try restricting the search to specific files.
        </p>
      )}
      {results !== null && !searching && !collapsed && (
        <div className="search-results">
          {results.map((r, i) => (
            <div
              key={i}
              className={
                "result-item" +
                // a rule above each block that does not continue the previous
                // one, so consecutive hits never run together
                (i > 0 && !continuesPrevious(results[i - 1], r) ? " result-break" : "")
              }
            >
              <button
                className={"result-row" + (r.filtered ? " result-row-filtered" : "")}
                onClick={(e) => onOpen(r.path, r.type === "line" ? r.line_no : undefined, e.altKey)}
                title={
                  (r.type === "line" ? `${r.path} (line ${r.line_no})` : r.path) +
                  "\nAlt/Option+click to open maximized" +
                  (r.filtered
                    ? "\n\nThis line matched the search but not the field filter;" +
                      " it is shown because context lines below did pass."
                    : "")
                }
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
              {(r.context ?? []).length > 0 && (
                <div className="result-context">
                  {(r.context ?? []).map((c, k) => (
                    <div key={k} className={"ctx-line" + (c.before ? " ctx-before" : " ctx-after")}>
                      <span className="ctx-no">{c.line_no}</span>
                      <span className="ctx-text">{c.text}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
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
  /* a break between blocks that are not adjacent in the file, like grep's -- */
  sep: boolean;
  /* the line matched the search, rather than being -A/-B context around one */
  match: boolean;
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
  onClose,
}: {
  fileId: string;
  path: string;
  from: string;
  to: string;
  highlightLine?: number;
  onClose?: () => void;
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
  // in-file search, same query language as the archive search (including
  // -A/-B/-C), so a loaded file can be narrowed without another round trip
  const [q, setQ] = useState("");
  const query = useMemo(() => parseLineQuery(q), [q]);
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
  // Entries kept by the in-file search, plus their -A/-B context. Each kept
  // entry records whether it was a match (rather than context) and whether a
  // gap precedes it, so non-adjacent blocks can be separated the way grep
  // separates them with "--" instead of running together.
  const shownEntries = useMemo(() => {
    if (!entries) return null;
    if (query.empty) {
      return entries.map((e) => ({ e, match: false, gap: false }));
    }
    const matched = new Set<number>();
    const keep = new Set<number>();
    entries.forEach((e, i) => {
      if (query.match(`${e.ts} ${e.label} ${e.msg}`)) {
        matched.add(i);
        keep.add(i);
        for (let k = 1; k <= query.before; k++) if (i - k >= 0) keep.add(i - k);
        for (let k = 1; k <= query.after; k++) if (i + k < entries.length) keep.add(i + k);
      }
    });
    const out: { e: LogEntryRow; match: boolean; gap: boolean }[] = [];
    let prev = -1;
    for (let i = 0; i < entries.length; i++) {
      if (!keep.has(i)) continue;
      // the field filter runs over matches and context alike, as piping to
      // awk would
      if (!query.keep(`${entries[i].ts} ${entries[i].label} ${entries[i].msg}`)) continue;
      out.push({ e: entries[i], match: matched.has(i), gap: prev >= 0 && i > prev + 1 });
      prev = i;
    }
    return out;
  }, [entries, query]);

  const matchCount = useMemo(() => {
    if (!entries || query.empty) return 0;
    let n = 0;
    for (const e of entries) {
      const line = `${e.ts} ${e.label} ${e.msg}`;
      if (query.match(line) && query.keep(line)) n++;
    }
    return n;
  }, [entries, query]);

  const rows: FlatRow[] = useMemo(() => {
    const shown = shownEntries;
    if (!shown) return [];
    const out: FlatRow[] = [];
    shown.forEach((s, i) => {
      const e = s.e;
      if (s.gap) {
        // a break between blocks that are not adjacent in the file
        out.push({ ts: "", label: "", msg: "", entryIdx: i, first: false, sep: true, match: false });
      }
      const chunks =
        e.msg.length > MSG_CHUNK
          ? e.msg.match(new RegExp(`.{1,${MSG_CHUNK}}`, "g")) ?? [e.msg]
          : [e.msg];
      chunks.forEach((c, j) =>
        out.push({
          ts: j === 0 ? e.ts : "",
          label: j === 0 ? e.label : "",
          msg: c,
          entryIdx: i,
          first: j === 0,
          sep: false,
          match: s.match,
        })
      );
    });
    return out;
  }, [shownEntries]);

  // the highlight indexes into the unfiltered list, so it only applies when
  // the in-file search is not narrowing the view
  const hlEntryIdx =
    query.empty && highlightLine !== undefined ? highlightLine - 1 - offset : -1;
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
        <span className="log-title-path">{path}</span>
        <span className="log-title-actions">
          {structured && (
            <input
              className="log-search"
              type="search"
              placeholder='search this file…  ospf AND down · -A 3 · | $2 > 10000'
              title={
                "Same syntax as the archive search:\n" +
                "  AND / OR / NOT (also && || !), parentheses\n" +
                '  bare terms are regexes, "quoted" terms are literal\n' +
                "  -A n / -B n / -C n for lines after / before / around a match\n" +
                "  | $2 > 10000   filter by field value, like piping to awk\n" +
                "     $1, $2, … count from the message (timestamp and label skipped)\n" +
                "     $0 is the whole line; operators > >= < <= == != ~ !~\n" +
                "     combine with AND / OR, e.g. | $2 > 1000 AND $1 ~ userid\n" +
                "     -F sets the separator: | -F',' $3 > 500  (longer than one\n" +
                "     character is treated as a regex, e.g. -F'\\s*:\\s*')"
              }
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          )}
          {structured && !query.empty && (
            <span className="log-search-count">
              {matchCount} match{matchCount === 1 ? "" : "es"}
            </span>
          )}
          {structured && query.filterText && (
            <span className="log-filter-tag" title="Field filter applied to matches and context alike">
              | {query.filterText}
            </span>
          )}
          {structured && query.filterError && (
            <span className="log-filter-bad" title={query.filterError}>
              filter ignored
            </span>
          )}
          <button className="view-toggle" onClick={() => setStructured(!structured)}>
            {structured ? "Raw view" : "Table view"}
          </button>
          {onClose && (
            <button className="view-toggle log-close" onClick={onClose} title="Close this file">
              ✕
            </button>
          )}
        </span>
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
            {rows.slice(winStart, winEnd).map((r, k) =>
              r.sep ? (
                <div key={winStart + k} className="vt-row vt-sep">
                  <span className="vt-sep-mark">⋯</span>
                </div>
              ) : (
                <div
                  key={winStart + k}
                  className={
                    "vt-row" +
                    (r.entryIdx === hlEntryIdx && r.first ? " hl-vt" : "") +
                    (!query.empty && !r.match ? " vt-ctx" : "")
                  }
                >
                  <span className="lt-ts">{r.ts}</span>
                  <span className="lt-label">{r.label}</span>
                  <span className="lt-msg">{r.msg}</span>
                </div>
              )
            )}
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

/* ---------- App Stats tab ----------
   The per-application traffic table from "show running application
   statistics", with the shares and per-session ratios derived from it. */

interface AppStat {
  app: string;
  vsys: string;
  sessions: number;
  packets: number;
  bytes: number;
  app_changed: number;
  threats: number;
  sessions_pct: number;
  packets_pct: number;
  bytes_pct: number;
  app_changed_pct: number;
  threats_pct: number;
  packets_per_session: number;
  bytes_per_session: number;
  avg_packet_size: number;
}

interface AppStatsDoc {
  rows: AppStat[];
  vsyses: string[];
  source: string;
  names_resolved: boolean;
  total_sessions: number;
  total_packets: number;
  total_bytes: number;
  total_app_changed: number;
  total_threats: number;
  reported_sessions: number;
  reported_packets: number;
  reported_bytes: number;
}

type AppSortKey =
  | "app" | "vsys" | "sessions" | "packets" | "bytes" | "app_changed" | "threats"
  | "packets_per_session" | "bytes_per_session" | "avg_packet_size";

const APP_COLUMNS: { key: AppSortKey; label: string; pct?: keyof AppStat; int?: boolean }[] = [
  { key: "app", label: "Application" },
  { key: "vsys", label: "Vsys" },
  { key: "sessions", label: "Sessions", pct: "sessions_pct" },
  { key: "packets", label: "Packets", pct: "packets_pct" },
  { key: "bytes", label: "Bytes", pct: "bytes_pct" },
  { key: "app_changed", label: "App Changed", pct: "app_changed_pct" },
  { key: "threats", label: "Threats", pct: "threats_pct" },
  { key: "packets_per_session", label: "Pkts / Session" },
  { key: "bytes_per_session", label: "Bytes / Session" },
  { key: "avg_packet_size", label: "Avg Pkt Size" },
];

const fmtNum = (n: number) =>
  Number.isFinite(n) ? Math.round(n).toLocaleString() : "—";

const fmtBytesShort = (n: number) => {
  if (!Number.isFinite(n)) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let v = n, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? Math.round(v).toString() : v.toFixed(2)) + " " + u[i];
};

function AppStatsTab({ fileId }: { fileId: string }) {
  const [doc, setDoc] = useState<AppStatsDoc | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<AppSortKey>("bytes");
  const [asc, setAsc] = useState(false);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    fetch(`/api/v1/files/${fileId}/app-stats`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => setDoc(d.app_stats ?? null))
      .catch(() =>
        setErr("No application statistics — 'show running application statistics' was not in this archive's CLI dump.")
      );
  }, [fileId]);

  const rows = useMemo(() => {
    if (!doc) return [];
    const f = filter.trim().toLowerCase();
    const list = f ? doc.rows.filter((r) => r.app.toLowerCase().includes(f)) : doc.rows.slice();
    list.sort((a, b) => {
      // text columns compare lexically, every other column numerically, and
      // each is sortable in both directions
      if (sortKey === "app" || sortKey === "vsys") {
        const av = String(a[sortKey]), bv = String(b[sortKey]);
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      }
      const av = a[sortKey] as number, bv = b[sortKey] as number;
      return asc ? av - bv : bv - av;
    });
    return list;
  }, [doc, sortKey, asc, filter]);

  const sortBy = (k: AppSortKey) => {
    if (k === sortKey) setAsc(!asc);
    else { setSortKey(k); setAsc(false); }
  };

  if (err) return <section><h2>App Stats</h2><p className="error">{err}</p></section>;
  if (!doc) return <section><h2>App Stats</h2><p className="muted">Loading…</p></section>;

  return (
    <section>
      <h2>App Stats</h2>
      <div className="cfg-source">
        <span className="cfg-source-path">{doc.source || "—"}</span>
        {doc.source === "panio_infreq" && (
          <span className="cfg-local-badge">dataplane · time series</span>
        )}
        {!doc.names_resolved && (
          <span className="app-unnamed" title="opt/pancfg/mgmt/updates/curcontent/.../global.xml was not in this archive, so applications are shown by numeric ID">
            application IDs unresolved
          </span>
        )}
      </div>
      <div className="mem-stats">
        <Stat label="Applications" value={doc.rows.length.toLocaleString()} />
        <Stat label="Sessions" value={fmtNum(doc.total_sessions)} />
        <Stat label="Packets" value={fmtNum(doc.total_packets)} />
        <Stat label="Bytes" value={fmtBytesShort(doc.total_bytes)} />
        <Stat label="App Changed" value={fmtNum(doc.total_app_changed)} />
        <Stat label="Threats" value={fmtNum(doc.total_threats)} />
        {doc.vsyses.length > 0 && <Stat label="Vsys" value={doc.vsyses.join(", ")} />}
      </div>
      <div className="anom-search">
        <input
          className="search-input"
          type="search"
          placeholder="Filter applications…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        {filter.trim() !== "" && (
          <span className="anom-search-count muted">{rows.length} of {doc.rows.length}</span>
        )}
      </div>
      <div className="cfg-table-wrap">
        <table className="cfg-table app-table">
          <thead>
            <tr>
              {APP_COLUMNS.map((c) => (
                <th
                  key={c.key}
                  className="app-th"
                  onClick={() => sortBy(c.key)}
                  title="Click to sort"
                >
                  {c.label}
                  {sortKey === c.key && <span className="app-sort">{asc ? " ▲" : " ▼"}</span>}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={r.app + r.vsys + i}>
                <td className="cfg-name">{r.app}</td>
                <td>{r.vsys || "—"}</td>
                <td>{fmtNum(r.sessions)}<span className="app-pct">{r.sessions_pct.toFixed(2)}%</span></td>
                <td>{fmtNum(r.packets)}<span className="app-pct">{r.packets_pct.toFixed(2)}%</span></td>
                <td>{fmtBytesShort(r.bytes)}<span className="app-pct">{r.bytes_pct.toFixed(2)}%</span></td>
                <td>{fmtNum(r.app_changed)}<span className="app-pct">{r.app_changed_pct.toFixed(2)}%</span></td>
                <td>{fmtNum(r.threats)}<span className="app-pct">{r.threats_pct.toFixed(2)}%</span></td>
                <td>{fmtNum(r.packets_per_session)}</td>
                <td>{fmtBytesShort(r.bytes_per_session)}</td>
                <td>{fmtNum(r.avg_packet_size)}</td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr><td colSpan={APP_COLUMNS.length}><span className="muted">No applications match.</span></td></tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/* ---------- Licenses tab ---------- */

interface LicenseRow {
  feature: string;
  description: string;
  serial: string;
  authcode?: string;
  issued?: string;
  expires?: string;
  expired?: string;
  base_license?: string;
  other?: KV[];
}

function LicensesTab({ fileId }: { fileId: string }) {
  const [lics, setLics] = useState<LicenseRow[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    fetch(`/api/v1/files/${fileId}/licenses`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => setLics(d.licenses ?? []))
      .catch(() =>
        setErr("No licence information — 'request license info' was not in this archive's CLI dump.")
      );
  }, [fileId]);

  if (err) return <section><h2>Licenses</h2><p className="error">{err}</p></section>;
  if (!lics) return <section><h2>Licenses</h2><p className="muted">Loading…</p></section>;

  const expiredCount = lics.filter((l) => (l.expired ?? "").toLowerCase() === "yes").length;

  return (
    <section>
      <h2>Licenses</h2>
      <div className="mem-stats">
        <Stat label="Installed" value={String(lics.length)} />
        <Stat label="Expired" value={String(expiredCount)} bad={expiredCount > 0} />
      </div>
      <div className="cfg-table-wrap">
        <table className="cfg-table">
          <thead>
            <tr>
              <th>Feature</th>
              <th>Description</th>
              <th>Expires</th>
              <th>Expired</th>
              <th>Issued</th>
              <th>Serial</th>
              <th>Auth Code</th>
              <th>Base</th>
              <th>Other</th>
            </tr>
          </thead>
          <tbody>
            {lics.map((l, i) => {
              const isExpired = (l.expired ?? "").toLowerCase() === "yes";
              return (
                <tr key={l.feature + i} className={isExpired ? "lic-expired" : ""}>
                  <td className="cfg-name">{l.feature || "—"}</td>
                  <td>{l.description || "—"}</td>
                  <td>{l.expires || "—"}</td>
                  <td>
                    {l.expired
                      ? <span className={"sev " + (isExpired ? "sev-high" : "sev-low")}>{l.expired}</span>
                      : "—"}
                  </td>
                  <td>{l.issued || "—"}</td>
                  <td className="mem-src">{l.serial || "—"}</td>
                  <td className="mem-src">{l.authcode || "—"}</td>
                  <td>{l.base_license || "—"}</td>
                  <td className="muted">
                    {(l.other ?? []).map((kv) => `${kv.key}: ${kv.value}`).join(" · ") || "—"}
                  </td>
                </tr>
              );
            })}
            {lics.length === 0 && (
              <tr><td colSpan={9}><span className="muted">No licences found.</span></td></tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
