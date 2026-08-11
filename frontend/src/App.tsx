import { Fragment, useEffect, useMemo, useRef, useState } from "react";
// aliased so it doesn't shadow the DOM MouseEvent the dygraphs interaction
// models are typed against
import type { MouseEvent as ReactMouseEvent } from "react";
import Dygraph from "dygraphs";
import "dygraphs/dist/dygraph.css";

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

interface CounterPoint {
  name: string;
  ts: string;
  value: number;
}

const MAX_PLOT = 8;

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

type SeriesMode = "val" | "del" | "rate";

interface SelEntry {
  name: string;
  mode: SeriesMode;
}

const selKey = (s: SelEntry) => (s.mode === "val" ? s.name : `${s.name} (${s.mode})`);

// del = difference between consecutive samples; rate = del per second
function transformSeries(pts: CounterPoint[], mode: SeriesMode): CounterPoint[] {
  if (mode === "val") return pts;
  const out: CounterPoint[] = [];
  for (let i = 1; i < pts.length; i++) {
    const dv = pts[i].value - pts[i - 1].value;
    const dt = (Date.parse(pts[i].ts) - Date.parse(pts[i - 1].ts)) / 1000;
    out.push({
      name: pts[i].name,
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
  const [view, setView] = useState<"counters" | "anomalies">("counters");
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
      </div>
      {view === "counters" ? <CounterGraphs fileId={fileId} /> : <AnomaliesView fileId={fileId} />}
    </section>
  );
}

function CounterGraphs({ fileId }: { fileId: string }) {
  const [counters, setCounters] = useState<CounterMeta[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [marks, setMarks] = useState<Mark[]>([]);
  // shared x-axis window: zooming one panel zooms both
  const [xRange, setXRange] = useState<[number, number] | null>(null);

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
      <GraphPanel fileId={fileId} counters={counters} onMark={addMark} xRange={xRange} onXRange={setXRange} />
      <GraphPanel fileId={fileId} counters={counters} onMark={addMark} xRange={xRange} onXRange={setXRange} />
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

function AnomaliesView({ fileId }: { fileId: string }) {
  const [groups, setGroups] = useState<AnomalyGroup[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
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
  const ordered = useMemo(() => {
    if (!groups) return null;
    return [...groups].sort((a, b) => {
      const d = severityRank(b.severity) - severityRank(a.severity);
      return d !== 0 ? d : b.count - a.count;
    });
  }, [groups]);

  const active = selected !== null ? ordered?.[selected] ?? null : null;

  return (
    <div className="anom-wrap">
      {err && <p className="error">{err}</p>}
      {!ordered && !err && <p className="muted">Loading…</p>}
      {ordered && ordered.length === 0 && <p className="muted">No recurring events found in the system log.</p>}
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
                    className={"anom-row" + (i === selected ? " active" : "")}
                    onClick={() => setSelected(i)}
                  >
                    <td className="anom-label" title={g.sample}>{g.label}</td>
                    <td>{g.subtype}</td>
                    <td>
                      <span className={"sev sev-" + g.severity.toLowerCase()}>{g.severity}</span>
                    </td>
                    <td>{g.count}</td>
                    <td>
                      {g.occurrences.length
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
function AnomalyChart({
  group,
  onMark,
}: {
  group: AnomalyGroup;
  onMark: (ts: string, lines: string[]) => void;
}) {
  const chartRef = useRef<HTMLDivElement | null>(null);
  const chartInst = useRef<Dygraph | null>(null);
  const [hoverTs, setHoverTs] = useState<number | null>(null);
  const [picked, setPicked] = useState<number | null>(null);

  // collapse duplicate timestamps into one point carrying the occurrence
  // count, so simultaneous events show as a taller dot instead of
  // overplotting invisibly at y=1; keep every raw message per timestamp so
  // a click can show exactly which file/neighbor/tunnel it was about
  const { rows, byTs } = useMemo(() => {
    const m = new Map<number, string[]>();
    for (const o of group.occurrences ?? []) {
      const ms = Date.parse(o.ts);
      if (Number.isNaN(ms)) continue;
      const list = m.get(ms);
      if (list) list.push(o.description);
      else m.set(ms, [o.description]);
    }
    const sorted = Array.from(m.entries()).sort((a, b) => a[0] - b[0]);
    return {
      rows: sorted.map(([ms, list]) => [new Date(ms), list.length]),
      byTs: m,
    };
  }, [group]);

  // reset the pinned message when switching to a different event
  useEffect(() => setPicked(null), [group]);

  // nearest plotted timestamp to the crosshair, so a click near a dot still
  // resolves to that dot
  const nearestTs = (t: number): number | null => {
    let best: number | null = null;
    let bestD = Infinity;
    for (const ms of byTs.keys()) {
      const d = Math.abs(ms - t);
      if (d < bestD) {
        bestD = d;
        best = ms;
      }
    }
    return best;
  };

  useEffect(() => {
    const el = chartRef.current;
    if (!el || rows.length === 0) return;

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

    const maxY = Math.max(...rows.map((r) => r[1] as number));
    const g = new Dygraph(el, rows as unknown as number[][], {
      labels: ["time", "Occurrences"],
      colors: ["#dc2626"],
      labelsUTC: true,
      legend: "never",
      // point-only: the dots are the data, lines between them would imply
      // a continuous series that doesn't exist
      strokeWidth: 0,
      drawPoints: true,
      pointSize: 3.5,
      highlightCircleSize: 5,
      includeZero: true,
      valueRange: [0, maxY + 1],
      axisLineColor: "#d4d4d8",
      gridLineColor: "#ececef",
      axisLabelFontSize: 11,
      interactionModel: interactionModel as unknown as Record<string, unknown>,
      highlightCallback: (_e, x) => setHoverTs(x),
      unhighlightCallback: () => setHoverTs(null),
    } as ConstructorParameters<typeof Dygraph>[2]);
    chartInst.current = g;

    const onResize = () => g.resize();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      g.destroy();
      chartInst.current = null;
    };
  }, [rows]);

  if (rows.length === 0) return <p className="muted">No timestamps to plot.</p>;

  const pickedLines = picked !== null ? byTs.get(picked) ?? [] : [];

  const handleClick = (e: ReactMouseEvent) => {
    if (hoverTs === null) return;
    const ts = nearestTs(hoverTs);
    if (ts === null) return;
    if (e.altKey) {
      onMark(new Date(ts).toISOString(), byTs.get(ts) ?? []);
      return;
    }
    setPicked(ts);
  };

  return (
    <div className="anom-chart">
      {/* the clicked incident's original log text sits above the graph */}
      <div className={"anom-picked" + (picked === null ? " anom-picked-empty" : "")}>
        {picked === null ? (
          <span className="muted">Click a point to see its original system-log message.</span>
        ) : (
          <>
            <div className="anom-picked-ts">{new Date(picked).toLocaleString()}</div>
            {pickedLines.map((l, i) => (
              <div key={i} className="anom-picked-msg">{l}</div>
            ))}
          </>
        )}
      </div>
      <div className="anom-chart-head">
        <span className="muted">{group.count} occurrences</span>
        <span className="graph-hover-ts">{hoverTs !== null ? fmtReadoutTs(hoverTs) : ""}</span>
        <button className="btn-outline" onClick={() => chartInst.current?.resetZoom()}>
          Reset zoom
        </button>
      </div>
      <div onClick={handleClick}>
        <div ref={chartRef} className="anom-chart-canvas" />
      </div>
      <div className="graph-hint">
        Click a point for its log message · <kbd>Shift</kbd> + drag to zoom · double-click to reset ·{" "}
        <kbd>Alt</kbd>/<kbd>Option</kbd> + click to note it
      </div>
    </div>
  );
}

/* one lookup → selected → plot row, monparse-style */
function GraphPanel({
  fileId,
  counters,
  onMark,
  xRange,
  onXRange,
}: {
  fileId: string;
  counters: CounterMeta[];
  onMark: (t: number, rows: MarkRow[]) => void;
  xRange: [number, number] | null;
  onXRange: (r: [number, number] | null) => void;
}) {
  const [filter, setFilter] = useState("");
  const [sel, setSel] = useState<SelEntry[]>([]);
  const [data, setData] = useState<Record<string, CounterPoint[]>>({});
  const [hidden, setHidden] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);

  const shown = useMemo(() => {
    const f = filter.trim();
    const list = f ? counters.filter(parseLookup(f).matches) : counters;
    return list.slice(0, 300);
  }, [counters, filter]);

  const add = (name: string, mode: SeriesMode) => {
    setErr(null);
    setSel((s) => {
      if (s.length >= MAX_PLOT || s.some((e) => e.name === name && e.mode === mode)) return s;
      return [...s, { name, mode }];
    });
    if (!data[name]) {
      fetch(`/api/v1/files/${fileId}/counters/data?names=${encodeURIComponent(name)}`)
        .then((r) => (r.ok ? r.json() : Promise.reject()))
        .then((d) => setData((prev) => ({ ...prev, ...(d.series ?? {}) })))
        .catch(() => setErr(`Could not load ${name}`));
    }
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
          <span>Selected ({sel.length}/{MAX_PLOT})</span>
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
}: {
  series: Record<string, CounterPoint[]>;
  hidden: string[];
  onToggle: (key: string) => void;
  onMark: (t: number, rows: MarkRow[]) => void;
  xRange: [number, number] | null;
  onXRange: (r: [number, number] | null) => void;
}) {
  const [hoverTs, setHoverTs] = useState<number | null>(null);
  const chartRef = useRef<HTMLDivElement | null>(null);
  const chartInst = useRef<Dygraph | null>(null);
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
    const el = chartRef.current;
    if (!el || dyData.rows.length === 0) return;

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

    const onResize = () => g.resize();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      g.destroy();
      chartInst.current = null;
    };
  }, [dyData]);

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
          <button className="btn-outline" onClick={resetZoom}>
            Reset zoom
          </button>
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
        <div ref={chartRef} className="graph-canvas" />
      </div>
      <div className="graph-hint graph-hint-bottom">
        Hold <kbd>Shift</kbd> + drag to zoom (both charts follow) · double-click to reset · <kbd>Alt</kbd>/<kbd>Option</kbd> + click records a time mark
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
  const [config, setConfig] = useState<ConfigNode | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [groupId, setGroupId] = useState("policies");
  const [sectionIdx, setSectionIdx] = useState(0);

  useEffect(() => {
    fetch(`/api/v1/files/${fileId}/config`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => setConfig(d.config ?? null))
      .catch(() =>
        setErr("No config extracted for this file — was a PAN-OS running-config.xml present in this archive?")
      );
  }, [fileId]);

  const group = CONFIG_GROUPS.find((g) => g.id === groupId) ?? CONFIG_GROUPS[0];
  const section = group.sections[sectionIdx] ?? group.sections[0];

  return (
    <section>
      <h2>Config</h2>
      <p className="muted cfg-hint">Read-only view of the parsed running config — browse it the way you would in the firewall's own UI.</p>
      {err && <p className="error">{err}</p>}
      {!config && !err && <p className="muted">Loading…</p>}
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
  const entries = useMemo(() => sectionEntries(config, section.tag, section.parentTag), [config, section]);
  const columns = useMemo(() => section.columns ?? genericColumns(entries), [section, entries]);
  return <ConfigEntryTable entries={entries} columns={columns} root={config} expandable={section.expandable} />;
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
      <ConfigEntryTable entries={entries} columns={IFACE_COLUMNS} root={config} />
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
  entries,
  columns,
  root,
  expandable,
}: {
  entries: ConfigNode[];
  columns: ColumnSpec[];
  root?: ConfigNode;
  expandable?: boolean;
}) {
  const [expanded, setExpanded] = useState<number | null>(null);
  if (entries.length === 0) {
    return <p className="muted">Not present in this config (or none configured).</p>;
  }
  return (
    <div className="cfg-table-wrap">
      <table className="cfg-table">
        <thead>
          <tr>
            <th>Name</th>
            {columns.map((c) => (
              <th key={c.header}>{c.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {entries.map((e, i) => (
            <Fragment key={(e.attrs?.name ?? "") + "_" + i}>
              <tr
                className={expandable ? "cfg-row-clickable" : ""}
                onClick={expandable ? () => setExpanded(expanded === i ? null : i) : undefined}
              >
                <td className="cfg-name">{e.attrs?.name ?? "—"}</td>
                {columns.map((c) => (
                  <td key={c.header}>{c.get(e, root) || "—"}</td>
                ))}
              </tr>
              {expandable && expanded === i && (
                <tr>
                  <td colSpan={columns.length + 1} className="cfg-expand-cell">
                    <div className="cfg-kv">
                      {flattenKv(e).map((r, k) => (
                        <div key={k} className="cfg-kv-row" style={{ paddingLeft: r.depth * 16 }}>
                          <span className="cfg-kv-key">{r.key}</span>
                          <span className="cfg-kv-val">{r.value}</span>
                        </div>
                      ))}
                    </div>
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
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
