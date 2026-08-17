// Parity harness for the awk-style field filter.
//
// The clause is implemented twice — Go (parser/fieldfilter.go) for the
// archive search, TypeScript (App.tsx) for the in-file search — and the same
// query typed in either box must give the same answer. This script extracts
// the real TypeScript source out of App.tsx, transpiles it, and compares it
// against a transcription of the Go logic on a grid of lines x clauses.
//
// Divergence here means one of the two boxes is lying to the user.

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const ROOT = new URL("..", import.meta.url).pathname;
const TSC = "/usr/local/lib/node_modules_global/lib/node_modules/typescript/bin/tsc";
const WORK = "/tmp/ffparity";

/* ---------- pull the real TS out of App.tsx ---------- */

const app = readFileSync(ROOT + "frontend/src/App.tsx", "utf8");
const start = app.indexOf("/* ---------- awk-style field filter");
const end = app.indexOf("function parseLineQuery(");
if (start < 0 || end < 0 || end <= start) {
  console.error("FAIL: could not locate the field-filter section in App.tsx");
  process.exit(1);
}
const section = app.slice(start, end);
for (const name of [
  "messageFields", "messageStart", "messageFieldsSep", "parseSeparator",
  "fieldNumber", "parseFieldFilter", "splitFieldClause",
]) {
  if (!section.includes(`function ${name}`)) {
    console.error(`FAIL: ${name} is not inside the extracted section`);
    process.exit(1);
  }
}

mkdirSync(WORK, { recursive: true });
writeFileSync(
  `${WORK}/ts.ts`,
  section +
    "\nexport { messageFields, messageStart, messageFieldsSep, parseSeparator," +
    " fieldNumber, parseFieldFilter, splitFieldClause };\n"
);
execFileSync("node", [TSC, `${WORK}/ts.ts`, "--target", "es2020", "--module", "esnext", "--skipLibCheck"], {
  stdio: "inherit",
});
const ts = await import(pathToFileURL(`${WORK}/ts.js`).href);

/* ---------- transcription of the Go implementation ---------- */

const GO_TS_DATE = /^\d{4}[-/]\d{2}[-/]\d{2}([T ]|$)/;
const GO_TS_TIME = /^\d{1,2}:\d{2}(:\d{2})?([.,]\d+)?$/;
const GO_TS_MON = /^(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)$/i;
const GO_TS_DAY = /^\d{1,2}$/;
const GO_LABEL = /^(critical|high|medium|low|informational|info|debug|warn|warning|error|err|notice|alert|emerg)$/i;

function goIsBareWord(s) {
  if (!s || (s[0] >= "0" && s[0] <= "9")) return false;
  return /^[A-Za-z0-9_-]+$/.test(s);
}

function goMessageStart(line) {
  const toks = [];
  const re = /[^\s]+/g;
  let m;
  while ((m = re.exec(line)) !== null) toks.push({ s: m[0], off: m.index });
  let i = 0;
  if (i < toks.length && GO_TS_DATE.test(toks[i].s)) i++;
  else if (i + 1 < toks.length && GO_TS_MON.test(toks[i].s) && GO_TS_DAY.test(toks[i + 1].s)) i += 2;
  if (i < toks.length && GO_TS_TIME.test(toks[i].s)) i++;
  if (i > 0) {
    if (i < toks.length && GO_LABEL.test(toks[i].s)) {
      i++;
      if (i < toks.length && goIsBareWord(toks[i].s)) i++;
    }
  }
  return i >= toks.length ? line.length : toks[i].off;
}

function goMessageFields(line) {
  const msg = line.slice(goMessageStart(line));
  return msg.trim() === "" ? [] : msg.split(/\s+/).filter(Boolean);
}

function goMessageFieldsSep(line, sep) {
  const msg = line.slice(goMessageStart(line));
  if (msg === "") return [];
  return msg.split(sep).map((s) => s.trim());
}

const GO_SEP_FLAG = /^-F\s*('[^']*'|"[^"]*"|\S+)\s*/;

function goParseSeparator(arg) {
  const shown = arg;
  let a = arg;
  if (a.length >= 2 && (a[0] === "'" || a[0] === '"') && a[a.length - 1] === a[0]) {
    a = a.slice(1, -1);
  }
  a = a.replace(/\\t/g, "\t").replace(/\\n/g, "\n").replace(/\\\\/g, "\\");
  if (a === "") return { re: null, shown, error: "empty -F separator" };
  if (a === " " || a === "\t") return { re: /\s+/, shown, error: "" };
  const quote = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if ([...a].length === 1) return { re: new RegExp(quote(a)), shown, error: "" };
  try { return { re: new RegExp(a), shown, error: "" }; }
  catch { return { re: new RegExp(quote(a)), shown, error: "" }; }
}

// mirrors parseFieldNumber: leading numeric run, trailing .+- trimmed
function goFieldNumber(s) {
  s = s.trim();
  let end = 0;
  while (end < s.length) {
    const c = s[end];
    if ((c >= "0" && c <= "9") || c === "." || c === "-" || c === "+") { end++; continue; }
    break;
  }
  if (end === 0) return null;
  const v = parseFloat(s.slice(0, end).replace(/[.+-]+$/, ""));
  return Number.isFinite(v) ? v : null;
}

const GO_COND = /^\$(\d+)\s*(!~|~|>=|<=|==|!=|=|>|<)\s*(.+)$/;

function goSplitKeyword(s, kw) {
  const out = [];
  let cur = [];
  for (const w of s.split(/\s+/).filter(Boolean)) {
    if (w.toUpperCase() === kw) { out.push(cur.join(" ")); cur = []; continue; }
    cur.push(w);
  }
  out.push(cur.join(" "));
  return out;
}

function goParseCond(s) {
  s = s.trim();
  const m = GO_COND.exec(s);
  if (!m) return s === "" ? "empty condition" : "bad";
  const field = parseInt(m[1], 10);
  let op = m[2];
  if (op === "=") op = "==";
  let rhs = m[3].trim().replace(/^["']|["']$/g, "");
  if (!rhs) return "bad";
  if (op === "~" || op === "!~") {
    try { return { field, op, re: new RegExp(rhs, "i"), num: null, str: "" }; }
    catch { return "bad"; }
  }
  const num = goFieldNumber(rhs);
  return { field, op, re: null, num, str: rhs.toLowerCase() };
}

function goParseFilter(clause) {
  clause = clause.trim();
  if (!clause) return { active: false, keep: () => true, error: "" };
  let sepRe = null;
  const sm = GO_SEP_FLAG.exec(clause);
  if (sm) {
    const parsed = goParseSeparator(sm[1]);
    if (parsed.error) return { active: false, keep: () => true, error: parsed.error };
    sepRe = parsed.re;
    clause = clause.slice(sm[0].length).trim();
    if (!clause) {
      return { active: false, keep: () => true, error: "-F given with no condition after it" };
    }
  }
  const groups = [];
  for (const orPart of goSplitKeyword(clause, "OR")) {
    const group = [];
    for (const andPart of goSplitKeyword(orPart, "AND")) {
      const c = goParseCond(andPart);
      if (typeof c === "string") return { active: false, keep: () => true, error: c };
      group.push(c);
    }
    if (group.length === 0) return { active: false, keep: () => true, error: "empty" };
    groups.push(group);
  }
  const evalCond = (c, line, fields) => {
    let val;
    if (c.field === 0) val = line;
    else if (c.field <= fields.length) val = fields[c.field - 1];
    else return false;
    if (c.op === "~") return c.re !== null && c.re.test(val);
    if (c.op === "!~") return c.re !== null && !c.re.test(val);
    if (c.num !== null) {
      const n = goFieldNumber(val);
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
    keep: (line) => {
      const fields = sepRe ? goMessageFieldsSep(line, sepRe) : goMessageFields(line);
      return groups.some((g) => g.every((c) => evalCond(c, line, fields)));
    },
  };
}

function goSplitClause(raw) {
  for (let i = raw.length - 1; i >= 0; i--) {
    if (raw[i] !== "|") continue;
    if (i > 0 && raw[i - 1] === "|") continue;
    const rest = raw.slice(i + 1).trim();
    if (rest.startsWith("$") || rest.startsWith("-F")) return [raw.slice(0, i).trim(), rest];
  }
  return [raw, ""];
}

/* ---------- the grid ---------- */

const lines = [
  "2026/08/04 21:00:20 medium general pkt_recv 4523",
  "2026-08-04T21:00:20 high routing BGP peer 10.9.9.9 reset",
  "Aug  4 21:00:20 critical general kernel: Out of memory: Killed process 1234 (reportd)",
  "pkt_recv                4523",
  "rx_packets 5",
  "rx_bytes 25000",
  "tx_packets 900000",
  "21:00:20 mp process useridd 1400000",
  "error count 12",
  "2026/08/04 21:00:20 4523 6789",
  "mem 1400000kB free 85% used 12.5",
  "--- pkt_recv counters ---",
  "n/a n/a n/a",
  "",
  "   ",
  "single",
  "tab\tseparated\t99",
  "negative -3 value",
  // separator-delimited shapes
  "a,25000,c",
  "a, 25000 ,c",
  "a,,25000",
  "a;25000;c",
  "a:25000:c",
  "a::25000::c",
  "a  :  25000  :  c",
  "2026/08/04 21:00:20 medium general a,25000,c",
  "one,two",
  ",leading,empty",
  "trailing,empty,",
];

const clauses = [
  "$1 > 10", "$2 > 10", "$2 > 10000", "$2 >= 4523", "$2 < 100", "$2 <= 0",
  "$2 == 4523", "$2 != 4523", "$0 ~ medium", "$0 !~ medium", "$1 ~ ^pkt",
  "$1 == pkt_recv", "$1 == PKT_RECV", "$1 != pkt_recv", "$1 < zzz", "$3 > 1",
  "$9 > 1", "$0 ~ [0-9]+", "$2 > 10 AND $1 ~ pkt", "$2 > 99999 OR $1 ~ rx",
  "$1 ~ recv AND $2 > 1000 AND $0 ~ 2026", "$2 > 1 OR $2 < 0",
  // -F separators
  "-F',' $2 > 10000", "-F',' $2 > 99999", "-F, $2 > 10000", `-F"," $1 == a`,
  "-F';' $2 > 10000", "-F: $2 > 10000", `-F'\\t' $2 > 10`,
  `-F'\\s*:\\s*' $2 > 10000`, "-F'::' $2 > 10000", `-F',' $2 ~ ^$`,
  "-F',' $3 > 10000", "-F',' $1 ~ a AND $2 > 100", "-F' ' $2 > 10",
  // malformed clauses: both sides must ignore them identically
  "$2 >", "$ > 10", "2 > 10", "$2 10", "$2 ~ [unclosed", "$2 > 10 AND garbage",
  "-F", "-F''", `-F""`, "-F','", "-F',' garbage", "-F',' $2 >",
  "", "   ",
];

const rawQueries = [
  "pkt_recv | $2 > 10", "pkt_recv -A 10 | $2 > 10000", "pkt_recv",
  "ospf|bgp", "ospf || bgp", "a|b | $1 > 2", "$notafield", "x | $0 ~ y | $1 > 3",
  "sessions | -F',' $3 > 500", "sessions -A 5 | -F: $2 ~ down", "a | b",
  // the separator is itself a pipe: the split must still find the real one
  "x | -F'|' $2 > 3",
];

let failures = 0;
const fail = (msg) => { console.log("FAIL  " + msg); failures++; };

// 1. field splitting, default and with each separator
let fieldMismatch = 0;
for (const line of lines) {
  const a = ts.messageFields(line);
  const b = goMessageFields(line);
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    fieldMismatch++;
    fail(`messageFields(${JSON.stringify(line)}): ts=${JSON.stringify(a)} go=${JSON.stringify(b)}`);
  }
  if (ts.messageStart(line) !== goMessageStart(line)) {
    fieldMismatch++;
    fail(`messageStart(${JSON.stringify(line)}): ts=${ts.messageStart(line)} go=${goMessageStart(line)}`);
  }
}
for (const sepArg of ["','", ",", ";", ":", "'::'", `'\\t'`, `'\\s*:\\s*'`, "'|'", "' '"]) {
  const a = ts.parseSeparator(sepArg);
  const b = goParseSeparator(sepArg);
  if (String(a.re) !== String(b.re) || Boolean(a.error) !== Boolean(b.error)) {
    fieldMismatch++;
    fail(`parseSeparator(${sepArg}): ts=${a.re}/${a.error} go=${b.re}/${b.error}`);
    continue;
  }
  if (!a.re) continue;
  for (const line of lines) {
    const fa = ts.messageFieldsSep(line, a.re);
    const fb = goMessageFieldsSep(line, b.re);
    if (JSON.stringify(fa) !== JSON.stringify(fb)) {
      fieldMismatch++;
      fail(`-F${sepArg} on ${JSON.stringify(line)}: ts=${JSON.stringify(fa)} go=${JSON.stringify(fb)}`);
    }
  }
}
if (!fieldMismatch) {
  console.log(`PASS  field splitting agrees on all ${lines.length} lines, whitespace and -F alike`);
}

// 2. clause parsing: active/ignored must match
let parseMismatch = 0;
for (const c of clauses) {
  const a = ts.parseFieldFilter(c);
  const b = goParseFilter(c);
  if (a.active !== b.active) {
    parseMismatch++;
    fail(`clause ${JSON.stringify(c)}: ts.active=${a.active} go.active=${b.active}`);
  }
  if (Boolean(a.error) !== Boolean(b.error)) {
    parseMismatch++;
    fail(`clause ${JSON.stringify(c)}: ts.error=${JSON.stringify(a.error)} go.error=${JSON.stringify(b.error)}`);
  }
}
if (!parseMismatch) console.log(`PASS  clause parsing agrees on all ${clauses.length} clauses (valid and malformed)`);

// 3. the grid: every clause against every line
let cells = 0, gridMismatch = 0;
for (const c of clauses) {
  const a = ts.parseFieldFilter(c);
  const b = goParseFilter(c);
  for (const line of lines) {
    cells++;
    const ka = a.keep(line);
    const kb = b.keep(line);
    if (ka !== kb) {
      gridMismatch++;
      if (gridMismatch <= 10) {
        fail(`${JSON.stringify(c)} on ${JSON.stringify(line)}: ts=${ka} go=${kb}`);
      }
    }
  }
}
if (!gridMismatch) console.log(`PASS  ${cells} clause x line decisions identical`);

// 4. splitting the query from its clause
let splitMismatch = 0;
for (const raw of rawQueries) {
  const a = ts.splitFieldClause(raw);
  const b = goSplitClause(raw);
  if (a[0] !== b[0] || a[1] !== b[1]) {
    splitMismatch++;
    fail(`splitFieldClause(${JSON.stringify(raw)}): ts=${JSON.stringify(a)} go=${JSON.stringify(b)}`);
  }
}
if (!splitMismatch) console.log(`PASS  query/clause splitting agrees on all ${rawQueries.length} inputs`);

// 5. a malformed clause must keep every line, on both sides
let inertMismatch = 0;
for (const c of ["$2 >", "$ > 10", "$2 ~ [unclosed", "$2 > 10 AND garbage"]) {
  for (const line of lines) {
    if (!ts.parseFieldFilter(c).keep(line) || !goParseFilter(c).keep(line)) {
      inertMismatch++;
      fail(`malformed clause ${JSON.stringify(c)} filtered ${JSON.stringify(line)}`);
    }
  }
}
if (!inertMismatch) console.log("PASS  malformed clauses keep every line on both sides");

console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
