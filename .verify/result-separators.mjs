// Checks the separator logic for search results.
//
// Two places had blocks running together with nothing between them: the
// archive-search result list (continuesPrevious, extracted from App.tsx and
// exercised directly) and the maximized in-file table, whose row pipeline is
// simulated here because it lives inside a component.

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const ROOT = new URL("..", import.meta.url).pathname;
const TSC = "/usr/local/lib/node_modules_global/lib/node_modules/typescript/bin/tsc";
const WORK = "/tmp/sepcheck";

/* ---------- the real continuesPrevious out of App.tsx ---------- */

const app = readFileSync(ROOT + "frontend/src/App.tsx", "utf8");
const start = app.indexOf("/* Two results continue one another");
const end = app.indexOf("interface LineQuery");
if (start < 0 || end < 0) {
  console.error("FAIL: could not locate continuesPrevious in App.tsx");
  process.exit(1);
}
mkdirSync(WORK, { recursive: true });
writeFileSync(
  `${WORK}/sep.ts`,
  `interface ContextLine { line_no: number; text: string; before: boolean }
interface SearchResult { type: "file" | "line"; path: string; line_no?: number; text?: string; context?: ContextLine[]; filtered?: boolean }
` +
    app.slice(start, end) +
    "\nexport { continuesPrevious };\n"
);
execFileSync("node", [TSC, `${WORK}/sep.ts`, "--target", "es2020", "--module", "esnext", "--skipLibCheck"], {
  stdio: "inherit",
});
const { continuesPrevious } = await import(pathToFileURL(`${WORK}/sep.js`).href);

let failures = 0;
const check = (ok, msg) => { console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`); if (!ok) failures++; };

const line = (path, n, ctx = []) => ({
  type: "line", path, line_no: n, text: `line ${n}`,
  context: ctx.map((c) => ({ line_no: c, text: `line ${c}`, before: c < n })),
});

check(continuesPrevious(line("a.log", 10), line("a.log", 11)) === true,
  "adjacent lines in one file are one block");
check(continuesPrevious(line("a.log", 10), line("a.log", 12)) === false,
  "a one-line gap starts a new block");
check(continuesPrevious(line("a.log", 10), line("b.log", 11)) === false,
  "a different file always starts a new block");
check(continuesPrevious(line("a.log", 10, [11, 12]), line("a.log", 13)) === true,
  "trailing -A context closes the gap to the next match");
check(continuesPrevious(line("a.log", 10, [11, 12]), line("a.log", 20)) === false,
  "a match beyond the -A context starts a new block");
check(continuesPrevious(line("a.log", 10), line("a.log", 14, [12, 13])) === false,
  "leading -B context that does not reach the previous line still breaks");
check(continuesPrevious(line("a.log", 10), line("a.log", 13, [11, 12])) === true,
  "leading -B context that reaches the previous line joins the block");
check(continuesPrevious({ type: "file", path: "a.log" }, line("a.log", 3)) === false,
  "a filename hit never merges with a line hit");

/* ---------- the in-file table pipeline ---------- */

// mirrors shownEntries + rows in App.tsx
function buildRows(entries, opts) {
  const { matchIdx, before, after, keep } = opts;
  const matched = new Set(matchIdx);
  const kept = new Set();
  for (const i of matchIdx) {
    kept.add(i);
    for (let k = 1; k <= before; k++) if (i - k >= 0) kept.add(i - k);
    for (let k = 1; k <= after; k++) if (i + k < entries.length) kept.add(i + k);
  }
  const shown = [];
  let prev = -1;
  for (let i = 0; i < entries.length; i++) {
    if (!kept.has(i)) continue;
    if (keep && !keep(entries[i])) continue;
    shown.push({ e: entries[i], match: matched.has(i), gap: prev >= 0 && i > prev + 1 });
    prev = i;
  }
  const rows = [];
  for (const s of shown) {
    if (s.gap) rows.push({ sep: true });
    rows.push({ sep: false, text: s.e, match: s.match });
  }
  return rows;
}

const entries = Array.from({ length: 20 }, (_, i) => `line ${i}`);

{
  // matches at 2 and 10, no context: one separator between them
  const rows = buildRows(entries, { matchIdx: [2, 10], before: 0, after: 0 });
  const seps = rows.filter((r) => r.sep).length;
  check(seps === 1, `two distant matches get exactly one separator (got ${seps})`);
  check(rows[1].sep === true, "the separator sits between the two matches");
}
{
  // adjacent matches: no separator
  const rows = buildRows(entries, { matchIdx: [4, 5], before: 0, after: 0 });
  check(rows.filter((r) => r.sep).length === 0, "adjacent matches get no separator");
}
{
  // -A 1 makes 2 and 4 contiguous (2,3,4): no separator
  const rows = buildRows(entries, { matchIdx: [2, 4], before: 0, after: 1 });
  check(rows.filter((r) => r.sep).length === 0,
    "context that bridges two matches suppresses the separator");
}
{
  // context that does not bridge: separator survives
  const rows = buildRows(entries, { matchIdx: [2, 8], before: 0, after: 1 });
  check(rows.filter((r) => r.sep).length === 1,
    "context that does not bridge keeps the separator");
}
{
  // the field filter removing a bridging line must reintroduce the break
  const rows = buildRows(entries, {
    matchIdx: [2, 4], before: 0, after: 1,
    keep: (t) => t !== "line 3",
  });
  check(rows.filter((r) => r.sep).length === 1,
    "a filtered-out bridging line reintroduces the separator");
}
{
  const rows = buildRows(entries, { matchIdx: [0], before: 0, after: 0 });
  check(rows.filter((r) => r.sep).length === 0, "a single block never leads with a separator");
}
{
  // match rows and context rows must be distinguishable
  const rows = buildRows(entries, { matchIdx: [5], before: 1, after: 1 });
  const flags = rows.filter((r) => !r.sep).map((r) => r.match);
  check(JSON.stringify(flags) === JSON.stringify([false, true, false]),
    "context rows are marked apart from the matched row");
}

console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
