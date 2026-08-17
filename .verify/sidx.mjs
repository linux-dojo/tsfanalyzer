// Node port of the Go search index, used to actually execute logic that has
// no Go compiler available in this environment. Mirrors searchindex.go
// structure-for-structure.
//
// The thresholds are deliberately tiny so the cap and budget branches — where
// a false negative would hide — are exercised, which the Go tests cannot
// reach with production constants.

// Set per configuration below. No single setting exercises everything: a
// generous budget is needed to see the filter narrow anything, and a starved
// one to see the fallback that keeps it correct when it cannot.
let MAX_POSTINGS_PER_TRIGRAM = 2048;
let MAX_TOTAL_POSTINGS = 24 << 20;
const MAX_TRI_GROUPS = 32;

/* ---------- folding ---------- */

// Mirrors foldRune: lower-case, then the smallest member of the fold orbit.
// For ASCII that is upper-casing. JS has no SimpleFold, so the two non-ASCII
// cases that matter are spelled out.
const SPECIAL_FOLD = new Map([
  ["K", "K"], // KELVIN SIGN
  ["ſ", "S"], // LATIN SMALL LETTER LONG S
]);

function foldString(s) {
  let out = "";
  for (const ch of s) {
    if (SPECIAL_FOLD.has(ch)) { out += SPECIAL_FOLD.get(ch); continue; }
    const c = ch.codePointAt(0);
    if (c < 128) {
      out += c >= 97 && c <= 122 ? String.fromCharCode(c - 32) : ch;
    } else {
      const up = ch.toLowerCase().toUpperCase();
      out += up.length === 1 ? up : ch.toLowerCase();
    }
  }
  return out;
}

const enc = new TextEncoder();
function trigramsOf(s) {
  const b = enc.encode(foldString(s)); // trigrams over folded bytes, as in Go
  const out = new Set();
  for (let i = 0; i + 3 <= b.length; i++) {
    out.add((b[i] << 16) | (b[i + 1] << 8) | b[i + 2]);
  }
  return out;
}

/* ---------- the index ---------- */

const TRI_COMMON = -1;

class SearchIndex {
  constructor() {
    this.files = [];      // {path, text}
    this.tri = new Map(); // trigram -> slot | TRI_COMMON
    this.post = [];       // slot -> sorted file indices
    this.alwaysScan = [];
    this.postings = 0;
  }

  build(corpus) {
    let budget = MAX_TOTAL_POSTINGS;
    for (const [path, text] of corpus) {
      const fi = this.files.length;
      this.files.push({ path, text });
      if (budget <= 0) { this.alwaysScan.push(fi); continue; }
      budget -= this.addPostings(fi, trigramsOf(text));
    }
    return this;
  }

  addPostings(fi, tris) {
    let used = 0;
    for (const t of tris) {
      let slot = this.tri.get(t);
      if (slot === TRI_COMMON) continue;
      if (slot === undefined) {
        slot = this.post.length;
        this.post.push([]);
        this.tri.set(t, slot);
      }
      const lst = this.post[slot];
      if (lst.length >= MAX_POSTINGS_PER_TRIGRAM) {
        this.tri.set(t, TRI_COMMON);
        this.post[slot] = null;
        this.postings -= lst.length;
        used -= lst.length;
        continue;
      }
      lst.push(fi);
      this.postings++;
      used++;
    }
    return used;
  }

  // null means "no constraint"; otherwise a per-file mask
  candidates(tq) {
    if (tq.any || tq.ors.length === 0) return null;
    const out = new Array(this.files.length).fill(false);
    for (const g of tq.ors) {
      const lists = [];
      let absent = false;
      for (const t of g.tris) {
        const slot = this.tri.get(t);
        if (slot === undefined) { absent = true; break; }
        if (slot === TRI_COMMON) continue;
        lists.push(this.post[slot]);
      }
      if (absent) continue;
      if (lists.length === 0) return null;
      lists.sort((a, b) => a.length - b.length);
      let acc = lists[0];
      for (const l of lists.slice(1)) {
        acc = intersectSorted(acc, l);
        if (acc.length === 0) break;
      }
      for (const fi of acc) out[fi] = true;
    }
    for (const fi of this.alwaysScan) out[fi] = true;
    return out;
  }
}

function intersectSorted(a, b) {
  const out = [];
  let i = 0, j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) { out.push(a[i]); i++; j++; }
    else if (a[i] < b[j]) i++;
    else j++;
  }
  return out;
}

/* ---------- query plans ---------- */

const triAny = () => ({ any: true, ors: [] });

function triFromLiteral(s) {
  const f = foldString(s);
  if (f.length < 3) return triAny();
  return { any: false, ors: [{ tris: [...trigramsOf(s)], lit: f }] };
}

function triAnd(a, b) {
  if (a.any) return b;
  if (b.any) return a;
  if (a.ors.length * b.ors.length > MAX_TRI_GROUPS) {
    return a.ors.length <= b.ors.length ? a : b;
  }
  const ors = [];
  for (const g1 of a.ors) {
    for (const g2 of b.ors) {
      ors.push({
        tris: [...g1.tris, ...g2.tris],
        lit: g2.lit.length > g1.lit.length ? g2.lit : g1.lit,
      });
    }
  }
  return { any: false, ors };
}

function triOr(a, b) {
  if (a.any || b.any) return triAny();
  if (a.ors.length + b.ors.length > MAX_TRI_GROUPS) return triAny();
  return { any: false, ors: [...a.ors, ...b.ors] };
}

function gateOf(tq) {
  if (tq.any || tq.ors.length !== 1) return "";
  return tq.ors[0].lit.length < 3 ? "" : tq.ors[0].lit;
}

/* ---------- a small query tree, mirroring the Go one ---------- */

const lit = (v) => ({ kind: "lit", value: v });
const rx = (src, plan) => ({ kind: "re", value: src, plan });
const and = (a, b) => ({ op: "and", a, b });
const or = (a, b) => ({ op: "or", a, b });
const not = (a) => ({ op: "not", a });

function planOf(n) {
  if (n.kind === "lit") return triFromLiteral(n.value);
  if (n.kind === "re") return n.plan ?? triAny();
  if (n.op === "not") return triAny();
  if (n.op === "and") return triAnd(planOf(n.a), planOf(n.b));
  return triOr(planOf(n.a), planOf(n.b));
}

function matchNode(n, line) {
  const lower = line.toLowerCase();
  if (n.kind === "lit") return lower.includes(n.value.toLowerCase());
  if (n.kind === "re") return new RegExp(n.value, "i").test(lower);
  if (n.op === "not") return !matchNode(n.a, line);
  if (n.op === "and") return matchNode(n.a, line) && matchNode(n.b, line);
  return matchNode(n.a, line) || matchNode(n.b, line);
}

/* ---------- the two search paths ---------- */

function bruteForce(corpus, node) {
  const out = [];
  for (const [path, text] of corpus) {
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (lines[i] !== "" && matchNode(node, lines[i])) {
        out.push(`${path}:${i + 1}:${lines[i]}`);
      }
    }
  }
  return out;
}

function indexed(idx, node) {
  const tq = planOf(node);
  const cand = idx.candidates(tq);
  const gate = gateOf(tq);
  const out = [];
  let scanned = 0;
  for (let fi = 0; fi < idx.files.length; fi++) {
    if (cand !== null && !cand[fi]) continue;
    scanned++;
    const { path, text } = idx.files[fi];
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (lines[i] === "") continue;
      if (gate && !foldString(lines[i]).includes(gate)) continue;
      if (matchNode(node, lines[i])) out.push(`${path}:${i + 1}:${lines[i]}`);
    }
  }
  return { out, scanned };
}

/* ---------- corpus ---------- */

const corpus = [
  ["var/log/pan/mp-monitor.log",
    Array.from({ length: 40 }, (_, i) =>
      `2026/08/04 21:${String(i % 60).padStart(2, "0")}:00 mp pkt_recv ${i} useridd res_swap ${700000 + i}`).join("\n")],
  ["var/log/pan/dp-monitor.log",
    Array.from({ length: 40 }, (_, i) => `dp PKT_RECV upper ${i} session entries ${i * 3}`).join("\n")],
  ["tmp/cli/logs/show_log_system.txt",
    "2026/08/04 21:00:20 medium general OSPF neighbor 10.1.1.2 went down\n" +
    "2026/08/04 21:10:00 high routing BGP peer 10.9.9.9 reset\n" +
    "kernel: Out of memory: Killed process 1234 (reportd)\n" +
    "K vs k vs K kelvin sign\n" +
    "long ſ vs s comparison"],
  ["var/log/pan/uniq-alpha.log", "alpha zzqqxx-alpha-needle here"],
  ["var/log/pan/uniq-beta.log", "beta zzqqxx-beta-needle here"],
  ...Array.from({ length: 10 }, (_, i) =>
    [`var/log/pan/bulk-${String(i).padStart(2, "0")}.log`,
      Array.from({ length: 5 }, () => "routine housekeeping line with common words").join("\n")]),
];

/* ---------- checks ---------- */

const queries = [
  ["plain literal", lit("pkt_recv")],
  ["literal, other case", lit("PKT_RECV")],
  ["unique needle", lit("zzqqxx-alpha-needle")],
  ["shared prefix", lit("zzqqxx")],
  ["absent term", lit("no-such-string-anywhere")],
  ["AND across files", and(lit("ospf"), lit("pkt_recv"))],
  ["AND same line", and(lit("ospf"), lit("down"))],
  ["OR", or(lit("ospf"), lit("pkt_recv"))],
  ["NOT alone", not(lit("ospf"))],
  ["AND NOT", and(lit("general"), not(lit("ospf")))],
  ["nested group", and(or(lit("ospf"), lit("bgp")), lit("general"))],
  ["kelvin sign", lit("kelvin")],
  ["long s", lit("comparison")],
  ["common word", lit("line")],
  ["housekeeping", lit("routine")],
  ["regex literal+wildcard", rx("res_swap.*000", triAnd(triFromLiteral("res_swap"), triFromLiteral("000")))],
  ["regex alternation", rx("ospf|bgp", triOr(triFromLiteral("ospf"), triFromLiteral("bgp")))],
  ["regex class only", rx("[0-9]+", triAny())],
  ["regex optional char", rx("neighbou?r", triFromLiteral("neighbo"))],
];

let failures = 0;
const say = (ok, msg) => { console.log(`  ${ok ? "PASS" : "FAIL"}  ${msg}`); if (!ok) failures++; };

// Every configuration must return identical results; only the amount read may
// differ. That is the entire contract of the index. No single setting
// exercises everything: a generous budget is needed to see the filter narrow
// anything, a starved one to see the fallback that keeps it correct when it
// cannot.
const configs = [
  { name: "production thresholds", perTrigram: 2048, total: 24 << 20, expect: { narrows: true } },
  { name: "per-trigram cap reached (trigrams demoted to common)", perTrigram: 3, total: 24 << 20, expect: { common: true } },
  { name: "postings budget exhausted (files fall back to always-scan)", perTrigram: 2048, total: 40, expect: { alwaysScan: true } },
];

for (const cfg of configs) {
  MAX_POSTINGS_PER_TRIGRAM = cfg.perTrigram;
  MAX_TOTAL_POSTINGS = cfg.total;
  const idx = new SearchIndex().build(corpus);

  console.log(`\n=== ${cfg.name} ===`);
  console.log(`  index: ${idx.files.length} files, ${idx.post.filter(Boolean).length} live posting lists, ` +
    `${idx.postings} postings, ${idx.alwaysScan.length} always-scan files`);

  let mismatches = 0, totalRead = 0;
  for (const [name, node] of queries) {
    const want = bruteForce(corpus, node);
    const { out: got, scanned } = indexed(idx, node);
    totalRead += scanned;
    const same = want.length === got.length && want.every((v, i) => v === got[i]);
    if (!same) {
      mismatches++;
      console.log(`  FAIL  ${name}: indexed ${got.length} vs full scan ${want.length}`);
      want.filter((v) => !got.includes(v)).slice(0, 3).forEach((m) => console.log(`        MISSED: ${m}`));
      got.filter((v) => !want.includes(v)).slice(0, 3).forEach((m) => console.log(`        EXTRA:  ${m}`));
    }
  }
  say(mismatches === 0,
    `all ${queries.length} queries identical to a full scan ` +
    `(${totalRead}/${queries.length * idx.files.length} file-reads)`);

  if (cfg.expect.narrows) {
    const { scanned } = indexed(idx, lit("zzqqxx-alpha-needle"));
    say(scanned === 1, `a needle unique to one file reads exactly 1 file (read ${scanned})`);
    const broad = indexed(idx, lit("routine"));
    say(broad.scanned >= 10, `a term present in every bulk file reads them all (read ${broad.scanned})`);
  }
  if (cfg.expect.common) {
    const t = [...trigramsOf("routine")][0];
    say(idx.tri.get(t) === TRI_COMMON,
      `an over-common trigram is demoted to "no constraint", not dropped (slot=${idx.tri.get(t)})`);
    const want = bruteForce(corpus, lit("routine"));
    const { out } = indexed(idx, lit("routine"));
    say(want.length === out.length && want.length > 0,
      `a query of only common trigrams still finds all ${want.length} results`);
  }
  if (cfg.expect.alwaysScan) {
    say(idx.alwaysScan.length > 0, `${idx.alwaysScan.length} files ended up with no trigram data`);
    const beyond = idx.files[idx.alwaysScan[0]];
    const word = beyond.text.split(/\s+/).find((w) => w.length > 4) ?? "line";
    const want = bruteForce(corpus, lit(word));
    const { out } = indexed(idx, lit(word));
    say(want.length === out.length && want.length > 0,
      `a file with no trigram data is still searched (${word}: ${out.length}/${want.length})`);
  }
}

console.log("\n=== folding and gating (threshold-independent) ===");
say(foldString("pkt_recv") === foldString("PKT_RECV"), "fold: case-insensitive agreement");
say(foldString("K") === foldString("K"), "fold: KELVIN SIGN folds onto K");
say(foldString("s") === foldString("ſ"), "fold: LONG S folds onto S");
say(foldString(foldString("Mixed Case")) === foldString("Mixed Case"), "fold: idempotent");

{
  let bad = 0, gated = 0;
  for (const [, node] of queries) {
    const g = gateOf(planOf(node));
    if (!g) continue;
    gated++;
    for (const [, text] of corpus) {
      for (const line of text.split("\n")) {
        if (line && matchNode(node, line) && !foldString(line).includes(g)) bad++;
      }
    }
  }
  say(bad === 0, `the line gate (active on ${gated} queries) never rejects a matching line`);
}

console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
