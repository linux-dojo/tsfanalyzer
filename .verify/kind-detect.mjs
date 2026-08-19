// Runs the archive-kind classifier (parser/kind.go) against the same cases as
// kind_test.go, since there is no Go compiler in this environment. The rule
// that matters is that firewall evidence outweighs GlobalProtect file names:
// a tech-support file from a firewall with GlobalProtect configured contains
// PanGPS-like logs of its own, and must not be filed as an endpoint bundle.

const FIREWALL = [
  /(^|\/)opt\/pancfg\//i,
  /(^|\/)tmp\/cli\//i,
  /(^|\/)(dp\d*-monitor|mp-monitor)\.log/i,
  /(^|\/)var\/log\/pan\//i,
  /(^|\/)opt\/panlogs\//i,
  /(^|\/)mergesp\.xml$/i,
  /(^|\/)running-config\.xml$/i,
];

const GP = [
  /(^|\/)PanGPS\.log/i,
  /(^|\/)PanGPA\.log/i,
  /(^|\/)pan_gp_event\.log/i,
  /(^|\/)PanGpHip(Mp)?\.log/i,
  /(^|\/)PanNExt\.log/i,
  /(^|\/)PanGPUI\.log/i,
  /(^|\/)HipReport(Success)?\.xml$/i,
  /(^|\/)\.GlobalProtect\//i,
  /(^|\/)GlobalProtect\/.*\.log/i,
];

const normalize = (p) => p.replace(/^\.\//, "").replace(/^\//, "");
const base = (p) => p.split("/").pop();

function looksLikeLogBundle(paths) {
  if (paths.length === 0 || paths.length > 200) return false;
  const logs = paths.filter((p) => {
    const b = base(p).toLowerCase();
    return b.endsWith(".log") || b.includes(".log.");
  }).length;
  return logs >= 2 && logs * 2 >= paths.length;
}

function detectKind(paths) {
  const seenFW = new Set();
  const seenGP = new Set();
  const fwPaths = [];
  const gpPaths = [];
  const notedFW = new Set();
  const notedGP = new Set();

  for (const raw of paths) {
    const p = normalize(raw);
    if (!p) continue;
    FIREWALL.forEach((re, i) => {
      if (!seenFW.has(i) && re.test(p)) {
        seenFW.add(i);
        if (!notedFW.has(p)) { notedFW.add(p); fwPaths.push(p); }
      }
    });
    if (seenFW.size === 0) {
      GP.forEach((re, i) => {
        if (!seenGP.has(i) && re.test(p)) {
          seenGP.add(i);
          if (!notedGP.has(p)) { notedGP.add(p); gpPaths.push(p); }
        }
      });
    }
  }

  if (seenFW.size > 0) {
    return { kind: "firewall", markers: fwPaths.slice(0, 6), fw: seenFW.size, gp: seenGP.size };
  }
  if (seenGP.size > 0) {
    return { kind: "gp-agent", markers: gpPaths.slice(0, 6), fw: 0, gp: seenGP.size };
  }
  if (looksLikeLogBundle(paths.map(normalize))) {
    return { kind: "gp-agent", markers: [], fw: 0, gp: 0 };
  }
  return { kind: "unknown", markers: [], fw: 0, gp: 0 };
}

let failures = 0;
const check = (ok, msg) => { console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`); if (!ok) failures++; };

{
  const r = detectKind([
    "opt/pancfg/mgmt/mergesp.xml", "tmp/cli/techsupport.txt",
    "var/log/pan/dp-monitor.log", "var/log/pan/ms.log",
  ]);
  check(r.kind === "firewall", `a tech-support file is firewall (got ${r.kind})`);
  check(r.markers.length > 0, "the deciding paths are reported");
  check(new Set(r.markers).size === r.markers.length,
    `evidence is de-duplicated (${JSON.stringify(r.markers)})`);
}
{
  const r = detectKind(["PanGPS.log", "PanGPA.log", "pan_gp_event.log", "PanGpHip.log", "HipReport.xml"]);
  check(r.kind === "gp-agent", `an agent collection is gp-agent (got ${r.kind})`);
  check(r.gp >= 4, `several GP markers matched (${r.gp})`);
}
{
  // the important one
  const r = detectKind([
    "opt/pancfg/mgmt/mergesp.xml", "var/log/pan/gpsvc.log", "var/log/pan/PanGPS.log",
    "tmp/cli/logs/PanGPA.log", "opt/pancfg/globalprotect/HipReport.xml",
  ]);
  check(r.kind === "firewall",
    `a firewall running GlobalProtect stays firewall (got ${r.kind})`);
}
{
  const gpOnly = ["PanGPS.log", "PanGPA.log", "pan_gp_event.log", "PanNExt.log"];
  check(detectKind(gpOnly).kind === "gp-agent", "baseline: GP-only bundle is gp-agent");
  check(detectKind([...gpOnly, "opt/pancfg/mgmt/running-config.xml"]).kind === "firewall",
    "a single firewall marker among GP names decides it");
  // and the order of the archive must not matter
  check(detectKind(["opt/pancfg/mgmt/running-config.xml", ...gpOnly]).kind === "firewall",
    "the firewall marker decides regardless of where it appears in the archive");
}
{
  const r = detectKind(["logs/client-service.log", "logs/client-ui.log", "logs/events.log", "version.txt"]);
  check(r.kind === "gp-agent", `an unfamiliar small log bundle falls back to gp-agent (got ${r.kind})`);
}
{
  const many = Array.from({ length: 400 }, (_, i) => `logs/file${i}.log`);
  check(detectKind(many).kind !== "gp-agent", "a large log archive is not assumed to be an agent bundle");
}
{
  check(detectKind([]).kind === "unknown", "an empty archive is unknown");
  check(detectKind(["readme.txt", "data.bin", "notes.md"]).kind === "unknown",
    "an unrecognised archive is unknown");
}
{
  check(detectKind(["./opt/pancfg/mgmt/mergesp.xml"]).kind === "firewall",
    'a "./" prefix does not hide a marker');
  check(detectKind(["/PanGPS.log", "/PanGPA.log"]).kind === "gp-agent",
    'a leading "/" does not hide a marker');
}
{
  // rotations and platform variations seen in real collections
  check(detectKind(["PanGPS.log.old", "PanGPA.log.old"]).kind === "gp-agent",
    "rotated logs still identify an agent bundle");
  check(detectKind(["Library/Logs/PaloAltoNetworks/GlobalProtect/PanGPS.log"]).kind === "gp-agent",
    "a macOS path layout still identifies an agent bundle");
  check(detectKind([".GlobalProtect/Collect.tgz", ".GlobalProtect/PanGPS.log"]).kind === "gp-agent",
    "the .GlobalProtect directory identifies an agent bundle");
}

console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
