// Package parser: kind.go works out what kind of archive was uploaded.
//
// The tool takes two quite different bundles:
//
//   - a firewall tech-support file: hundreds of megabytes, PAN-OS config,
//     monitor logs, counters, CLI dumps;
//   - a GlobalProtect agent log collection, produced on the endpoint by the
//     GP app's "Collect Logs" (or `globalprotect collect-log`), which is far
//     smaller and holds the client-side service and UI logs.
//
// They share almost nothing, so the tabs, the parsers and the analysis all
// differ. Classification happens from the archive index that is built anyway,
// so it costs no extra read of the archive.
//
// # Why firewall markers win
//
// A firewall tech-support file *also* contains GlobalProtect material — the
// gateway and portal write their own logs, and file names there can look very
// like the agent's. The reverse is never true: an endpoint collection has no
// /opt/pancfg, no CLI dump and no dataplane monitor logs. So a single firewall
// marker outweighs any number of GP-looking names, and only an archive with no
// firewall evidence at all is considered for the GP classification.
package parser

import (
	"path"
	"regexp"
	"strings"
)

// ArchiveKind is what an uploaded file turned out to be.
type ArchiveKind string

const (
	KindFirewall ArchiveKind = "firewall"
	KindGPAgent  ArchiveKind = "gp-agent"
	KindUnknown  ArchiveKind = "unknown"
)

// Label is the human name for a kind, for the file list.
func (k ArchiveKind) Label() string {
	switch k {
	case KindFirewall:
		return "Firewall tech-support"
	case KindGPAgent:
		return "GlobalProtect agent"
	default:
		return "Unrecognised archive"
	}
}

// KindResult is the verdict plus the evidence behind it, so a wrong call can
// be understood rather than just disbelieved.
type KindResult struct {
	Kind ArchiveKind `json:"kind"`
	// Markers are the paths that decided it, at most a handful.
	Markers []string `json:"markers,omitempty"`
	// Firewall/GP are how many distinct marker patterns each side matched.
	FirewallHits int `json:"firewall_hits"`
	GPHits       int `json:"gp_hits"`
}

// firewallMarkers are paths only a PAN-OS tech-support file has.
var firewallMarkers = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(^|/)opt/pancfg/`),
	regexp.MustCompile(`(?i)(^|/)tmp/cli/`),
	regexp.MustCompile(`(?i)(^|/)(dp\d*-monitor|mp-monitor)\.log`),
	regexp.MustCompile(`(?i)(^|/)var/log/pan/`),
	regexp.MustCompile(`(?i)(^|/)opt/panlogs/`),
	regexp.MustCompile(`(?i)(^|/)mergesp\.xml$`),
	regexp.MustCompile(`(?i)(^|/)running-config\.xml$`),
}

// gpMarkers are the files a GlobalProtect endpoint collection carries. The
// service and UI logs are the reliable ones; the rest corroborate.
var gpMarkers = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(^|/)PanGPS\.log`),
	regexp.MustCompile(`(?i)(^|/)PanGPA\.log`),
	regexp.MustCompile(`(?i)(^|/)pan_gp_event\.log`),
	regexp.MustCompile(`(?i)(^|/)PanGpHip(Mp)?\.log`),
	regexp.MustCompile(`(?i)(^|/)PanNExt\.log`),
	regexp.MustCompile(`(?i)(^|/)PanGPUI\.log`),
	regexp.MustCompile(`(?i)(^|/)HipReport(Success)?\.xml$`),
	regexp.MustCompile(`(?i)(^|/)\.GlobalProtect/`),
	regexp.MustCompile(`(?i)(^|/)GlobalProtect/.*\.log`),
}

// DetectKind classifies an archive from its file list. The index is built in
// the first parse pass regardless, so this adds no I/O.
func DetectKind(entries []ArchiveEntry) KindResult {
	res := KindResult{Kind: KindUnknown}
	seenFW := make(map[int]bool)
	seenGP := make(map[int]bool)
	var fwPaths, gpPaths []string
	// one path can satisfy several patterns, so the evidence is de-duplicated
	notedFW := make(map[string]bool)
	notedGP := make(map[string]bool)

	for _, e := range entries {
		p := normalizePath(e.Path)
		if p == "" {
			continue
		}
		for i, re := range firewallMarkers {
			if !seenFW[i] && re.MatchString(p) {
				seenFW[i] = true
				if !notedFW[p] {
					notedFW[p] = true
					fwPaths = append(fwPaths, p)
				}
			}
		}
		// Only bother looking for GP markers while the firewall case is still
		// open; on a real tech-support file this loop would match constantly.
		if len(seenFW) == 0 {
			for i, re := range gpMarkers {
				if !seenGP[i] && re.MatchString(p) {
					seenGP[i] = true
					if !notedGP[p] {
						notedGP[p] = true
						gpPaths = append(gpPaths, p)
					}
				}
			}
		}
	}

	res.FirewallHits, res.GPHits = len(seenFW), len(seenGP)
	switch {
	case res.FirewallHits > 0:
		res.Kind, res.Markers = KindFirewall, trimMarkers(fwPaths)
	case res.GPHits > 0:
		res.Kind, res.Markers = KindGPAgent, trimMarkers(gpPaths)
	default:
		// Nothing recognisable. A last look at the shape of the thing: a
		// handful of .log files and nothing else is far more likely to be an
		// endpoint collection than a firewall dump.
		if looksLikeLogBundle(entries) {
			res.Kind = KindGPAgent
			res.Markers = trimMarkers(logNames(entries))
		}
	}
	return res
}

// looksLikeLogBundle is the fallback for a GP collection whose file names we
// do not recognise: small, flat, and mostly logs.
func looksLikeLogBundle(entries []ArchiveEntry) bool {
	if len(entries) == 0 || len(entries) > 200 {
		return false
	}
	logs := 0
	for _, e := range entries {
		base := strings.ToLower(path.Base(e.Path))
		if strings.HasSuffix(base, ".log") || strings.Contains(base, ".log.") {
			logs++
		}
	}
	return logs >= 2 && logs*2 >= len(entries)
}

func logNames(entries []ArchiveEntry) []string {
	var out []string
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.Path), ".log") {
			out = append(out, e.Path)
		}
	}
	return out
}

func trimMarkers(paths []string) []string {
	if len(paths) > 6 {
		return paths[:6]
	}
	return paths
}
