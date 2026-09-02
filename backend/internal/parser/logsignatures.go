// Package parser: logsignatures.go scans named log files for patterns that
// indicate a fault, so the Anomalies tab can lead with them.
//
// These are file-scoped rather than archive-wide on purpose. "SYSTEM REBOOT"
// means something specific in reboot.log and nothing in a config dump, and
// scanning every file for every pattern would be both slow and noisy. Each
// signature therefore names the files it applies to.
package parser

import (
	"archive/tar"
	"bufio"
	"io"
	"regexp"
	"sort"
	"strings"
)

// LogSignature is one pattern, the files it applies to, and what a match means.
type LogSignature struct {
	ID       string
	Title    string
	Severity string // critical | warning | info
	// Why explains what the match tells the reader, which is the part that
	// makes a hit actionable rather than just highlighted.
	Why string
	// PathRe selects the files this signature reads.
	PathRe *regexp.Regexp
	// Re is the pattern itself.
	Re *regexp.Regexp
	// Exclude drops a line that Re matched.
	//
	// Go's regexp is RE2, which has no lookahead, so a pattern written as
	// "^(?!.*(quota|is star|...)).*(info +hw).*$" cannot be compiled as one
	// expression. It becomes a positive match plus this negative list, which
	// is the same thing and rather easier to read.
	Exclude *regexp.Regexp
}

// LogFinding is one matched line.
type LogFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Why      string `json:"why,omitempty"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Ts       string `json:"ts,omitempty"`
	Text     string `json:"text"`
}

// LogFindingGroup collapses events that are the same kind of thing.
//
// A signature on its own is too coarse a grouping: reboot.log holds 29
// reboots, but "UI Initiated", "CLI Initiated" and "md initiated configd
// restarts exhausted" are three different stories, and the last one is a fault
// while the first is somebody pressing a button. Grouping by the shape of the
// matched line separates them — 29 events become 5 groups — without burying
// the distinction the way a single "System reboot ×29" row would.
type LogFindingGroup struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Why      string `json:"why,omitempty"`
	// Pattern is the normalised shape shared by every event in the group;
	// Sample is the first real line, which is what the reader should see.
	Pattern string `json:"pattern"`
	Sample  string `json:"sample"`
	Count   int    `json:"count"`
	First   string `json:"first,omitempty"`
	Last    string `json:"last,omitempty"`
	Files   []string `json:"files,omitempty"`
	// Events are the retained lines, for the detail view. Count is exact even
	// when this is capped.
	Events    []LogFinding `json:"events"`
	Truncated bool         `json:"truncated,omitempty"`
}

// LogSignatureReport is the whole scan.
type LogSignatureReport struct {
	Groups []LogFindingGroup `json:"groups"`
	// Counts per signature id, including the ones that matched nothing, so the
	// view can say "checked, clean" rather than staying silent. A signature
	// that is silent because it was never run is a different thing from one
	// that ran and found nothing, and only the second is reassuring.
	Checked map[string]int `json:"checked"`
	// Truncated marks a signature that hit the per-signature cap.
	Truncated map[string]bool `json:"truncated,omitempty"`
}

// maxPerSignature bounds how many lines one signature retains. reboot.log
// alone carries 29 reboots and md_apps.log over a thousand process exits, so
// an uncapped list would bury the single line that matters. Counts stay exact
// past the cap; only the retained examples stop growing.
const maxPerSignature = 500

// maxEventsPerGroup bounds one group's detail list.
const maxEventsPerGroup = 200

// logSignatures is the catalogue.
//
// Several of these patterns were corrected against a real PA-5250 archive
// rather than taken as written; where that happened the reason is recorded on
// the signature, because the original spelling looked plausible and silently
// matched nothing.
var logSignatures = []LogSignature{
	{
		ID: "reboot", Title: "System reboot", Severity: "info",
		Why:     "Each line is a restart, with the reason the system recorded for it.",
		PathRe:  regexp.MustCompile(`(?:^|/)reboot\.log(?:\.\d+)?$`),
		Re:      regexp.MustCompile(`SYSTEM REBOOT`),
	},
	{
		ID: "sensor_alarm", Title: "Hardware sensor alarm", Severity: "critical",
		Why: "The environmental monitor raised an alarm: a fan, power supply, " +
			"temperature sensor or drive array is outside its expected state.",
		PathRe: regexp.MustCompile(`(?:^|/)ehmon\.log(?:\.\d+|\.old)?$`),
		// The written pattern was "Sensor Alarm . True.*", which does not match
		// the real line — there is no space between the bracket and "True":
		//
		//	Sensor Alarm [True ]: System Drives Raid Array status = False
		//
		// so it found nothing on an archive that had a degraded RAID array.
		Re: regexp.MustCompile(`Sensor Alarm\s*\[\s*True\s*\]`),
	},
	{
		ID: "panos_install", Title: "PAN-OS install", Severity: "info",
		Why:    "Software installs on this device, newest last. Useful for placing a fault either side of an upgrade.",
		PathRe: regexp.MustCompile(`(?:^|/)panrepo/logs/history\.log(?:\.\d+)?$`),
		Re:     regexp.MustCompile(`install panos.*Success`),
	},
	{
		ID: "segfault", Title: "Process segfault", Severity: "critical",
		Why:    "A process crashed on an invalid memory access. The kernel names the process and the faulting address.",
		PathRe: regexp.MustCompile(`(?:^|/)(?:var/)?log/messages(?:\.\d+)?$`),
		Re:     regexp.MustCompile(`segfault`),
	},
	{
		ID: "console", Title: "Dataplane console output", Severity: "warning",
		Why: "Bootloader banners, kernel faults and hardware self-test failures on the " +
			"dataplane console. A boot banner mid-log means that dataplane restarted.",
		PathRe: regexp.MustCompile(`(?:^|/)(?:dataplane\d*|controlplane)-console-output\.log(?:\.\d+)?$`),
		Re: regexp.MustCompile(`CacheErr|U-Boot |DFM.*re|invoked oom-killer|NMI Watchdog|Oops|` +
			`Welcome|he er|Unhandled kernel unaligned access|mcheck|bus error|init inc|BIST FA|` +
			`: cause: |kernel paging request|nfs.*resp.*try|BUG:|TLB.*rror|blocked for`),
	},
	{
		ID: "device_cert", Title: "Device certificate not valid", Severity: "critical",
		Why: "The device certificate is anything other than Valid. Without it the firewall " +
			"cannot authenticate to Palo Alto cloud services, so content updates, WildFire " +
			"and telemetry stop working.",
		PathRe: regexp.MustCompile(`(?:^|/)tmp/cli/.*\.txt$`),
		// Go's RE2 has no lookahead, so the negative lookahead in the original
		// is expressed by matching the status line and testing the value.
		Re: regexp.MustCompile(`device-certificate-status:\s*(\S.*)$`),
	},
	{
		ID: "ha_down", Title: "HA connection down", Severity: "critical",
		Why:    "The high-availability link to the peer dropped. Sustained loss risks a split brain or an unprotected failover.",
		PathRe: regexp.MustCompile(`(?:^|/)ha_agent\.log(?:\.\d+)?$`),
		Re:     regexp.MustCompile(`ha_event.+HA.+connection down`),
	},
	{
		ID: "ha_transition", Title: "HA state transition", Severity: "warning",
		Why:    "The device changed HA state. A cluster that flaps between states is failing over repeatedly.",
		PathRe: regexp.MustCompile(`(?:^|/)ha_agent\.log(?:\.\d+)?$`),
		Re:     regexp.MustCompile(`transition to state `),
	},
	{
		ID: "process_signal", Title: "Process killed by signal", Severity: "low",
		Why: "A managed process died on a signal rather than exiting cleanly — a crash or " +
			"an out-of-memory kill, not a normal restart.",
		PathRe: regexp.MustCompile(`(?:^|/)md_apps\.log(?:\.\d+|\.old)?$`),
		Re:     regexp.MustCompile(`Process .* exited with signal`),
	},
	{
		ID: "orphan_partition", Title: "Orphaned log partition", Severity: "low",
		Why: "A log partition was left behind without an owner, usually after a failed " +
			"resize or an interrupted upgrade. It consumes disk without being written to.",
		PathRe: regexp.MustCompile(`(?:^|/)pan-logs-partition\.log(?:\.\d+)?$`),
		Re:     regexp.MustCompile(`(?i)orphan`),
	},
	{
		ID: "dp_exit", Title: "Dataplane exit", Severity: "low",
		Why: "The dataplane process exited. A restart interrupts forwarding, so a " +
			"cluster of these around one time is worth lining up against traffic loss.",
		PathRe: regexp.MustCompile(`(?:^|/)md_info\.log(?:\.\d+|\.old)?$`),
		// "exit" rather than "exited" on purpose: it is a prefix of the real
		// line ("INFO: <proc>: exited, Core: False, Exit code: 0") so both
		// spellings are covered.
		Re: regexp.MustCompile(`INFO: data_plane: exit`),
	},
	{
		ID: "masterd_manual", Title: "Process needs manual restart", Severity: "low",
		Why: "masterd gave up restarting a process after too many failures, so it stays " +
			"down until somebody intervenes. Whatever that process did is not happening.",
		// The request named md_info.log twice; md_apps.log is the other masterd
		// log and carries the same message, so both are read.
		PathRe: regexp.MustCompile(`(?:^|/)md_(?:info|apps)\.log(?:\.\d+|\.old)?$`),
		Re:     regexp.MustCompile(`Exited \d+ times, must be manually`),
	},
	{
		ID: "mp_uptime", Title: "Management plane uptime", Severity: "low",
		Why: "The uptime line sampled by top. One row here means the management plane ran " +
			"continuously across these logs; a second row is a different uptime shape, " +
			"which is what a restart looks like.",
		PathRe: regexp.MustCompile(`(?:^|/)mp-monitor\.log(?:\.\d+)?$`),
		// Anchored on "top - ... up" rather than a bare "up": the loose form
		// matched 12,457 lines in the sample archive — "/cgroup", "LOWER_UP",
		// every interface flag — which is noise, not an event.
		Re: regexp.MustCompile(`top - .* up `),
	},
	{
		ID: "hw_info", Title: "Hardware event", Severity: "low",
		Why: "A hardware-subtype system event, with routine licensing, quota and " +
			"link-state chatter filtered out.",
		PathRe: regexp.MustCompile(`(?:^|/)(?:mp-monitor\.log(?:\.\d+)?|show_log_system\.txt)$`),
		Re:     regexp.MustCompile(`info +hw`),
		// The written form used a negative lookahead, which RE2 cannot compile.
		Exclude: regexp.MustCompile(`quota|is star|is up|inserted|License|LDAP`),
	},

	// ---- GlobalProtect agent ------------------------------------------
	//
	// Path-scoped like everything else, so these are inert on a firewall
	// tech-support file and the firewall signatures are inert on an agent
	// collection. One catalogue, separated by the files each entry names.
	{
		ID: "gpa_gps_ipc", Title: "GlobalProtect app cannot reach its service", Severity: "warning",
		Why: "PanGPA (the app the user sees) talks to PanGPS (the service that does the " +
			"work) over a local socket, app as client and service as server. While this " +
			"fails the UI has no service to query, so GlobalProtect appears dead to the " +
			"user even when a tunnel is up. The app retries and the socket monitor " +
			"restarts the connection, so a burst of these is a stall rather than a " +
			"permanent break — but it is what the user was looking at.",
		PathRe: regexp.MustCompile(`(?:^|/)PanGPA(?:\.\d+)?\.log$`),
		// Keyed on the connect failure alone. The companion "Cannot connect to
		// service, error: N" line reports the same event, so matching both
		// would double every count. The recovery wording varies between
		// versions — "keep monitoring the socket" in one, "socket monitoring
		// found connection failed. restart init connection" in the macOS
		// bundle — so it is deliberately not part of the pattern.
		Re: regexp.MustCompile(`CPanSocket::Connect - Failed to connect to server at port:\d+`),
	},
}

// deviceCertOKRe recognises the one value that is not a finding.
var deviceCertOKRe = regexp.MustCompile(`^Valid\s*$`)

// leadingTsRe pulls the timestamp off the front of a log line when there is
// one, so a finding can be placed in time.
var leadingTsRe = regexp.MustCompile(
	`^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|` + // 2026-07-14 01:26:50
		`[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}|` + // Jul 14 01:26:50
		`[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4})`) // Tue Jul 14 08:27:58 2026

// ScanLogSignatures reads the archive once and applies every signature to the
// files it names.
func ScanLogSignatures(r io.ReadSeeker) (*LogSignatureReport, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	rep := &LogSignatureReport{
		Checked:   map[string]int{},
		Truncated: map[string]bool{},
	}
	var flat []LogFinding
	for _, s := range logSignatures {
		rep.Checked[s.ID] = 0
	}

	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		path := normalizePath(hdr.Name)

		var active []LogSignature
		for _, s := range logSignatures {
			if s.PathRe.MatchString(path) {
				active = append(active, s)
			}
		}
		if len(active) == 0 {
			continue
		}

		sc := bufio.NewScanner(tr)
		sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
		for n := 1; sc.Scan(); n++ {
			line := strings.TrimRight(sc.Text(), "\r")
			if line == "" {
				continue
			}
			for _, s := range active {
				m := s.Re.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				if s.Exclude != nil && s.Exclude.MatchString(line) {
					continue
				}
				// The device certificate line matches whatever its value is;
				// only a value other than "Valid" is a finding.
				if s.ID == "device_cert" {
					if len(m) < 2 || deviceCertOKRe.MatchString(strings.TrimSpace(m[1])) {
						continue
					}
				}
				rep.Checked[s.ID]++
				if rep.Checked[s.ID] > maxPerSignature {
					rep.Truncated[s.ID] = true
					continue
				}
				flat = append(flat, LogFinding{
					ID: s.ID, Title: s.Title, Severity: s.Severity, Why: s.Why,
					Path: path, Line: n,
					Ts:   leadingTsRe.FindString(line),
					Text: trimLong(line, 400),
				})
			}
		}
	}
	rep.Groups = groupFindings(flat)
	return rep, nil
}

// trimLong keeps a finding readable when the line is a wall of text.
func trimLong(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + " …"
}

// SeverityRank orders findings worst-first. "low" sits below "info": these are
// events worth having on the page but not worth drawing the eye to.
func SeverityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "warning":
		return 1
	case "info":
		return 2
	case "low":
		return 3
	}
	return 4
}

/* ---------- grouping ---------- */

var (
	monRe = `(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)`
	dowRe = `(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)`

	// The leading timestamp of the log line itself, in any of the forms the
	// PAN-OS logs use.
	normLeadRe = regexp.MustCompile(`^\s*(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\S*(?:\s*[-+]\d{4})?|` +
		dowRe + ` ` + monRe + ` +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}|` +
		monRe + ` +\d{1,2} \d{2}:\d{2}:\d{2})\s*:?\s*`)

	// Dates and times embedded in the message. Collapsing these is what makes
	// thirteen "UI Initiated at <month>" groups become one.
	normDateRes = []*regexp.Regexp{
		regexp.MustCompile(dowRe + ` ` + monRe + ` +\d{1,2} \d{2}:\d{2}:\d{2}(?: [A-Z]{2,4})?(?: \d{4})?`),
		regexp.MustCompile(monRe + ` +\d{1,2},? \d{2}:\d{2}:\d{2}`),
		regexp.MustCompile(monRe + ` +\d{1,2}`),
		regexp.MustCompile(`\d{1,2}/\d{1,2}/\d{2,4}`),
	}
	normTimeRe = regexp.MustCompile(`\d{2}:\d{2}:\d{2}`)
	normHexRe  = regexp.MustCompile(`\b(?:0x)?[0-9a-fA-F]{6,}\b`)
	normNumRe  = regexp.MustCompile(`\d+`)
	normWsRe   = regexp.MustCompile(`\s+`)
)

// normalizeFinding reduces a matched line to the shape it shares with others
// of its kind: the timestamp, dates, addresses and counts come out, the words
// stay. Two lines with the same shape are the same kind of event.
func normalizeFinding(line string) string {
	s := normLeadRe.ReplaceAllString(strings.TrimRight(line, " \t\r"), "")
	for _, re := range normDateRes {
		s = re.ReplaceAllString(s, "<date>")
	}
	s = normTimeRe.ReplaceAllString(s, "<time>")
	s = normHexRe.ReplaceAllString(s, "<hex>")
	s = normNumRe.ReplaceAllString(s, "<n>")
	s = strings.TrimSpace(normWsRe.ReplaceAllString(s, " "))
	return trimLong(s, 160)
}

// groupFindings collapses findings into one row per kind of event, worst
// severity first and then by how often it happened.
func groupFindings(fs []LogFinding) []LogFindingGroup {
	type acc struct {
		g     *LogFindingGroup
		files map[string]bool
	}
	byKey := map[string]*acc{}
	var order []string

	for _, f := range fs {
		pattern := normalizeFinding(f.Text)
		key := f.ID + "\x00" + pattern
		a, ok := byKey[key]
		if !ok {
			a = &acc{
				g: &LogFindingGroup{
					ID: f.ID, Title: f.Title, Severity: f.Severity, Why: f.Why,
					Pattern: pattern, Sample: f.Text, First: f.Ts, Last: f.Ts,
				},
				files: map[string]bool{},
			}
			byKey[key] = a
			order = append(order, key)
		}
		a.g.Count++
		if f.Ts != "" {
			if a.g.First == "" || f.Ts < a.g.First {
				a.g.First = f.Ts
			}
			if f.Ts > a.g.Last {
				a.g.Last = f.Ts
			}
		}
		if !a.files[f.Path] {
			a.files[f.Path] = true
			a.g.Files = append(a.g.Files, f.Path)
		}
		if len(a.g.Events) < maxEventsPerGroup {
			a.g.Events = append(a.g.Events, f)
		} else {
			a.g.Truncated = true
		}
	}

	out := make([]LogFindingGroup, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k].g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := SeverityRank(out[i].Severity), SeverityRank(out[j].Severity); a != b {
			return a < b
		}
		return out[i].Count > out[j].Count
	})
	return out
}
