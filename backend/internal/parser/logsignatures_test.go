package parser

import (
	"strings"
	"testing"
)

// scanLines applies the catalogue to a handful of lines from one path, the way
// ScanLogSignatures does over an archive, and returns the flat findings plus
// the per-signature tally.
func scanLines(path string, lines ...string) ([]LogFinding, map[string]int) {
	checked := map[string]int{}
	var found []LogFinding
	for _, s := range logSignatures {
		checked[s.ID] = 0
		if !s.PathRe.MatchString(path) {
			continue
		}
		for n, line := range lines {
			m := s.Re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if s.ID == "device_cert" {
				if len(m) < 2 || deviceCertOKRe.MatchString(strings.TrimSpace(m[1])) {
					continue
				}
			}
			checked[s.ID]++
			found = append(found, LogFinding{
				ID: s.ID, Title: s.Title, Severity: s.Severity, Why: s.Why,
				Path: path, Line: n + 1,
				Ts:   leadingTsRe.FindString(line), Text: line,
			})
		}
	}
	return found, checked
}

func ids(fs []LogFinding, _ map[string]int) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.ID]++
	}
	return out
}

// The written pattern was "Sensor Alarm . True.*", which assumes a space
// between the bracket and the word. The real line has none:
//
//	Sensor Alarm [True ]: System Drives Raid Array status = False
//
// so it matched nothing on an archive whose RAID array was degraded — the
// tool would have called that box clean.
func TestSensorAlarmMatchesTheRealBracketForm(t *testing.T) {
	real := "2026-07-14 01:26:50.245 -0700 Sensor Alarm [True ]: System Drives Raid Array status = False"
	fs, checked := scanLines("var/log/pan/ehmon.log", real)
	if ids(fs, checked)["sensor_alarm"] != 1 {
		t.Fatalf("the real sensor alarm line was not matched: %q", real)
	}
	if got := fs[0].Ts; got != "2026-07-14 01:26:50" {
		t.Errorf("timestamp = %q", got)
	}
	// A cleared alarm is not a finding.
	if n := ids(scanLines("var/log/pan/ehmon.log",
		"2026-07-14 01:26:50.245 -0700 Sensor Alarm [False]: System Drives Raid Array status = True"))["sensor_alarm"]; n != 0 {
		t.Errorf("a False alarm should not be reported, got %d", n)
	}
}

// Go's RE2 has no lookahead, so the negative lookahead in the original pattern
// is expressed by matching the status and testing the value.
func TestDeviceCertificateOnlyFlagsNonValid(t *testing.T) {
	bad := ids(scanLines("tmp/cli/techsupport_Lab340-PA-5250.txt", "device-certificate-status: None"))
	if bad["device_cert"] != 1 {
		t.Error("a device certificate status of None is a finding")
	}
	for _, ok := range []string{"device-certificate-status: Valid", "device-certificate-status: Valid  "} {
		if n := ids(scanLines("tmp/cli/x.txt", ok))["device_cert"]; n != 0 {
			t.Errorf("%q is the healthy value and must not be reported", ok)
		}
	}
}

// Each signature reads only the files it names; scanning everything would be
// slow and would report "SYSTEM REBOOT" out of any file that mentioned it.
func TestSignaturesAreScopedToTheirFiles(t *testing.T) {
	line := "SYSTEM REBOOT [UI Initiated at Mar 13 10:59:48]"
	if ids(scanLines("opt/panrepo/logs/reboot.log", line))["reboot"] != 1 {
		t.Error("reboot.log should match")
	}
	if n := ids(scanLines("var/log/pan/ms.log", line))["reboot"]; n != 0 {
		t.Errorf("the same text elsewhere must not be reported, got %d", n)
	}
}

func TestConsoleAndProcessSignatures(t *testing.T) {
	console := ids(scanLines("opt/var.cp/log/pan/dataplane1-console-output.log",
		"Tue Jul 14 08:27:58 2026:     Welcome to the PanOS Bootloader.",
		"Tue Jul 14 08:27:58 2026: U-Boot 11.0.0.1-72 (Build time: Dec 24 2024)",
		"Tue Jul 14 08:28:10 2026: nothing interesting here"))
	if console["console"] != 2 {
		t.Errorf("console hits = %d, want 2", console["console"])
	}
	// md_apps.log carries over a thousand clean "exited with exit code of"
	// lines; only a signal exit is abnormal.
	got := ids(scanLines("var/log/pan/md_apps.log",
		"2026-08-09 22:45:02.671 -0700 Process log_index exited with exit code of 0; core dumped: no",
		"2026-08-09 22:45:02.671 -0700 Process mgmtsrvr exited with signal 11; core dumped: yes"))
	if got["process_signal"] != 1 {
		t.Errorf("process_signal = %d, want 1 (a clean exit is not a finding)", got["process_signal"])
	}
}

// Every signature has to be listed in Checked whether or not it matched, so
// the view can say "checked, clean" instead of staying silent.
func TestEverySignatureIsAccountedFor(t *testing.T) {
	_, checked := scanLines("var/log/pan/nothing.log", "irrelevant")
	if len(checked) != len(logSignatures) {
		t.Errorf("Checked has %d entries, want %d", len(checked), len(logSignatures))
	}
	seen := map[string]bool{}
	for _, s := range logSignatures {
		if seen[s.ID] {
			t.Errorf("duplicate signature id %q", s.ID)
		}
		seen[s.ID] = true
		if s.Severity != "critical" && s.Severity != "warning" && s.Severity != "info" {
			t.Errorf("%s: unexpected severity %q", s.ID, s.Severity)
		}
		if s.Why == "" {
			t.Errorf("%s: a finding needs to say what it means", s.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// Grouping
// ---------------------------------------------------------------------------

// Grouping by signature alone is too coarse and by raw line too fine. The
// shape of the line is the useful middle: reboot.log's 29 reboots collapse to
// a handful of *reasons*, and "the box rebooted itself six times because
// configd restarts were exhausted" stays visible instead of being averaged
// into one "System reboot ×29" row.
func TestGroupingCollapsesByShapeNotByLine(t *testing.T) {
	var fs []LogFinding
	add := func(ts, text string) {
		fs = append(fs, LogFinding{ID: "reboot", Title: "System reboot", Severity: "info",
			Path: "opt/panrepo/logs/reboot.log", Ts: ts, Text: text})
	}
	add("2025-03-13 10:59:48", "SYSTEM REBOOT [UI Initiated at Mar 13 10:59:48]")
	add("2025-04-02 08:11:02", "SYSTEM REBOOT [UI Initiated at Apr 2 08:11:02]")
	add("2025-11-19 23:04:10", "SYSTEM REBOOT [UI Initiated at Nov 19 23:04:10]")
	add("2025-12-30 04:00:00", "SYSTEM REBOOT [md initiated configd restarts exhausted at Dec 30 04:00:00]")
	add("2025-12-31 05:00:00", "SYSTEM REBOOT [md initiated configd restarts exhausted at Dec 31 05:00:00]")
	add("2026-08-01 09:00:00", "SYSTEM REBOOT [CLI Initiated at Aug 1 09:00:00]")

	gs := groupFindings(fs)
	if len(gs) != 3 {
		t.Fatalf("got %d groups, want 3 (UI, configd, CLI): %+v", len(gs), gs)
	}
	// ordered by count within the same severity
	if gs[0].Count != 3 {
		t.Errorf("largest group has %d events, want 3", gs[0].Count)
	}
	if !strings.Contains(gs[0].Pattern, "UI Initiated") {
		t.Errorf("first group pattern = %q", gs[0].Pattern)
	}
	// the month must not fragment the group
	if strings.Contains(gs[0].Pattern, "Mar") || strings.Contains(gs[0].Pattern, "Nov") {
		t.Errorf("a month name leaked into the group key: %q", gs[0].Pattern)
	}
	// the span comes from the events, and the sample is a real line
	if gs[0].First != "2025-03-13 10:59:48" || gs[0].Last != "2025-11-19 23:04:10" {
		t.Errorf("span = %q .. %q", gs[0].First, gs[0].Last)
	}
	if !strings.Contains(gs[0].Sample, "Mar 13") {
		t.Errorf("sample should be an actual line, got %q", gs[0].Sample)
	}
	if len(gs[0].Events) != 3 {
		t.Errorf("group kept %d events for the detail view, want 3", len(gs[0].Events))
	}
}

// Different signatures never merge, however similar their text.
func TestGroupsNeverSpanSignatures(t *testing.T) {
	fs := []LogFinding{
		{ID: "a", Title: "A", Severity: "warning", Text: "same text", Path: "p"},
		{ID: "b", Title: "B", Severity: "warning", Text: "same text", Path: "p"},
	}
	if got := len(groupFindings(fs)); got != 2 {
		t.Errorf("got %d groups, want 2 — an id must be part of the key", got)
	}
}

// Worst first, then commonest, so the row that matters is at the top.
func TestGroupOrdering(t *testing.T) {
	fs := []LogFinding{
		{ID: "i", Severity: "info", Text: "info thing", Path: "p"},
		{ID: "i", Severity: "info", Text: "info thing", Path: "p"},
		{ID: "w", Severity: "warning", Text: "warn thing", Path: "p"},
		{ID: "c", Severity: "critical", Text: "crit thing", Path: "p"},
	}
	gs := groupFindings(fs)
	want := []string{"critical", "warning", "info"}
	for i, sv := range want {
		if gs[i].Severity != sv {
			t.Errorf("group %d severity = %q, want %q", i, gs[i].Severity, sv)
		}
	}
}

// Numbers and addresses vary between otherwise identical events and must not
// split them, but the words have to survive or unrelated events would merge.
func TestNormalizeKeepsWordsAndDropsValues(t *testing.T) {
	a := normalizeFinding("2026-08-09 22:45:02.671 -0700 Process log_index exited with signal 11")
	b := normalizeFinding("2026-08-10 03:12:44.001 -0700 Process log_index exited with signal 9")
	if a != b {
		t.Errorf("same event with a different signal number split:\n  %q\n  %q", a, b)
	}
	c := normalizeFinding("2026-08-09 22:45:02.671 -0700 Process mgmtsrvr exited with signal 11")
	if a == c {
		t.Error("different processes must not merge — the process name is the distinguishing word")
	}
	if strings.Contains(a, "2026") || strings.Contains(a, "22:45") {
		t.Errorf("the leading timestamp should be stripped, got %q", a)
	}
}

// ---------------------------------------------------------------------------
// The later signatures
// ---------------------------------------------------------------------------

// RE2 has no lookahead, so "^(?!.*(quota|...)).*(info +hw).*$" cannot be one
// expression. It is a positive match plus an exclusion list, and the exclusion
// has to actually run or the filtered noise comes straight back.
func TestHardwareInfoExclusionList(t *testing.T) {
	var sig LogSignature
	for _, s := range logSignatures {
		if s.ID == "hw_info" {
			sig = s
		}
	}
	if sig.Exclude == nil {
		t.Fatal("hw_info needs an exclusion list; RE2 cannot express the lookahead")
	}
	keep := "2026-08-17 10:00:00 info  hw  slot 1 powered on"
	if !sig.Re.MatchString(keep) || sig.Exclude.MatchString(keep) {
		t.Errorf("a real hardware event should survive: %q", keep)
	}
	for _, drop := range []string{
		"info  hw  License quota exceeded",
		"info  hw  port is up",
		"info  hw  module inserted",
		"info  hw  LDAP server reachable",
		"info  hw  daemon is started",
	} {
		if sig.Re.MatchString(drop) && !sig.Exclude.MatchString(drop) {
			t.Errorf("%q should have been excluded", drop)
		}
	}
}

// A bare ".*up" against mp-monitor matched 12,457 lines in the sample archive
// — "/cgroup", every "LOWER_UP" interface flag — which is noise rather than an
// event. Anchoring on the top uptime line is what makes it mean something.
func TestUptimeSignatureIsAnchoredOnTheTopLine(t *testing.T) {
	var sig LogSignature
	for _, s := range logSignatures {
		if s.ID == "mp_uptime" {
			sig = s
		}
	}
	if !sig.Re.MatchString("top - 04:04:50 up 34 days,  2:40,  0 users,  load average: 0.09") {
		t.Error("the top uptime line should match")
	}
	for _, noise := range []string{
		"/cgroup          0          0",
		"11: fvif4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500",
		"  Swap:  0 total, 0 used",
	} {
		if sig.Re.MatchString(noise) {
			t.Errorf("%q is not an uptime event", noise)
		}
	}
}

// "exit" is a prefix of the real "exited" line, so one pattern covers both.
func TestDataplaneExitMatchesTheRealWording(t *testing.T) {
	fs, _ := scanLines("var/log/pan/md_info.log",
		"2026-08-09 22:45:02.671 -0700 INFO: data_plane: exited, Core: False, Exit code: 0",
		"2026-08-09 22:45:02.671 -0700 INFO: l3svc: exited, Core: False, Exit code: 0")
	n := ids(fs, nil)["dp_exit"]
	if n != 1 {
		t.Errorf("dp_exit matched %d lines, want 1 (only the dataplane)", n)
	}
}

// masterd writes this to both of its logs, and the request named one of them
// twice, so both are read.
func TestMasterdManualRestartReadsBothLogs(t *testing.T) {
	line := "2026-08-09 22:45:02.671 -0700 Process foo Exited 5 times, must be manually restarted"
	for _, path := range []string{"var/log/pan/md_info.log", "var/log/pan/md_apps.log"} {
		fs, _ := scanLines(path, line)
		if ids(fs, nil)["masterd_manual"] != 1 {
			t.Errorf("%s: the manual-restart message should be found", path)
		}
	}
}

// These are all reference material rather than alarms.
func TestLowSeveritySignatures(t *testing.T) {
	want := map[string]bool{
		"process_signal": true, "orphan_partition": true, "dp_exit": true,
		"masterd_manual": true, "mp_uptime": true, "hw_info": true,
	}
	for _, s := range logSignatures {
		if want[s.ID] && s.Severity != "low" {
			t.Errorf("%s severity = %q, want low", s.ID, s.Severity)
		}
	}
	if SeverityRank("low") <= SeverityRank("info") {
		t.Error("low must sort below info so it never displaces a real finding")
	}
}

// PanGPA is the app the user sees; PanGPS is the service that does the work.
// The app is the client and the service the server, over a local socket. While
// that connection is down the UI has nothing to query, so GlobalProtect looks
// dead to the user regardless of what the tunnel is doing.
func TestGPAtoGPSSocketFailure(t *testing.T) {
	fs, _ := scanLines("PanGPA.log",
		"P 692-T259   08/10/2026 09:31:44:777 Error(  80): CPanSocket::Connect - Failed to connect to server at port:4767",
		"P 692-T259   08/10/2026 09:31:44:777 Error( 195): Cannot connect to service, error: 61",
		"P 692-T259   08/10/2026 09:31:44:777 Info ( 207): Connecting to Pan MS Service end failed. keep monitoring the socket.",
		"P 692-T259   08/10/2026 09:31:44:777 Info ( 555): StartSocketMonitor - socket monitoring started.",
	)
	// One event, not four. The companion lines describe the same failure, and
	// matching them too would multiply every count by four.
	if n := ids(fs, nil)["gpa_gps_ipc"]; n != 1 {
		t.Errorf("got %d findings for one failure, want 1", n)
	}

	// The macOS agent words the recovery differently, so the pattern must not
	// depend on it.
	fs, _ = scanLines("PanGPA.log",
		"P3101-T35395 08/24/2026 15:20:33:436 Error(  80): CPanSocket::Connect - Failed to connect to server at port:4767",
		"P3101-T35395 08/24/2026 15:20:33:436 Error( 258): Cannot connect to service, error: 61",
		"P3101-T35395 08/24/2026 15:20:33:436 Dump (1732): socket monitoring found connection failed. restart init connection it",
	)
	if n := ids(fs, nil)["gpa_gps_ipc"]; n != 1 {
		t.Errorf("macOS wording: got %d, want 1", n)
	}
}

// A healthy agent log must produce nothing.
func TestGPAtoGPSQuietWhenConnected(t *testing.T) {
	fs, _ := scanLines("PanGPA.log",
		"P 692-T259   08/10/2026 09:31:44:777 Info ( 254): InitConnection ...",
		"P 692-T259   08/10/2026 09:31:45:100 Debug(  57): fd still open before connect",
	)
	if n := ids(fs, nil)["gpa_gps_ipc"]; n != 0 {
		t.Errorf("got %d findings on a clean log, want 0", n)
	}
}

// The catalogue is one list separated by path: agent entries must not fire on
// a firewall file, and PAN-OS entries must not fire on an agent file.
func TestSignatureCataloguesDoNotCrossOver(t *testing.T) {
	gpLine := "P 692-T259 08/10/2026 09:31:44:777 Error( 80): CPanSocket::Connect - Failed to connect to server at port:4767"
	if n := ids(scanLines("var/log/pan/ms.log", gpLine))["gpa_gps_ipc"]; n != 0 {
		t.Error("the agent signature should only read PanGPA logs")
	}
	fwLine := "SYSTEM REBOOT [UI Initiated at Mar 13 10:59:48]"
	if n := ids(scanLines("PanGPA.log", fwLine))["reboot"]; n != 0 {
		t.Error("the reboot signature should only read reboot.log")
	}
	// PanGPS is the server side and has its own formats; the app-side socket
	// signature is scoped to the client log only.
	if n := ids(scanLines("PanGPS.log", gpLine))["gpa_gps_ipc"]; n != 0 {
		t.Error("this is the app's view of the failure, so it reads PanGPA")
	}
}
