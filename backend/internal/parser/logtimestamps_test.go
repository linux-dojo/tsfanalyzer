package parser

import (
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// reboot.log, audit.log, wildfire-monitor.log
//
// These three keep their timestamp somewhere no anchored pattern can reach:
// inside the message, inside a record id, or on a banner line that the rows
// beneath it inherit. Every line below is copied from the PA-5250 archive.
// ---------------------------------------------------------------------------

// reboot.log writes the date inside the reason, in two spellings — one with a
// year and one without.
func TestRebootLogTimestamps(t *testing.T) {
	withYear := "SYSTEM REBOOT [Unkown reboot at Wed Mar 12 08:20:21 PDT 2025]"
	got, ok := parseLooseTs(withYear, 0)
	if !ok {
		t.Fatalf("no timestamp found in %q", withYear)
	}
	if s := got.Format("2006-01-02 15:04:05"); s != "2025-03-12 08:20:21" {
		t.Errorf("got %s, want 2025-03-12 08:20:21", s)
	}

	// The year-less spelling depends on the running hint.
	noYear := "SYSTEM REBOOT [UI Initiated at Mar 13 10:59:48]"
	if _, ok := parseLooseTs(noYear, 0); ok {
		t.Error("with no year available this must stay unstamped rather than guess")
	}
	got, ok = parseLooseTs(noYear, 2026)
	if !ok {
		t.Fatalf("no timestamp found in %q with a hint", noYear)
	}
	if s := got.Format("2006-01-02 15:04:05"); s != "2026-03-13 10:59:48" {
		t.Errorf("got %s, want 2026-03-13 10:59:48", s)
	}
}

// The file spans March 2025 to August 2026, so the hint has to follow the log
// rather than pin every line to the first year seen.
func TestRebootLogYearFollowsTheLog(t *testing.T) {
	if y := explicitYear("SYSTEM REBOOT [Unkown reboot at Wed Mar 12 08:20:21 PDT 2025]"); y != 2025 {
		t.Errorf("explicit year = %d, want 2025", y)
	}
	if y := explicitYear("SYSTEM REBOOT [UI Initiated at Mar 13 10:59:48]"); y != 0 {
		t.Errorf("explicit year = %d, want 0 — this line names no year", y)
	}

	body := strings.Join([]string{
		"SYSTEM REBOOT [Unkown reboot at Wed Mar 12 08:20:21 PDT 2025]",
		"SYSTEM REBOOT [UI Initiated at Apr 2 08:11:02]",
		"SYSTEM REBOOT [Unkown reboot at Fri Apr 10 11:00:00 PDT 2026]",
		"SYSTEM REBOOT [CLI Initiated at Aug 1 09:00:00]",
	}, "\n")
	got := StructureLogYear(strings.NewReader(body), time.Time{}, time.Time{}, 0)
	if len(got) != 4 {
		t.Fatalf("got %d entries, want 4", len(got))
	}
	want := []string{"2025/03/12", "2025/04/02", "2026/04/10", "2026/08/01"}
	for i, w := range want {
		if !strings.HasPrefix(got[i].Ts, w) {
			t.Errorf("entry %d = %q, want it to start %q", i, got[i].Ts, w)
		}
	}
}

// audit.log carries epoch seconds inside its record id.
func TestAuditLogEpochTimestamp(t *testing.T) {
	line := "type=DAEMON_START msg=audit(1784017521.553:6107): op=start ver=3.0 format=enriched"
	got, ok := parseLooseTs(line, 0)
	if !ok {
		t.Fatal("the epoch inside audit(...) should be read")
	}
	if got.Unix() != 1784017521 {
		t.Errorf("got %d, want 1784017521", got.Unix())
	}
	// A number that is not a plausible epoch must not become a date.
	if _, ok := parseLooseTs("msg=audit(12:34): nonsense", 0); ok {
		t.Error("an implausible epoch should be rejected")
	}
}

// wildfire-monitor.log stamps a banner and lets the rows beneath inherit it,
// which is the same model the monitor logs use.
func TestWildfireMonitorBannerAndInheritance(t *testing.T) {
	body := strings.Join([]string{
		"============================== 2026-07-14 01:47:26 -0700 ==============================",
		"some detail line with no time of its own",
		"another detail line",
		"============================== 2026-07-14 02:17:26 -0700 ==============================",
		"a later detail line",
	}, "\n")
	got := StructureLogYear(strings.NewReader(body), time.Time{}, time.Time{}, 0)
	if len(got) != 5 {
		t.Fatalf("got %d entries, want 5", len(got))
	}
	for i, want := range []string{
		"2026/07/14 01:47:26", "2026/07/14 01:47:26", "2026/07/14 01:47:26",
		"2026/07/14 02:17:26", "2026/07/14 02:17:26",
	} {
		if got[i].Ts != want {
			t.Errorf("entry %d = %q, want %q", i, got[i].Ts, want)
		}
	}
}

// The unanchored patterns are the risky ones: they will find a date anywhere
// in a line. They run only after every anchored pattern has declined, so a
// normal log line is still read by its own leading timestamp.
func TestAnchoredPatternsWinOverUnanchored(t *testing.T) {
	// A syslog line quoting a different date in its message must be stamped
	// from its own prefix, not from the quoted one.
	got, ok := parseLooseTs("Jul 14 01:26:26 INFO: restored backup from Mar 12 08:20:21 2019", 2026)
	if !ok {
		t.Fatal("should parse")
	}
	if s := got.Format("2006-01-02 15:04:05"); s != "2026-07-14 01:26:26" {
		t.Errorf("got %s, want the line's own timestamp 2026-07-14 01:26:26", s)
	}
}

// One case per family found in the PA-5250 survey. 68 of its 327 log files had
// no recognised timestamp at all, which left them invisible to the time filter
// and blank in the Timestamp column.
func TestLooseTimestampFamilies(t *testing.T) {
	cases := []struct {
		name, line, want string
		hint             int
	}{
		{"rfc3339", `2026-07-14T01:26:40.961-07:00 something`, "2026-07-14 01:26:40", 0},
		{"json", `{"level":"info","time":"2026-07-14T01:26:40.96101438-07:00","message":"start"}`,
			"2026-07-14 01:26:40", 0},
		{"ctime", `Tue Jul 14 01:26:27 PDT 2026 Copying certificates...`, "2026-07-14 01:26:27", 0},
		{"redis", `7400:C 14 Jul 2026 01:26:28.215 # Redis is starting`, "2026-07-14 01:26:28", 0},
		{"us-date", `07/14/26 01:25:25 fips     INFO: FIPS-CC Self-Tests begin`, "2026-07-14 01:25:25", 0},
		{"bracket-iso", `[2026/07/14 02:02:39]`, "2026-07-14 02:02:39", 0},
		{"bracket-iso-mid", `00106647 [2026-08-04 15:07:36.0305] [ifmon] Interface:69`, "2026-08-04 15:07:36", 0},
		{"clf", `::ffff:10.47.135.171 - - [14/Jul/2026:01:30:33 -0700] "GET /" 302`, "2026-07-14 01:30:33", 0},
		{"php", `[14-Jul-2026 08:26:59 UTC] PHP Warning: Module 'curl' already loaded`, "2026-07-14 08:26:59", 0},
		{"colon-iso", `2026:07:14T01:26:41.077-07:00 [9684-9684] main ikemgr started`, "2026-07-14 01:26:41", 0},
		{"syslog+hint", `Jul 14 01:26:26 INFO: ZRAM mem_limit not supported`, "2026-07-14 01:26:26", 2026},
		// history.log puts its timestamp at the end of a fixed-width row, so
		// nothing anchored at the start of the line can find it.
		{"trailing", `bootstrap panlogs logs panos-11.1.6-h17     Success  12/11/25 18:58:42`,
			"2025-12-11 18:58:42", 0},
	}
	for _, c := range cases {
		got, ok := parseLooseTs(c.line, c.hint)
		if !ok {
			t.Errorf("%s: no timestamp found in %q", c.name, c.line)
			continue
		}
		if s := got.Format("2006-01-02 15:04:05"); s != c.want {
			t.Errorf("%s: got %s, want %s", c.name, s, c.want)
		}
	}
}

// A year-less line with no year available anywhere stays unstamped. Guessing
// the current year would silently move a whole file in and out of a time
// filter, which is worse than an empty column.
func TestSyslogWithoutAYearIsLeftUnstamped(t *testing.T) {
	if _, ok := parseLooseTs("Aug 11 04:02:01 host run-parts[6640]: finished", 0); ok {
		t.Error("no year is available, so no timestamp should be invented")
	}
	if _, ok := parseLooseTs("Aug 11 04:02:01 host run-parts[6640]: finished", 2026); !ok {
		t.Error("with a hint it should parse")
	}
}

// Several files open with a year-less line whose *banner* carries the year.
func TestYearHintReadsAYearFromMidLine(t *testing.T) {
	head := []string{"Jul 14 01:26:23 DEBUG: +++++++ Tue Jul 14 01:26:23 2026 +++++++"}
	if y := looseYearHint(head); y != 2026 {
		t.Errorf("year hint = %d, want 2026", y)
	}
	if y := looseYearHint([]string{"nothing dated here"}); y != 0 {
		t.Errorf("year hint = %d, want 0 when there is no year", y)
	}
}

// Nonsense must be rejected rather than normalised: time.Date turns month 0
// into the previous December without complaining.
func TestImpossibleDatesRejected(t *testing.T) {
	if _, ok := mk(2026, 0, 14, 1, 2, 3); ok {
		t.Error("month 0 should be rejected")
	}
	if _, ok := mk(2026, 13, 1, 1, 2, 3); ok {
		t.Error("month 13 should be rejected")
	}
	if _, ok := mk(2026, 7, 32, 1, 2, 3); ok {
		t.Error("day 32 should be rejected")
	}
}

// The banding only applies to one-record-per-line structured logs.
func TestJSONLinesDetection(t *testing.T) {
	jsonHead := []string{
		`{"level":"info","time":"2026-07-14T01:26:40Z","message":"a"}`,
		`{"level":"warn","time":"2026-07-14T01:26:41Z","message":"b"}`,
	}
	if !jsonLinesLog(jsonHead) {
		t.Error("a stream of JSON records should be detected")
	}
	if jsonLinesLog([]string{"Jul 14 01:26:26 INFO: plain text", "more text"}) {
		t.Error("a plain log is not a structured one")
	}
	if jsonLinesLog(nil) {
		t.Error("nothing to judge from")
	}
}

// The whole point: a file whose only timestamps are in these formats now
// yields entries that carry them.
func TestStructureLogPicksUpLooseFormats(t *testing.T) {
	body := strings.Join([]string{
		`{"level":"info","time":"2026-07-14T01:26:40.961-07:00","message":"start gpsvc"}`,
		`{"level":"info","time":"2026-07-14T01:26:41.101-07:00","message":"version 8.0.93"}`,
	}, "\n")
	got := StructureLogYear(strings.NewReader(body), time.Time{}, time.Time{}, 0)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	for i, e := range got {
		if e.Ts == "" {
			t.Errorf("entry %d has no timestamp: %q", i, e.Msg)
		}
	}
}
