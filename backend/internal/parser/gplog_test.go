package parser

import (
	"strings"
	"testing"
	"time"
)

// Every line below is copied verbatim from a real GlobalProtect 6.3.3
// collection. The three formats were found by measuring coverage against that
// bundle rather than by assuming, and two of them only came to light that way:
// PanGPA.log indents its lines by one space, and pan_cp_events.log orders the
// fields differently and runs a long severity straight into the date.
const (
	gpEventSample = `08/18/2026 09:39:11:548 [Info ]: GlobalProtect service started (client version: 6.3.3-1121, OS version: Microsoft Windows 10 Pro , 64-bit).
08/18/2026 13:31:17:897 [Info ]: Auth failed for portal
08/18/2026 13:55:40:423 [Info ]: portal status is Connected.
08/18/2026 13:55:41:076 [Error]: The network connection is unreachable or the gateway is unresponsive. Check the network connection and reconnect.`

	gpTraceSample = `(P3024-T9396)Info ( 132): 06/15/26 23:57:29:747 ####################### Start PanGPS service (ver: 6.3.3-828) #######################
(P11496-T6520)Info (11298): 08/18/26 13:55:40:474 Connect method is user-logon
 (P12048-T11416)Debug( 646): 06/15/26 23:57:32:273 translate-enter-key = yes`

	gpCpSample = `(P11496-T14080)info 08/18/26 09:41:41:742 (152): [CP_DETECT] CPExceptionTime = 0 s
(P11496-T14080)debug08/18/26 09:41:41:742 (152): [CP_DETECT] CaptivePortalDetectionThread: wait`
)

func TestGPLineFormatsRecognised(t *testing.T) {
	for _, block := range []string{gpEventSample, gpTraceSample, gpCpSample} {
		for _, line := range strings.Split(block, "\n") {
			if !IsGPLogLine(line) {
				t.Errorf("not recognised as a GlobalProtect line:\n  %s", line)
			}
		}
	}
	for _, line := range []string{
		"2026-06-09 11:27:40.087 -0700  --- panio",       // a firewall monitor log
		`   "result" : {`,                                 // a JSON continuation
		", Upgradetype=Manual Upgrade",                    // an event continuation
		"Host Name:                 DESKTOP-1DSRGV8",      // systeminfo output
	} {
		if IsGPLogLine(line) {
			t.Errorf("wrongly recognised as a GlobalProtect line: %q", line)
		}
	}
}

// PanGPA.log indents most of its lines by a single space. Missing that cost
// well over half the file when measured against the real bundle.
func TestGPTraceToleratesLeadingSpace(t *testing.T) {
	indented := ` (P12048-T11416)Debug( 646): 06/15/26 23:57:32:273 translate-enter-key = yes`
	if !IsGPLogLine(indented) {
		t.Fatal("an indented component-log line must still parse")
	}
	got := StructureGPLog(strings.NewReader(indented), time.Time{}, time.Time{})
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Label != "Debug" {
		t.Errorf("label = %q, want Debug", got[0].Label)
	}
	if !strings.HasPrefix(got[0].Msg, "P12048-T11416 ") {
		t.Errorf("the process/thread should lead the message: %q", got[0].Msg)
	}
}

// "debug08/18/26" has no space between the severity and the date, so the
// severity has to be matched as letters only.
func TestGPCaptivePortalFormat(t *testing.T) {
	got := StructureGPLog(strings.NewReader(gpCpSample), time.Time{}, time.Time{})
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].Label != "info" || got[1].Label != "debug" {
		t.Errorf("labels = %q/%q, want info/debug", got[0].Label, got[1].Label)
	}
	for _, e := range got {
		if !strings.HasPrefix(e.Ts, "2026-08-18 09:41:41") {
			t.Errorf("timestamp = %q, want 2026-08-18 09:41:41…", e.Ts)
		}
	}
}

func TestStructureGPLogEventFormat(t *testing.T) {
	got := StructureGPLog(strings.NewReader(gpEventSample), time.Time{}, time.Time{})
	if len(got) != 4 {
		t.Fatalf("got %d entries, want 4", len(got))
	}
	if got[0].Ts != "2026-08-18 09:39:11.548" {
		t.Errorf("ts = %q", got[0].Ts)
	}
	if got[0].Label != "Info" || got[3].Label != "Error" {
		t.Errorf("labels = %q … %q, want Info … Error", got[0].Label, got[3].Label)
	}
	if !strings.Contains(got[2].Msg, "portal status is Connected") {
		t.Errorf("message not preserved: %q", got[2].Msg)
	}
}

// A line that parses no format is a continuation: it belongs to the entry
// above it and keeps that timestamp, rather than being dropped. In the real
// bundle 24,000 of PanGPA.log's lines are exactly this.
func TestStructureGPLogKeepsContinuations(t *testing.T) {
	in := "(P11496-T6520)Info (11298): 08/18/26 13:55:40:474 HIP report follows\n" +
		"    \"result\" : {\n" +
		"        \"detected_products\" : [\n"
	got := StructureGPLog(strings.NewReader(in), time.Time{}, time.Time{})
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3 (one entry plus two continuations)", len(got))
	}
	for i, e := range got {
		if e.Ts != got[0].Ts {
			t.Errorf("entry %d has ts %q, want the parent's %q", i, e.Ts, got[0].Ts)
		}
	}
}

func TestStructureGPLogTimeFilter(t *testing.T) {
	from, _ := time.Parse("2006-01-02 15:04:05", "2026-08-18 13:00:00")
	got := StructureGPLog(strings.NewReader(gpEventSample), from, time.Time{})
	if len(got) != 3 {
		t.Fatalf("got %d entries, want the 3 after 13:00", len(got))
	}
	if strings.Contains(got[0].Msg, "service started") {
		t.Error("the 09:39 line should have been filtered out")
	}
}

// The paged entry point must route to the GP parser on its own: nothing tells
// it which kind of archive the file came from.
func TestStructureLogPageDetectsGPFormat(t *testing.T) {
	got, total := StructureLogPage(strings.NewReader(gpEventSample), time.Time{}, time.Time{}, 0, 100)
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
	if got[0].Label != "Info" {
		t.Errorf("the GP parser was not selected: label = %q", got[0].Label)
	}
	// and a firewall monitor log must still go to the monitor parser
	fw := "2026-06-09 11:27:40.087 -0700  --- panio\n:CPU load (%) during last 60 seconds:\n: 1 2 3\n"
	got2, _ := StructureLogPage(strings.NewReader(fw), time.Time{}, time.Time{}, 0, 100)
	if len(got2) == 0 || strings.HasPrefix(got2[0].Msg, "P") {
		t.Errorf("a monitor log was routed to the GP parser: %+v", got2)
	}
}

// The agent sometimes writes two entries onto one physical line with no
// separator, which would bury the second inside the first one's message. This
// line is verbatim from a SAML/Okta collection, where it happens around the
// embedded browser — exactly the part you are reading the log to understand.
func TestSplitEmbeddedEntries(t *testing.T) {
	real := "08/19/2026 05:30:46:180 [Info ]: Load the SAML Browser" +
		"08/19/2026 05:30:46:180 [Info ]: ShowPage - using embedded browser."
	parts := splitGPEmbedded(real)
	if len(parts) != 2 {
		t.Fatalf("got %d parts, want 2: %q", len(parts), parts)
	}
	for _, p := range parts {
		if !gpEventLineRe.MatchString(p) {
			t.Errorf("part does not parse as an event: %q", p)
		}
	}
	if !strings.HasSuffix(parts[0], "Load the SAML Browser") {
		t.Errorf("first part = %q", parts[0])
	}
	if !strings.Contains(parts[1], "ShowPage") {
		t.Errorf("second part = %q", parts[1])
	}

	// an ordinary line must be left alone, including one that merely starts
	// with a timestamp, and so must a continuation
	for _, line := range []string{
		"08/18/2026 09:39:11:548 [Info ]: GlobalProtect service started.",
		`    "result" : {`,
		"",
	} {
		if got := splitGPEmbedded(line); len(got) != 1 || got[0] != line {
			t.Errorf("splitGPEmbedded(%q) = %q, want it unchanged", line, got)
		}
	}

	// and end to end: both entries reach the structured output
	got := StructureGPLog(strings.NewReader(real), time.Time{}, time.Time{})
	if len(got) != 2 {
		t.Fatalf("got %d entries from the concatenated line, want 2", len(got))
	}
	if !strings.Contains(got[1].Msg, "ShowPage") {
		t.Errorf("the second entry was lost: %+v", got)
	}
}

func TestParseGPTimeBothWidths(t *testing.T) {
	four, ok := parseGPTime("08/18/2026", "13:55:40")
	if !ok || four.Year() != 2026 || four.Month() != 8 || four.Day() != 18 {
		t.Errorf("four-digit year: %v ok=%v", four, ok)
	}
	two, ok := parseGPTime("08/18/26", "13:55:40")
	if !ok || two.Year() != 2026 {
		t.Errorf("two-digit year should resolve to 2026: %v ok=%v", two, ok)
	}
	if !four.Equal(two) {
		t.Errorf("the two forms should agree: %v vs %v", four, two)
	}
	if _, ok := parseGPTime("not a date", "13:55:40"); ok {
		t.Error("a bad date should not parse")
	}
}
