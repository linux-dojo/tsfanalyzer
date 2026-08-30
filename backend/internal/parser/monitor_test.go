package parser

import (
	"strings"
	"testing"
	"time"
)

const sampleMonitor = `2026-06-04 00:19:34.524 -0700  --- panio
pan_comm message statistics
:Resource monitoring sampling data (per second):
:CPU load sampling by group:
:flow_lookup                    :     0%
:CPU load (%) during last 15 seconds:
:core   0   1   2   3
:       0   0   0   0
:Resource utilization (%) during last 15 seconds:
:session:
:  0   0   0
:packet buffer:
:  3   3   3
2026-06-04 00:20:34.524 -0700  --- panio
next block line
`

func find(t *testing.T, entries []LogEntry, msgPart string) LogEntry {
	t.Helper()
	for _, e := range entries {
		if strings.Contains(e.Msg, msgPart) {
			return e
		}
	}
	t.Fatalf("no entry containing %q", msgPart)
	return LogEntry{}
}

func TestStructureLogLabels(t *testing.T) {
	entries := StructureLog(strings.NewReader(sampleMonitor), time.Time{}, time.Time{})
	if len(entries) == 0 {
		t.Fatal("no entries")
	}
	if e := find(t, entries, "pan_comm message"); e.Label != "panio" || e.Ts != "2026/06/04 00:19:34" {
		t.Fatalf("panio line: %+v", e)
	}
	if e := find(t, entries, ":flow_lookup"); e.Label != "cpu_by_group" {
		t.Fatalf("cpu group line: %+v", e)
	}
	if e := find(t, entries, ":core"); e.Label != "CPU 15s" {
		t.Fatalf("cpu load line: %+v", e)
	}
	if e := find(t, entries, ":  3   3   3"); e.Label != "resource 15s :packet buffer" {
		t.Fatalf("resource sub line: %+v", e)
	}
}

func TestStructureLogTimeFilter(t *testing.T) {
	from, _ := time.Parse("2006-01-02 15:04:05", "2026-06-04 00:20:00")
	entries := StructureLog(strings.NewReader(sampleMonitor), from, time.Time{})
	for _, e := range entries {
		if e.Ts != "2026/06/04 00:20:34" {
			t.Fatalf("entry outside range kept: %+v", e)
		}
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
}

// The two parsers format their display timestamp differently — the monitor
// parser with slashes, the GlobalProtect parser with dashes — and the time
// filter compares those strings. Comparing them unnormalised drops every
// monitor entry, because '/' sorts above '-': a silent, total failure of the
// firewall time filter.
func TestNormalizeLogTs(t *testing.T) {
	if got := normalizeLogTs("2026/08/24 15:12:04"); got != "2026-08-24 15:12:04" {
		t.Errorf("monitor timestamp = %q, want dashes", got)
	}
	if got := normalizeLogTs("2026-08-24 15:12:04.876"); got != "2026-08-24 15:12:04.876" {
		t.Errorf("a GP timestamp must pass through unchanged, got %q", got)
	}
	if got := normalizeLogTs(""); got != "" {
		t.Errorf("empty must stay empty, got %q", got)
	}
	// and the normalised forms must order the same way
	if !(normalizeLogTs("2026/08/24 14:00:00") < normalizeLogTs("2026-08-24 15:00:00")) {
		t.Error("normalised timestamps must compare chronologically across both formats")
	}
}

// A macOS GlobalProtect log filtered to a window inside its span must return
// the entries in that window, and report the file's real span either way.
func TestStructureLogPageStatsFiltersMacFormat(t *testing.T) {
	const log = `P3094-T64395 08/24/2026 14:59:55:832 Debug(4036): before the window
P3094-T16899 08/24/2026 15:12:04:876 Info (2710): inside the window
P3094-T259   08/24/2026 15:20:23:216 Debug(6398): after the window`

	from, _ := time.Parse("2006-01-02 15:04:05", "2026-08-24 15:00:00")
	to, _ := time.Parse("2006-01-02 15:04:05", "2026-08-24 15:15:00")

	page, st := StructureLogPageStats(strings.NewReader(log), from, to, 0, 100)
	if st.Total != 1 || len(page) != 1 {
		t.Fatalf("got %d of %d in range, want 1 of 1", len(page), st.Total)
	}
	if !strings.Contains(page[0].Msg, "inside the window") {
		t.Errorf("wrong entry survived: %q", page[0].Msg)
	}
	// the span is reported regardless of the filter, so an empty page can
	// explain itself
	if st.FileTotal != 3 || st.Timestamped != 3 {
		t.Errorf("file_total=%d timestamped=%d, want 3/3", st.FileTotal, st.Timestamped)
	}
	if st.First != "2026-08-24 14:59:55.832" || st.Last != "2026-08-24 15:20:23.216" {
		t.Errorf("span = %q .. %q", st.First, st.Last)
	}

	// a window outside the file yields nothing, but still reports the span
	early, _ := time.Parse("2006-01-02 15:04:05", "2026-08-24 09:00:00")
	late, _ := time.Parse("2006-01-02 15:04:05", "2026-08-24 09:30:00")
	page, st = StructureLogPageStats(strings.NewReader(log), early, late, 0, 100)
	if len(page) != 0 || st.Total != 0 {
		t.Errorf("expected an empty page, got %d", len(page))
	}
	if st.First == "" || st.FileTotal != 3 {
		t.Errorf("the span must still be reported on an empty page: %+v", st)
	}
}
