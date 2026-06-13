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
