package parser

import (
	"bytes"
	"strings"
	"testing"
)

const sampleSystemLog = `2026/08/04 21:00:20 medium   general                          general                   0  Failed to check Content content upgrade info due to Couldn't connect to server
2026/08/04 21:12:11 info     general                          general                   0  Successfully connect to address: 34.90.253.226 port: 3978, conn id: triallr-34.90.253.226-4-def
2026/08/04 21:12:11 info     general                          general                   0  Successfully connect to address: 34.90.253.226 port: 3978, conn id: triallr-34.90.253.226-1-def
2026/08/04 22:00:00 high     routing                          routing                   0  OSPF neighbor 10.10.10.2 on ethernet1/1 went down: dead timer expired
2026/08/04 23:00:00 high     routing                          routing                   0  OSPF neighbor 10.10.10.3 on ethernet1/2 went down: dead timer expired
2026/08/05 01:00:00 medium   general                          general                   0  Failed to check Content content upgrade info due to Couldn't connect to server
2026/08/05 02:00:00 critical ha                               ha                        0  HA state changed from active to suspended
2026/08/05 03:00:00 low      ha                               ha                        0  HA state changed from suspended to active
`

func TestParseSystemLogEvents(t *testing.T) {
	events := parseSystemLogEvents(bytes.NewReader([]byte(sampleSystemLog)))
	if len(events) != 8 {
		t.Fatalf("got %d events, want 8", len(events))
	}
	first := events[0]
	if first.Severity != "medium" || first.Subtype != "general" {
		t.Fatalf("first event = %+v", first)
	}
	if first.Description != "Failed to check Content content upgrade info due to Couldn't connect to server" {
		t.Fatalf("description = %q", first.Description)
	}
	if first.Ts.Format("2006-01-02 15:04:05") != "2026-08-04 21:00:20" {
		t.Fatalf("timestamp = %v", first.Ts)
	}
}

func TestIsNoise(t *testing.T) {
	if !isNoise("Successfully connect to address: 1.2.3.4 port: 443, conn id: abc") {
		t.Error("successful-connect line should be noise")
	}
	if isNoise("Failed to check Content content upgrade info due to Couldn't connect to server") {
		t.Error("content update failure should not be noise")
	}
	if isNoise("OSPF neighbor 10.10.10.2 on ethernet1/1 went down: dead timer expired") {
		t.Error("OSPF down should not be noise")
	}
}

func TestGroupAnomaliesKnownPatterns(t *testing.T) {
	events := parseSystemLogEvents(bytes.NewReader([]byte(sampleSystemLog)))
	groups := GroupAnomalies(events)

	byLabel := map[string]AnomalyGroup{}
	for _, g := range groups {
		byLabel[g.Label] = g
	}

	ospf, ok := byLabel["OSPF Neighbor Down"]
	if !ok {
		t.Fatal("missing OSPF Neighbor Down group")
	}
	if ospf.Count != 2 {
		t.Fatalf("OSPF group count = %d, want 2 (different neighbor IPs/interfaces must still merge)", ospf.Count)
	}
	// each occurrence must keep its own original text so the UI can show
	// which neighbor a specific incident was about
	if len(ospf.Occurrences) != 2 {
		t.Fatalf("OSPF occurrences = %d, want 2", len(ospf.Occurrences))
	}
	if !strings.Contains(ospf.Occurrences[0].Description, "10.10.10.2") ||
		!strings.Contains(ospf.Occurrences[1].Description, "10.10.10.3") {
		t.Fatalf("per-occurrence raw text lost: %+v", ospf.Occurrences)
	}
	if ospf.Occurrences[1].Ts.Before(ospf.Occurrences[0].Ts) {
		t.Error("occurrences must be sorted oldest-first")
	}

	cu, ok := byLabel["Content Update Failure"]
	if !ok {
		t.Fatal("missing Content Update Failure group")
	}
	if cu.Count != 2 {
		t.Fatalf("content update group count = %d, want 2", cu.Count)
	}
	if cu.Severity != "medium" {
		t.Fatalf("content update severity = %q, want medium", cu.Severity)
	}

	ha, ok := byLabel["HA Failover"]
	if !ok {
		t.Fatal("missing HA Failover group")
	}
	if ha.Count != 2 {
		t.Fatalf("HA group count = %d, want 2", ha.Count)
	}
	// severity must escalate to the worst seen in the group (critical, not low)
	if ha.Severity != "critical" {
		t.Fatalf("HA severity = %q, want critical (escalated from low)", ha.Severity)
	}
}

func TestGroupAnomaliesDropsNoise(t *testing.T) {
	events := parseSystemLogEvents(bytes.NewReader([]byte(sampleSystemLog)))
	groups := GroupAnomalies(events)
	for _, g := range groups {
		if g.Label == "" {
			t.Errorf("group with empty label: %+v", g)
		}
	}
	total := 0
	for _, g := range groups {
		total += g.Count
	}
	// 8 lines - 2 "successfully connect" noise lines = 6 counted occurrences
	if total != 6 {
		t.Fatalf("total grouped occurrences = %d, want 6 (2 successful-connect lines must be dropped)", total)
	}
}

func TestGroupAnomaliesSortedBySeverityThenCount(t *testing.T) {
	events := parseSystemLogEvents(bytes.NewReader([]byte(sampleSystemLog)))
	groups := GroupAnomalies(events)
	for i := 1; i < len(groups); i++ {
		prev, cur := groups[i-1], groups[i]
		ps, cs := severityRank(prev.Severity), severityRank(cur.Severity)
		if ps < cs {
			t.Fatalf("severity out of order at %d: %q(%s) before %q(%s)", i, prev.Label, prev.Severity, cur.Label, cur.Severity)
		}
		if ps == cs && prev.Count < cur.Count {
			t.Fatalf("count out of order within severity %s: %+v then %+v", cur.Severity, prev, cur)
		}
	}
	// the critical HA group must lead, ahead of the more frequent-but-lower
	// severity groups
	if len(groups) > 0 && groups[0].Label != "HA Failover" {
		t.Fatalf("first group = %q (%s), want the critical HA Failover group first", groups[0].Label, groups[0].Severity)
	}
}

// Device telemetry uploads name a per-hour .tgz file, so every occurrence
// has different text. They must still collapse into one group.
const sampleTelemetryLog = `2026/08/01 16:30:11 medium   general                          general                   0  Failed to send: file 'PA_007900000836465_dt_12.1.2_20260801_1530_1-hr-interval_HOUR.tgz'
2026/08/01 17:30:14 medium   general                          general                   0  Failed to send: file 'PA_007900000836465_dt_12.1.2_20260801_1630_1-hr-interval_HOUR.tgz'
2026/08/01 18:30:09 medium   general                          general                   0  Failed to send: file 'PA_007900000836465_dt_12.1.2_20260801_1730_1-hr-interval_HOUR.tgz'
2026/08/02 09:15:00 medium   general                          general                   0  Failed to send: file 'PA_007900000836465_dt_12.1.2_20260802_0815_1-hr-interval_HOUR.tgz'
`

func TestDeviceTelemetryMergesAcrossHours(t *testing.T) {
	events := parseSystemLogEvents(bytes.NewReader([]byte(sampleTelemetryLog)))
	if len(events) != 4 {
		t.Fatalf("parsed %d events, want 4", len(events))
	}
	groups := GroupAnomalies(events)
	if len(groups) != 1 {
		labels := []string{}
		for _, g := range groups {
			labels = append(labels, g.Label)
		}
		t.Fatalf("got %d groups %v, want 1 (all telemetry send failures must merge)", len(groups), labels)
	}
	g := groups[0]
	if g.Count != 4 {
		t.Fatalf("count = %d, want 4", g.Count)
	}
	if len(g.Occurrences) != 4 {
		t.Fatalf("occurrences = %d, want 4", len(g.Occurrences))
	}
	// the individual filenames must survive per occurrence
	if !strings.Contains(g.Occurrences[0].Description, "20260801_1530") {
		t.Errorf("first occurrence lost its filename: %q", g.Occurrences[0].Description)
	}
	if !strings.Contains(g.Occurrences[3].Description, "20260802_0815") {
		t.Errorf("last occurrence lost its filename: %q", g.Occurrences[3].Description)
	}
}

// Guards the specific bug that split telemetry per hour: \b\d+\b never
// matches digits adjacent to "_", so underscore-delimited serials, dates
// and hours used to survive normalization.
func TestNormalizeTemplateHandlesUnderscoreDelimitedDigits(t *testing.T) {
	a := normalizeTemplate("Failed to send: file 'PA_007900000836465_dt_12.1.2_20260801_1530_1-hr-interval_HOUR.tgz'")
	b := normalizeTemplate("Failed to send: file 'PA_007900000836465_dt_12.1.2_20260801_1630_1-hr-interval_HOUR.tgz'")
	if a != b {
		t.Fatalf("same event normalized differently:\n a = %q\n b = %q", a, b)
	}
	if strings.Contains(a, "20260801") || strings.Contains(a, "1530") {
		t.Errorf("date/hour survived normalization: %q", a)
	}
	c := normalizeTemplate("Config installed successfully from job_1234")
	if strings.Contains(c, "1234") {
		t.Errorf("underscore-prefixed number survived normalization: %q", c)
	}
}

func TestExtractAnomaliesFindsFile(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"tmp/cli/logs/show_log_system.txt": sampleSystemLog,
		"tmp/cli/other.txt":                "unrelated content",
	})
	groups, err := ExtractAnomalies(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) == 0 {
		t.Fatal("expected at least one anomaly group")
	}
}

func TestExtractAnomaliesMissing(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"tmp/cli/other.txt": "nothing relevant here",
	})
	if _, err := ExtractAnomalies(bytes.NewReader(tgz)); err != ErrNoSystemLog {
		t.Fatalf("got %v, want ErrNoSystemLog", err)
	}
}
