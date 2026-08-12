package parser

import (
	"strings"
	"testing"
	"time"
)

func atTime(name string, base time.Time, vals ...float64) []CounterSample {
	out := make([]CounterSample, 0, len(vals))
	for i, v := range vals {
		out = append(out, CounterSample{Name: name, Ts: base.Add(time.Duration(i) * time.Minute), Value: v})
	}
	return out
}

func groupsByLabel(g []AnomalyGroup) map[string]AnomalyGroup {
	m := map[string]AnomalyGroup{}
	for _, x := range g {
		m[x.Label] = x
	}
	return m
}

func TestCounterAnomaliesLoadAverageBands(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	// below, between 2.5 and 5, and above 5
	s := atTime("mp__cpu_load_avg__i_1", base, 0.8, 3.1, 6.2, 2.0, 5.5)
	got := groupsByLabel(CounterAnomalies(s))

	warn, ok := got["mp cpu 1 min load above 2.5"]
	if !ok {
		t.Fatalf("missing above-2.5 group: %v", got)
	}
	if warn.Count != 1 {
		t.Errorf("above-2.5 count = %d, want 1 (only the 3.1 sample; 6.2 and 5.5 belong to the higher band)", warn.Count)
	}
	if warn.Severity != "critical" {
		t.Errorf("above-2.5 severity = %q, want critical", warn.Severity)
	}

	high, ok := got["mp cpu 1 min load above 5"]
	if !ok {
		t.Fatalf("missing above-5 group: %v", got)
	}
	if high.Count != 2 {
		t.Errorf("above-5 count = %d, want 2 (6.2 and 5.5)", high.Count)
	}
	if high.Severity != "critical" {
		t.Errorf("above-5 severity = %q, want critical", high.Severity)
	}
	if !strings.Contains(high.Occurrences[0].Description, "6.2") {
		t.Errorf("occurrence should carry the breaching value: %q", high.Occurrences[0].Description)
	}
}

func TestCounterAnomaliesLoadWindowsAreSeparate(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	var s []CounterSample
	s = append(s, atTime("mp__cpu_load_avg__i_1", base, 6.0)...)
	s = append(s, atTime("mp__cpu_load_avg__i_5", base, 6.0)...)
	s = append(s, atTime("mp__cpu_load_avg__i_15", base, 3.0)...)
	s = append(s, atTime("dp__cpu_load_avg__i_1", base, 6.0)...)
	got := groupsByLabel(CounterAnomalies(s))
	for _, want := range []string{
		"mp cpu 1 min load above 5",
		"mp cpu 5 min load above 5",
		"mp cpu 15 min load above 2.5",
		"dp cpu 1 min load above 5",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing group %q", want)
		}
	}
}

func TestCounterAnomaliesIowaitBands(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	s := atTime("mp__top__cpu__iowait_pct", base, 0.5, 3.0, 7.5)
	got := groupsByLabel(CounterAnomalies(s))

	hi, ok := got["mp cpu iowait above 2"]
	if !ok || hi.Severity != "high" {
		t.Fatalf("iowait above 2 = %+v, want present with high severity", hi)
	}
	if hi.Count != 1 {
		t.Errorf("iowait above-2 count = %d, want 1", hi.Count)
	}
	crit, ok := got["mp cpu iowait above 5"]
	if !ok || crit.Severity != "critical" {
		t.Fatalf("iowait above 5 = %+v, want present with critical severity", crit)
	}
}

func TestCounterAnomaliesPlaneCPU(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	var s []CounterSample
	s = append(s, atTime("dp__cpu__last_3m_avg_pct", base, 40, 92)...)
	s = append(s, atTime("dp__cpu__last_3m_max_pct", base, 70, 99)...)
	// per-core entries collapse into one group per plane+kind
	s = append(s, atTime("dp__cpu__03_max", base, 85)...)
	s = append(s, atTime("dp__cpu__07_max", base, 91)...)
	got := groupsByLabel(CounterAnomalies(s))

	if g, ok := got["dp cpu avg above 80%"]; !ok || g.Severity != "critical" || g.Count != 1 {
		t.Errorf("dp cpu avg group = %+v", g)
	}
	if g, ok := got["dp cpu max above 80%"]; !ok || g.Count != 1 {
		t.Errorf("dp cpu max group = %+v", g)
	}
	core, ok := got["dp cpu core max above 80%"]
	if !ok {
		t.Fatal("missing per-core group")
	}
	if core.Count != 2 {
		t.Errorf("core group count = %d, want 2 (both cores in one group)", core.Count)
	}
	var sawCore3, sawCore7 bool
	for _, o := range core.Occurrences {
		if strings.Contains(o.Description, "core 03") {
			sawCore3 = true
		}
		if strings.Contains(o.Description, "core 07") {
			sawCore7 = true
		}
	}
	if !sawCore3 || !sawCore7 {
		t.Errorf("occurrences must name the core: %+v", core.Occurrences)
	}
}

func TestCounterAnomaliesProcessCPU(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	var s []CounterSample
	s = append(s, atTime("mp__processes__useridd_11889_cpu", base, 12, 91, 96)...)
	s = append(s, atTime("mp__processes__logd_1001_cpu", base, 10, 20)...) // below threshold
	got := groupsByLabel(CounterAnomalies(s))

	g, ok := got["mp process useridd cpu above 85%"]
	if !ok {
		t.Fatalf("missing per-process group: %v", got)
	}
	if g.Count != 2 || g.Severity != "high" {
		t.Errorf("group = count %d severity %q, want 2/high", g.Count, g.Severity)
	}
	if !strings.Contains(g.Occurrences[0].Description, "pid 11889") {
		t.Errorf("occurrence should name the pid: %q", g.Occurrences[0].Description)
	}
	for label := range got {
		if strings.Contains(label, "logd") {
			t.Errorf("process below threshold was flagged: %q", label)
		}
	}
}

func TestCounterAnomaliesGrowingSocketQueue(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	// steadily climbing recv_q
	rising := atTime("mp__netstat_detail__tcp_mgmtsrvr_recv_q", base, 0, 0, 500, 2000, 8000, 20000, 60000)
	// a transient spike that drains: must NOT be flagged
	spike := atTime("mp__netstat_detail__tcp_sslmgr_send_q", base, 0, 0, 9000, 0, 0, 0, 0)
	got := groupsByLabel(CounterAnomalies(append(rising, spike...)))

	g, ok := got["mp netstat tcp_mgmtsrvr recv_q increasing"]
	if !ok {
		t.Fatalf("growing queue not flagged: %v", got)
	}
	if g.Count == 0 {
		t.Error("expected occurrences for the rising samples")
	}
	if !strings.Contains(g.Sample, "grew from") {
		t.Errorf("sample should describe the growth: %q", g.Sample)
	}
	for label := range got {
		if strings.Contains(label, "sslmgr") {
			t.Errorf("a transient spike that drained was flagged: %q", label)
		}
	}
}

func TestCounterAnomaliesQueueNeedsEnoughSamples(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	s := atTime("mp__netstat_detail__tcp_foo_recv_q", base, 0, 100)
	if g := CounterAnomalies(s); len(g) != 0 {
		t.Errorf("two samples should be too few to call a trend: %+v", g)
	}
}

func TestCounterAnomaliesSortedBySeverityThenCount(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	var s []CounterSample
	s = append(s, atTime("mp__processes__x_1_cpu", base, 90)...)               // high
	s = append(s, atTime("mp__cpu_load_avg__i_1", base, 6, 6, 6)...)          // critical, 3
	s = append(s, atTime("mp__cpu_load_avg__i_5", base, 6)...)                // critical, 1
	out := CounterAnomalies(s)
	if len(out) < 3 {
		t.Fatalf("want 3 groups, got %d", len(out))
	}
	if severityRank(out[0].Severity) < severityRank(out[len(out)-1].Severity) {
		t.Errorf("not sorted by severity: %+v", out)
	}
	if out[0].Severity == "critical" && out[1].Severity == "critical" && out[0].Count < out[1].Count {
		t.Errorf("equal severities not sorted by count: %d then %d", out[0].Count, out[1].Count)
	}
}

func TestCounterAnomaliesIgnoresUnrelatedCounters(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	s := atTime("mp__gc__pkt_recv", base, 999999, 1000000)
	if g := CounterAnomalies(s); len(g) != 0 {
		t.Errorf("unrelated counters must not produce anomalies: %+v", g)
	}
}
