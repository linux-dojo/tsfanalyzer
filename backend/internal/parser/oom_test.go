package parser

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const sampleOOMLog = `2026/07/01 03:14:02 kernel: configd invoked oom-killer: gfp_mask=0x24201ca, order=0, oom_score_adj=0
2026/07/01 03:14:02 kernel: Out of memory: Killed process 4821 (logd) total-vm:6321004kB, anon-rss:5120044kB score 907
2026/07/01 03:19:41 kernel: pan_comm invoked oom-killer: gfp_mask=0x24201ca, order=0, oom_score_adj=0
2026/07/01 03:19:41 kernel: Out of memory: Killed process 5010 (reportd) total-vm:2100000kB, anon-rss:1800000kB score 604
`

func TestFindOOMEvents(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"var/log/messages":  sampleOOMLog,
		"tmp/cli/other.txt": "nothing here",
	})
	events, err := FindOOMEvents(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d OOM events, want 2: %+v", len(events), events)
	}
	first := events[0]
	if first.InvokedBy != "configd" {
		t.Errorf("invoked_by = %q, want configd (the requester, not the culprit)", first.InvokedBy)
	}
	if first.Killed != "logd" || first.KilledPid != "4821" {
		t.Errorf("killed = %q pid %q, want logd/4821", first.Killed, first.KilledPid)
	}
	if first.Score != "907" {
		t.Errorf("score = %q, want 907", first.Score)
	}
	if events[1].Killed != "reportd" {
		t.Errorf("second killed = %q, want reportd", events[1].Killed)
	}
	// events must be time-ordered so FirstOOM is genuinely the earliest
	if events[1].Ts.Before(events[0].Ts) {
		t.Error("events not sorted oldest-first")
	}
}

func TestFindOOMEventsNoneFound(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"var/log/messages": "2026/07/01 03:14:02 kernel: everything is fine\n",
	})
	events, err := FindOOMEvents(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0", len(events))
	}
}

// helper: build a linear series of samples
func mkSeries(name string, startVal, endVal float64, from time.Time, days int) []CounterSample {
	var out []CounterSample
	for i := 0; i <= days; i++ {
		frac := float64(i) / float64(days)
		out = append(out, CounterSample{
			Name:  name,
			Ts:    from.AddDate(0, 0, i),
			Value: startVal + (endVal-startVal)*frac,
		})
	}
	return out
}

// The documented user-space workflow: available memory falls, and one
// process's Res+Swap growth accounts for it.
func TestAnalyzeMemoryUserspaceLeak(t *testing.T) {
	from := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	var s []CounterSample
	// available memory drops 10 GB across 30 days (kB)
	s = append(s, mkSeries("mp__memorydetail__memavailable", 12*1024*1024, 2*1024*1024, from, 30)...)
	// logd grows 5 GB — the biggest contributor
	s = append(s, mkSeries("mp__processes__logd_1001_res_swap", 200_000, 5*1024*1024+200_000, from, 30)...)
	// useridd grows 2 GB
	s = append(s, mkSeries("mp__processes__useridd_1002_res_swap", 100_000, 2*1024*1024+100_000, from, 30)...)
	// a big but flat process must NOT be flagged: high usage alone isn't a leak
	s = append(s, mkSeries("mp__processes__pan_task_1003_res_swap", 6*1024*1024, 6*1024*1024, from, 30)...)

	a := AnalyzeMemory(s, nil, "mp")

	if a.Trend == nil {
		t.Fatal("no trend computed")
	}
	if a.Trend.Counter != "mp__memorydetail__memavailable" {
		t.Errorf("trend counter = %q, want memavailable (preferred over free/top)", a.Trend.Counter)
	}
	wantDrop := 10 * 1024 * 1024.0
	if diff := a.Trend.DropKB - wantDrop; diff > 1024 || diff < -1024 {
		t.Errorf("drop = %v kB, want ~%v", a.Trend.DropKB, wantDrop)
	}
	if len(a.Suspects) == 0 {
		t.Fatal("no suspects found")
	}
	if a.Suspects[0].Name != "logd" {
		t.Errorf("top suspect = %q, want logd (largest growth)", a.Suspects[0].Name)
	}
	for _, sus := range a.Suspects {
		if sus.Name == "pan_task" {
			t.Errorf("flat high-memory process was flagged as a suspect: %+v", sus)
		}
	}
	// logd's 5 GB of a 10 GB decline is about half
	if p := a.Suspects[0].PctOfDrop; p < 45 || p > 55 {
		t.Errorf("logd pct_of_drop = %v, want ~50", p)
	}
	if a.KernelLikely {
		t.Error("kernel leak should not be suspected when processes explain the drop")
	}
}

// The documented kernel path: no process accounts for the decline, and
// unreclaimable slab / a slab cache does.
func TestAnalyzeMemoryKernelLeak(t *testing.T) {
	from := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	var s []CounterSample
	// 6 GB decline over 40 days
	s = append(s, mkSeries("mp__memorydetail__memavailable", 8*1024*1024, 2*1024*1024, from, 40)...)
	// no process grows more than ~200 MB
	s = append(s, mkSeries("mp__processes__configd_1001_res_swap", 300_000, 500_000, from, 40)...)
	s = append(s, mkSeries("mp__processes__devsrvr_1002_res_swap", 200_000, 300_000, from, 40)...)
	// unreclaimable slab grows ~5.5 GB, and kmalloc-96 accounts for it
	s = append(s, mkSeries("mp__memorydetail__sunreclaim", 500_000, 500_000+5.5*1024*1024, from, 40)...)
	s = append(s, mkSeries("mp__slabinfo__kmalloc_96_totalactsize", 100*1024*1024, 5*1024*1024*1024, from, 40)...)

	a := AnalyzeMemory(s, nil, "mp")

	if !a.KernelLikely {
		t.Fatalf("kernel leak not suspected; explained=%v%% suspects=%d kernel=%d",
			a.Explained, len(a.Suspects), len(a.KernelSuspects))
	}
	if a.Explained > userspaceExplainsThreshold {
		t.Errorf("explained = %v%%, expected well under %v%%", a.Explained, userspaceExplainsThreshold)
	}
	if len(a.KernelSuspects) == 0 {
		t.Fatal("no kernel suspects")
	}
	// slab growth (~5.5 GB) must outrank the kmalloc cache (~4.9 GB) or vice
	// versa, but both must be present and expressed in kB
	var sawSunreclaim, sawKmalloc bool
	for _, k := range a.KernelSuspects {
		if strings.Contains(k.Counter, "sunreclaim") {
			sawSunreclaim = true
			if k.GrowthKB < 5*1024*1024 {
				t.Errorf("sunreclaim growth = %v kB, want ~5.5 GB", k.GrowthKB)
			}
		}
		if strings.Contains(k.Counter, "kmalloc_96") {
			sawKmalloc = true
			// slabinfo is in bytes and must be converted to kB
			if k.GrowthKB > 5*1024*1024 {
				t.Errorf("kmalloc-96 growth = %v kB — looks unconverted from bytes", k.GrowthKB)
			}
		}
	}
	if !sawSunreclaim || !sawKmalloc {
		t.Errorf("missing kernel suspects: sunreclaim=%v kmalloc=%v", sawSunreclaim, sawKmalloc)
	}
}

func TestAnalyzeMemoryTopAvailUnitConversion(t *testing.T) {
	from := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	// only the top block is available; it prints MiB and must be scaled to kB
	s := mkSeries("mp__top__avail_mem", 4000, 1000, from, 10)
	a := AnalyzeMemory(s, nil, "mp")
	if a.Trend == nil {
		t.Fatal("no trend")
	}
	if a.Trend.StartKB != 4000*1024 {
		t.Errorf("start = %v kB, want %v (MiB must be converted)", a.Trend.StartKB, 4000*1024)
	}
	if a.Trend.DropKB != 3000*1024 {
		t.Errorf("drop = %v kB, want %v", a.Trend.DropKB, 3000*1024)
	}
}

// Several PIDs alive at the same sample is a genuine fault; several PIDs
// merely seen across the window is just a restart and must not be reported
// as duplicate instances.
func TestAnalyzeMemoryConcurrentDuplicatesOnly(t *testing.T) {
	from := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	var s []CounterSample
	s = append(s, mkSeries("mp__memorydetail__memavailable", 4*1024*1024, 3*1024*1024, from, 5)...)
	// two pan_comm PIDs sampled at the same timestamps: concurrent
	s = append(s, mkSeries("mp__processes__pan_comm_2001_res_swap", 100_000, 120_000, from, 5)...)
	s = append(s, mkSeries("mp__processes__pan_comm_2002_res_swap", 100_000, 120_000, from, 5)...)
	// useridd hands over from one PID to the next: a restart, not a duplicate
	s = append(s, mkSeries("mp__processes__useridd_3001_res_swap", 400_000, 900_000, from, 5)...)
	s = append(s, mkSeries("mp__processes__useridd_3002_res_swap", 500_000, 520_000, from.AddDate(0, 0, 6), 5)...)

	a := AnalyzeMemory(s, nil, "mp")
	has := func(n string) bool {
		for _, d := range a.Duplicates {
			if d == n {
				return true
			}
		}
		return false
	}
	if !has("pan_comm") {
		t.Errorf("concurrent pan_comm PIDs not reported: %v", a.Duplicates)
	}
	if has("useridd") {
		t.Errorf("a sequential restart was misreported as multiple instances: %v", a.Duplicates)
	}
}

// The reported real-world case: useridd sat at ~1.4 GB, was restarted (new
// PID), then ran steadily around 700 MB. The memory the restart handed back
// and did not re-acquire is the leak evidence, and both PIDs must be exposed
// so the before/after can be plotted.
func TestAnalyzeMemoryRestartReclaimIsTheEvidence(t *testing.T) {
	from := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	const mb = 1024.0
	var s []CounterSample
	s = append(s, mkSeries("mp__memorydetail__memavailable", 6*1024*1024, 4*1024*1024, from, 30)...)
	// pid 11889: climbs 400 MB -> 1.4 GB over 20 days
	s = append(s, mkSeries("mp__processes__useridd_11889_res_swap", 400*mb, 1400*mb, from, 20)...)
	// pid 23011: settles at ~700 MB and stays there
	s = append(s, mkSeries("mp__processes__useridd_23011_res_swap", 700*mb, 715*mb, from.AddDate(0, 0, 21), 9)...)
	// a legitimately large but flat daemon must not outrank it
	s = append(s, mkSeries("mp__processes__pan_task_900_res_swap", 1200*mb, 1200*mb, from, 30)...)

	a := AnalyzeMemory(s, nil, "mp")
	if len(a.Suspects) == 0 {
		t.Fatal("no suspects")
	}
	var u *MemSuspect
	for i := range a.Suspects {
		if a.Suspects[i].Name == "useridd" {
			u = &a.Suspects[i]
		}
		if a.Suspects[i].Name == "pan_task" {
			t.Error("a flat 1.2 GB daemon should not be a suspect at all")
		}
	}
	if u == nil {
		t.Fatalf("useridd missing from suspects: %+v", a.Suspects)
	}
	if a.Suspects[0].Name != "useridd" {
		t.Errorf("top suspect = %q, want useridd", a.Suspects[0].Name)
	}
	if !u.Restarted {
		t.Error("restart across PIDs not detected")
	}
	if u.PeakKB < 1390*mb || u.PeakKB > 1410*mb {
		t.Errorf("peak = %v kB, want ~1.4 GB", u.PeakKB)
	}
	if u.PostRestartKB < 690*mb || u.PostRestartKB > 730*mb {
		t.Errorf("post-restart level = %v kB, want ~700 MB", u.PostRestartKB)
	}
	if u.ReclaimedKB < 650*mb || u.ReclaimedKB > 730*mb {
		t.Errorf("reclaimed = %v kB, want ~700 MB", u.ReclaimedKB)
	}
	// both PIDs must be exposed so the chart can span the restart
	if len(u.PIDs) != 2 {
		t.Errorf("PIDs = %v, want both 11889 and 23011", u.PIDs)
	}
	if len(u.Counters) != 2 {
		t.Errorf("Counters = %v, want one series per PID", u.Counters)
	}
}

func TestAnalyzeMemoryFindingsMentionOOMCaveat(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{"var/log/messages": sampleOOMLog})
	oom, err := FindOOMEvents(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	a := AnalyzeMemory(nil, oom, "mp")
	if a.FirstOOM == nil || a.FirstOOM.Killed != "logd" {
		t.Fatalf("first OOM = %+v", a.FirstOOM)
	}
	var joined string
	for _, f := range a.Findings {
		joined += f.Severity + " " + f.Title + " " + f.Detail + "\n"
	}
	if !strings.Contains(joined, "critical") {
		t.Error("an OOM should raise a critical finding")
	}
	// the report must not imply the named processes are the cause
	if !strings.Contains(strings.ToLower(joined), "not necessarily the cause") {
		t.Errorf("findings should caveat that the named processes aren't the culprit:\n%s", joined)
	}
}

// Regression: nil slices marshal to JSON null, and the UI calls .length /
// .map on these fields directly. An archive with no OOM events is the
// normal case, so every slice must survive as [] rather than null.
func TestAnalyzeMemoryNeverMarshalsNullSlices(t *testing.T) {
	for _, tc := range []struct {
		name    string
		samples []CounterSample
		oom     []OOMEvent
	}{
		{"completely empty", nil, nil},
		{"counters but no OOM", mkSeries("mp__memorydetail__memavailable", 4*1024*1024, 4*1024*1024, time.Now(), 3), nil},
		{"OOM but no counters", nil, []OOMEvent{{Killed: "logd"}}},
	} {
		a := AnalyzeMemory(tc.samples, tc.oom, "mp")
		b, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("%s: marshal: %v", tc.name, err)
		}
		s := string(b)
		for _, field := range []string{
			`"oom_events":null`, `"suspects":null`, `"kernel_suspects":null`,
			`"duplicates":null`, `"findings":null`,
		} {
			if strings.Contains(s, field) {
				t.Errorf("%s: %s would crash the UI\n%s", tc.name, field, s)
			}
		}
	}
}

func TestConfigSizeRiskNeverNil(t *testing.T) {
	// no mergesp.xml and no memory counters: still must be a usable array
	f := ConfigSizeRisk(nil, nil, "mp")
	if f == nil {
		t.Fatal("ConfigSizeRisk returned nil; marshals to null and breaks the UI spread")
	}
	b, _ := json.Marshal(f)
	if string(b) != "[]" {
		t.Errorf("got %s, want []", b)
	}
}

func TestGroupAnomaliesOccurrencesNeverNil(t *testing.T) {
	groups := GroupAnomalies([]AnomalyEvent{{Ts: time.Now(), Severity: "high", Subtype: "general", Description: "OSPF neighbor down"}})
	if len(groups) == 0 {
		t.Fatal("no groups")
	}
	b, _ := json.Marshal(groups[0])
	if strings.Contains(string(b), `"occurrences":null`) {
		t.Errorf("occurrences marshalled as null: %s", b)
	}
}

func TestConfigSizeRiskLowMemoryVM(t *testing.T) {
	from := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	// 8 GB VM: under the 9 GB threshold
	s := mkSeries("mp__memorydetail__memtotal", 8*1024*1024, 8*1024*1024, from, 2)
	entries := []ArchiveEntry{{Path: "opt/pancfg/mgmt/saved/mergesp.xml", Size: 30 << 20}} // 30 MB
	f := ConfigSizeRisk(entries, s, "mp")
	if len(f) == 0 {
		t.Fatal("expected a config-size finding")
	}
	if f[0].Severity != "high" {
		t.Errorf("severity = %q, want high (30 MB config on an 8 GB VM)", f[0].Severity)
	}
	if !strings.Contains(f[0].Detail, "26 MB") {
		t.Errorf("detail should reference the 26 MB threshold: %q", f[0].Detail)
	}
}

func TestConfigSizeRiskSmallConfig(t *testing.T) {
	from := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	s := mkSeries("mp__memorydetail__memtotal", 32*1024*1024, 32*1024*1024, from, 2)
	entries := []ArchiveEntry{{Path: "opt/pancfg/mgmt/saved/mergesp.xml", Size: 4 << 20}}
	f := ConfigSizeRisk(entries, s, "mp")
	if len(f) != 1 || f[0].Severity != "info" {
		t.Fatalf("small config on a big box should be info only: %+v", f)
	}
}
