package parser

import (
	"bytes"
	"strings"
	"testing"
)

// The content database maps numeric application IDs to names.
const sampleGlobalXML = `<?xml version="1.0"?>
<content>
  <application>
    <entry name="ibm-tsm" id="109"/>
    <entry name="ssl" id="15"><category>networking</category></entry>
    <entry id="2061" name="quic-base"/>
    <entry name="web-browsing" id="1"/>
  </application>
</content>
`

// A real "--- panio_infreq" block: the per-app table is keyed by numeric
// application ID and every line carries the panio ':' prefix.
const samplePanioInfreq = `2026-07-30 00:35:54.927 +0000  --- panio_infreq
:Time: Thu Jul 30 00:35:54 2026
:Vsys: 1
:Number of apps: 4
:App (report-as) sessions   packets    bytes        app changed threats
:--------------- ---------- ---------- ------------ ----------- -------
:1               3040       71827      21134306     3122        3223
:15              1421963    274502175  152236539894 0           363080
:109             596        12654      5905739      596         0
:2061            28         692        81791        0           0
2026-07-31 00:35:54.927 +0000  --- panio_infreq
:Time: Fri Jul 31 00:35:54 2026
:Vsys: 1
:Number of apps: 2
:App (report-as) sessions   packets    bytes        app changed threats
:--------------- ---------- ---------- ------------ ----------- -------
:15              1500000    280000000  160000000000 0           400000
:109             600        12700      5910000      600         0
`

func TestExtractAppIDs(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"opt/pancfg/mgmt/updates/curcontent/global/global.xml": sampleGlobalXML,
	})
	names, err := ExtractAppIDs(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]string{109: "ibm-tsm", 15: "ssl", 2061: "quic-base", 1: "web-browsing"}
	for id, n := range want {
		if names[id] != n {
			t.Errorf("id %d = %q, want %q", id, names[id], n)
		}
	}
}

// The content DB is not always collected; that must not be an error.
func TestExtractAppIDsMissingIsNotFatal(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{"var/log/pan/ms.log": "nothing"})
	names, err := ExtractAppIDs(bytes.NewReader(tgz))
	if err != nil {
		t.Fatalf("a missing content DB should not be an error: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("expected an empty map, got %v", names)
	}
}

func TestAppLabelFallback(t *testing.T) {
	names := map[int]string{15: "ssl"}
	if got := AppLabel(15, names); got != "ssl" {
		t.Errorf("mapped id = %q, want ssl", got)
	}
	if got := AppLabel(9999, names); got != "app-9999" {
		t.Errorf("unmapped id = %q, want app-9999", got)
	}
	if got := AppLabel(15, nil); got != "app-15" {
		t.Errorf("nil map = %q, want app-15", got)
	}
}

// The per-app table becomes counters, named when the content DB was present.
func TestPanioInfreqCounters(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"var/log/pan/dp-monitor.log":                           samplePanioInfreq,
		"opt/pancfg/mgmt/updates/curcontent/global/global.xml": sampleGlobalXML,
	})
	names, err := ExtractAppIDs(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	series, err := CollectAllCounters(bytes.NewReader(tgz), names)
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"dp__appstats__vsys1_ssl_sessions",
		"dp__appstats__vsys1_ssl_packets",
		"dp__appstats__vsys1_ssl_bytes",
		"dp__appstats__vsys1_ssl_app_changed",
		"dp__appstats__vsys1_ssl_threats",
		"dp__appstats__vsys1_ibm_tsm_bytes",
		"dp__appstats__vsys1_quic_base_bytes",
	} {
		if _, ok := series[want]; !ok {
			t.Errorf("missing counter %s", want)
		}
	}

	// ssl appears in both blocks, so it must be a two-point series in order
	ssl := series["dp__appstats__vsys1_ssl_bytes"]
	if len(ssl) != 2 {
		t.Fatalf("ssl bytes = %d samples, want 2 (one per block)", len(ssl))
	}
	if ssl[0].Value != 152236539894 || ssl[1].Value != 160000000000 {
		t.Errorf("ssl bytes series = %v", ssl)
	}
	if !ssl[0].Ts.Before(ssl[1].Ts) {
		t.Error("samples must be ordered oldest-first")
	}

	// the header, separator and ":Time:"/":Number of apps:" lines must not
	// become counters
	for name := range series {
		if strings.Contains(name, "appstats") &&
			(strings.Contains(name, "number") || strings.Contains(name, "time")) {
			t.Errorf("a header line became a counter: %s", name)
		}
	}
}

func TestPanioInfreqUnmappedIDs(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{"var/log/pan/dp-monitor.log": samplePanioInfreq})
	series, err := CollectAllCounters(bytes.NewReader(tgz), nil)
	if err != nil {
		t.Fatal(err)
	}
	// without the content DB the ID is still reported, just unnamed
	if _, ok := series["dp__appstats__vsys1_app_15_bytes"]; !ok {
		var got []string
		for n := range series {
			if strings.Contains(n, "appstats") {
				got = append(got, n)
			}
		}
		t.Fatalf("expected app_15 counters without a name map; got %v", got)
	}
}

func TestAppStatsFromSeries(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"var/log/pan/dp-monitor.log":                           samplePanioInfreq,
		"opt/pancfg/mgmt/updates/curcontent/global/global.xml": sampleGlobalXML,
	})
	names, _ := ExtractAppIDs(bytes.NewReader(tgz))
	series, err := CollectAllCounters(bytes.NewReader(tgz), names)
	if err != nil {
		t.Fatal(err)
	}
	st := AppStatsFromSeries(series, "dp")
	if st == nil {
		t.Fatal("no app stats derived from the counters")
	}
	if len(st.Rows) != 4 {
		t.Fatalf("got %d rows, want 4", len(st.Rows))
	}

	by := map[string]AppStat{}
	for _, r := range st.Rows {
		by[r.App] = r
	}
	ssl, ok := by["ssl"]
	if !ok {
		t.Fatalf("ssl missing: %+v", st.Rows)
	}
	// the counters are cumulative, so the latest sample is the volume
	if ssl.Bytes != 160000000000 || ssl.Sessions != 1500000 {
		t.Errorf("ssl should use the newest sample, got bytes=%v sessions=%v", ssl.Bytes, ssl.Sessions)
	}
	if ssl.Vsys != "1" {
		t.Errorf("vsys = %q, want 1", ssl.Vsys)
	}

	// derived figures
	if want := 280000000.0 / 1500000.0; ssl.PacketsPerSession < want-1 || ssl.PacketsPerSession > want+1 {
		t.Errorf("packets/session = %v, want ~%v", ssl.PacketsPerSession, want)
	}
	if want := 160000000000.0 / 280000000.0; ssl.AvgPacketSize < want-1 || ssl.AvgPacketSize > want+1 {
		t.Errorf("avg packet size = %v, want ~%v", ssl.AvgPacketSize, want)
	}

	// shares must total 100
	var bp, sp float64
	for _, r := range st.Rows {
		bp += r.BytesPct
		sp += r.SessionsPct
	}
	if bp < 99.9 || bp > 100.1 || sp < 99.9 || sp > 100.1 {
		t.Errorf("percentages should total 100: bytes=%v sessions=%v", bp, sp)
	}
	// ssl dominates the byte total here
	if ssl.BytesPct < 95 {
		t.Errorf("ssl bytes pct = %v, expected it to dominate", ssl.BytesPct)
	}
}

func TestAppStatsFromSeriesNoneWhenAbsent(t *testing.T) {
	if st := AppStatsFromSeries(Series{"dp__gc__pkt_recv": {{Value: 1}}}, "dp"); st != nil {
		t.Errorf("expected nil when no appstats counters exist, got %+v", st)
	}
}
