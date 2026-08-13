package parser

import (
	"bytes"
	"testing"
)

// Excerpt of a real CLI dump. The long application names matter: they push
// the numeric columns past the header width, so a fixed-width column parse
// would misread them.
const sampleCLIDump = `
==========================
 > show system info

hostname: PA-FW-LAB01
device-certificate-status: None

==========================
> request license info

License entry:
Feature: Adv Threat Prevention
Description: Adv Threat Prevention Sub
Serial: 007900000836465
Authcode:
Issued: April 03, 2026
Expires: September 04, 2026
Expired?: no
Base license: PA-VM

License entry:
Feature: AutoFocus Device License
Description: AutoFocus Device License
Serial: 007900000836465
Authcode: S1U56IY8
Issued: April 03, 2026
Expires: February 11, 2040
Expired?: no
Base license: PA-VM

License entry:
Feature: Logging Service
Description: Device Logging Service
Serial: 007900000836465
Log Storage TB: 1
Expires: never
Expired?: no
Base license: PA-VM

==========================
> show running application statistics

Vsys: 1
Number of apps: 4
App (report-as) sessions   packets    bytes        app changed threats
--------------- ---------- ---------- ------------ ----------- -------
ssl             763        298194     313818940    0           0
paloalto-userid-agent 1          26         9347         1           0
ping            22550      38050      2986028      0           2
claude-base     9          2092317    2606444222   11          0
--------------- ---------- ---------- ------------ ----------- -------
Total           23323      2428587    2923258537   12          2


==========================
> show clock

Tue Jun  9 10:15:02 PST 2026
`

func cliTgz(t *testing.T) []byte {
	t.Helper()
	return buildMultiTgz(t, map[string]string{
		"tmp/cli/techsupport_20260609.txt": sampleCLIDump,
		"var/log/pan/ms.log":               "unrelated",
	})
}

func TestExtractAppStats(t *testing.T) {
	st, err := ExtractAppStats(bytes.NewReader(cliTgz(t)))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Rows) != 4 {
		t.Fatalf("got %d rows, want 4: %+v", len(st.Rows), st.Rows)
	}
	if len(st.Vsyses) != 1 || st.Vsyses[0] != "1" {
		t.Errorf("vsyses = %v, want [1]", st.Vsyses)
	}

	by := map[string]AppStat{}
	for _, r := range st.Rows {
		by[r.App] = r
	}

	// the long name must not swallow a column
	ua, ok := by["paloalto-userid-agent"]
	if !ok {
		t.Fatalf("long application name not parsed: %+v", st.Rows)
	}
	if ua.Sessions != 1 || ua.Packets != 26 || ua.Bytes != 9347 || ua.AppChanged != 1 {
		t.Errorf("paloalto-userid-agent = %+v", ua)
	}

	// the Total line must not become a row
	if _, isRow := by["Total"]; isRow {
		t.Error("the Total line was parsed as an application")
	}
	// but it should be recorded for comparison
	if st.ReportedSessions != 23323 || st.ReportedBytes != 2923258537 {
		t.Errorf("reported totals = %v / %v", st.ReportedSessions, st.ReportedBytes)
	}
	// and our own sums must agree with it
	if st.TotalSessions != st.ReportedSessions || st.TotalBytes != st.ReportedBytes {
		t.Errorf("summed totals (%v/%v) disagree with the device (%v/%v)",
			st.TotalSessions, st.TotalBytes, st.ReportedSessions, st.ReportedBytes)
	}
}

func TestAppStatsDerivedMetrics(t *testing.T) {
	st, err := ExtractAppStats(bytes.NewReader(cliTgz(t)))
	if err != nil {
		t.Fatal(err)
	}
	var claude AppStat
	for _, r := range st.Rows {
		if r.App == "claude-base" {
			claude = r
		}
	}
	if claude.App == "" {
		t.Fatal("claude-base missing")
	}
	// 2606444222 of 2923258537 bytes ~= 89%
	if claude.BytesPct < 88 || claude.BytesPct > 90 {
		t.Errorf("bytes pct = %v, want ~89", claude.BytesPct)
	}
	if want := 2092317.0 / 9.0; claude.PacketsPerSession < want-1 || claude.PacketsPerSession > want+1 {
		t.Errorf("packets/session = %v, want ~%v", claude.PacketsPerSession, want)
	}
	if want := 2606444222.0 / 9.0; claude.BytesPerSession < want-1 || claude.BytesPerSession > want+1 {
		t.Errorf("bytes/session = %v, want ~%v", claude.BytesPerSession, want)
	}
	if want := 2606444222.0 / 2092317.0; claude.AvgPacketSize < want-1 || claude.AvgPacketSize > want+1 {
		t.Errorf("avg packet size = %v, want ~%v", claude.AvgPacketSize, want)
	}

	// percentages across all rows must add to 100 for each metric
	var sp, bp float64
	for _, r := range st.Rows {
		sp += r.SessionsPct
		bp += r.BytesPct
	}
	if sp < 99.9 || sp > 100.1 {
		t.Errorf("session percentages total %v, want 100", sp)
	}
	if bp < 99.9 || bp > 100.1 {
		t.Errorf("byte percentages total %v, want 100", bp)
	}
}

// A zero-session or zero-packet application must not produce a division blowup.
func TestAppStatsZeroDivision(t *testing.T) {
	body := []string{
		"Vsys: 1",
		"App (report-as) sessions   packets    bytes        app changed threats",
		"ipsec-esp       4          0          0            0           0",
		"idle-app        0          0          0            0           0",
	}
	st := parseAppStats(body)
	if len(st.Rows) != 2 {
		t.Fatalf("got %d rows", len(st.Rows))
	}
	for _, r := range st.Rows {
		if isNaNOrInf(r.PacketsPerSession) || isNaNOrInf(r.BytesPerSession) || isNaNOrInf(r.AvgPacketSize) {
			t.Errorf("%s produced a non-finite ratio: %+v", r.App, r)
		}
	}
}

func isNaNOrInf(f float64) bool {
	return f != f || f > 1e300 || f < -1e300
}

func TestExtractLicenses(t *testing.T) {
	lics, err := ExtractLicenses(bytes.NewReader(cliTgz(t)))
	if err != nil {
		t.Fatal(err)
	}
	if len(lics) != 3 {
		t.Fatalf("got %d licences, want 3: %+v", len(lics), lics)
	}

	first := lics[0]
	if first.Feature != "Adv Threat Prevention" {
		t.Errorf("feature = %q", first.Feature)
	}
	if first.Expires != "September 04, 2026" || first.Expired != "no" {
		t.Errorf("expiry = %q / %q", first.Expires, first.Expired)
	}
	if first.Authcode != "" {
		t.Errorf("blank authcode should stay blank, got %q", first.Authcode)
	}
	if lics[1].Authcode != "S1U56IY8" {
		t.Errorf("authcode = %q", lics[1].Authcode)
	}
	if lics[2].Expires != "never" {
		t.Errorf("a perpetual licence should keep 'never', got %q", lics[2].Expires)
	}
	// an unmodelled field must be preserved rather than dropped
	var sawStorage bool
	for _, kv := range lics[2].Other {
		if kv.Key == "Log Storage TB" && kv.Value == "1" {
			sawStorage = true
		}
	}
	if !sawStorage {
		t.Errorf("unmodelled licence field was dropped: %+v", lics[2].Other)
	}
}

func TestCLISectionStopsAtNextCommand(t *testing.T) {
	// "show clock" output must not leak into the app-stats section
	st, err := ExtractAppStats(bytes.NewReader(cliTgz(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range st.Rows {
		if r.App == "Tue" {
			t.Error("output from the following command leaked into the table")
		}
	}
}

func TestExtractAppStatsMissing(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{"tmp/cli/other.txt": "> show clock\nTue Jun 9\n"})
	if _, err := ExtractAppStats(bytes.NewReader(tgz)); err == nil {
		t.Fatal("expected an error when the section is absent")
	}
}
