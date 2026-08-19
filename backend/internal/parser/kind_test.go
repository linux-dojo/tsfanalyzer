package parser

import "testing"

func kindEntries(paths ...string) []ArchiveEntry {
	out := make([]ArchiveEntry, 0, len(paths))
	for _, p := range paths {
		out = append(out, ArchiveEntry{Path: p, Size: 100})
	}
	return out
}

func TestDetectKindFirewall(t *testing.T) {
	got := DetectKind(kindEntries(
		"opt/pancfg/mgmt/mergesp.xml",
		"tmp/cli/techsupport.txt",
		"var/log/pan/dp-monitor.log",
		"var/log/pan/ms.log",
	))
	if got.Kind != KindFirewall {
		t.Fatalf("got %q, want firewall (markers %v)", got.Kind, got.Markers)
	}
	if len(got.Markers) == 0 {
		t.Error("the deciding paths should be reported")
	}
}

func TestDetectKindGPAgent(t *testing.T) {
	got := DetectKind(kindEntries(
		"PanGPS.log",
		"PanGPA.log",
		"pan_gp_event.log",
		"PanGpHip.log",
		"HipReport.xml",
	))
	if got.Kind != KindGPAgent {
		t.Fatalf("got %q, want gp-agent (markers %v)", got.Kind, got.Markers)
	}
	if got.GPHits < 4 {
		t.Errorf("expected several GP markers, got %d", got.GPHits)
	}
}

// The case that actually matters: a firewall tech-support file also contains
// GlobalProtect material, because the portal and gateway write their own logs.
// A firewall marker must outweigh any number of GP-looking names, or every
// tech-support file with GlobalProtect configured would be misfiled.
func TestDetectKindFirewallWinsOverGlobalProtectFiles(t *testing.T) {
	got := DetectKind(kindEntries(
		"opt/pancfg/mgmt/mergesp.xml",
		"var/log/pan/gpsvc.log",
		"var/log/pan/PanGPS.log",
		"tmp/cli/logs/PanGPA.log",
		"opt/pancfg/globalprotect/HipReport.xml",
	))
	if got.Kind != KindFirewall {
		t.Fatalf("a tech-support file with GlobalProtect logs was classified %q", got.Kind)
	}
}

// Even one firewall marker among many GP names is decisive.
func TestDetectKindSingleFirewallMarkerDecides(t *testing.T) {
	paths := []string{"PanGPS.log", "PanGPA.log", "pan_gp_event.log", "PanNExt.log"}
	if got := DetectKind(kindEntries(paths...)); got.Kind != KindGPAgent {
		t.Fatalf("baseline: got %q, want gp-agent", got.Kind)
	}
	paths = append(paths, "opt/pancfg/mgmt/running-config.xml")
	if got := DetectKind(kindEntries(paths...)); got.Kind != KindFirewall {
		t.Fatalf("one firewall marker should decide it, got %q", got.Kind)
	}
}

// A GP collection whose file names are not the documented ones should still be
// recognised by shape: small, flat, mostly logs.
func TestDetectKindUnknownNamesFallBackToShape(t *testing.T) {
	got := DetectKind(kindEntries(
		"logs/client-service.log",
		"logs/client-ui.log",
		"logs/events.log",
		"version.txt",
	))
	if got.Kind != KindGPAgent {
		t.Errorf("a small flat bundle of logs should read as an agent collection, got %q", got.Kind)
	}
}

// ...but a big archive of logs is not, or a tech-support file missing its
// marker paths would be misfiled as an endpoint collection.
func TestDetectKindLargeLogArchiveIsNotGP(t *testing.T) {
	var paths []string
	for i := 0; i < 400; i++ {
		paths = append(paths, "logs/file"+string(rune('a'+i%26))+".log")
	}
	if got := DetectKind(kindEntries(paths...)); got.Kind == KindGPAgent {
		t.Error("a large log archive should not be assumed to be an agent collection")
	}
}

func TestDetectKindEmptyAndUnrecognised(t *testing.T) {
	if got := DetectKind(nil); got.Kind != KindUnknown {
		t.Errorf("empty archive: got %q, want unknown", got.Kind)
	}
	got := DetectKind(kindEntries("readme.txt", "data.bin", "notes.md"))
	if got.Kind != KindUnknown {
		t.Errorf("unrecognised archive: got %q, want unknown", got.Kind)
	}
}

// Paths are normalised before matching, so a "./" prefix must not hide a marker.
func TestDetectKindNormalisesPaths(t *testing.T) {
	if got := DetectKind(kindEntries("./opt/pancfg/mgmt/mergesp.xml")); got.Kind != KindFirewall {
		t.Errorf(`a "./" prefix hid the marker: got %q`, got.Kind)
	}
	if got := DetectKind(kindEntries("/PanGPS.log", "/PanGPA.log")); got.Kind != KindGPAgent {
		t.Errorf(`a leading "/" hid the marker: got %q`, got.Kind)
	}
}

func TestArchiveKindLabels(t *testing.T) {
	for k, want := range map[ArchiveKind]string{
		KindFirewall: "Firewall tech-support",
		KindGPAgent:  "GlobalProtect agent",
		KindUnknown:  "Unrecognised archive",
	} {
		if got := k.Label(); got != want {
			t.Errorf("%q label = %q, want %q", k, got, want)
		}
	}
}
