package parser

import (
	"strings"
	"testing"
	"time"
)

// These lines are real, one per format, and stand in for the files they came
// from. The macOS one is the shape that exposed the routing bug on screen.
const (
	macLine     = "P1571-T16387 07/16/2026 07:24:40:520 Debug(11558): Cas auth"
	eventLine   = "08/18/2026 13:55:40:423 [Info ]: portal status is Connected."
	traceLine   = "(P11496-T6520)Info (11298): 08/18/26 13:55:40:474 Connect method is user-logon"
	monitorLine = "2026-06-09 11:27:40.087 -0700  --- panio"
	dumpLine    = `        "PortalList" : [`
)

func repeat(line string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = line
	}
	return out
}

// The bug: a file whose opening lines are a plist or JSON dump was sent to the
// monitor parser, which understands none of the GlobalProtect formats. Every
// row then lost its timestamp and label — the whole raw line landed in the
// message column — and because a row with no timestamp cannot be placed in a
// range, the time filter matched nothing at all.
//
// The old rule asked whether half of the first twenty lines were GlobalProtect
// lines. Eleven dump lines were enough to fail it.
func TestGPFileOpeningWithADumpIsStillRoutedToTheGPParser(t *testing.T) {
	head := append(repeat(dumpLine, 60), repeat(macLine, 20)...)
	if !looksLikeGPLog(head) {
		t.Fatal("a GlobalProtect file that opens with a dump was misrouted; " +
			"its rows would show no timestamp and no label at all")
	}
}

// The sample is wide enough that a long dump does not exhaust it. PanGPA.log
// is 89% continuation lines, so a narrow sample can legitimately contain none
// of that file's own format.
func TestSniffSampleIsWideEnoughForASparseFile(t *testing.T) {
	if logSniffLines < 200 {
		t.Errorf("sampling %d lines is too few for a file that is mostly "+
			"continuation lines", logSniffLines)
	}
}

// The other direction has to keep working, or a firewall tech-support log
// would be handed to the GlobalProtect parser.
func TestMonitorLogIsNotMistakenForGP(t *testing.T) {
	if looksLikeGPLog(repeat(monitorLine, 50)) {
		t.Error("a monitor log was routed to the GlobalProtect parser")
	}
	mixed := append(repeat(monitorLine, 50), "some untimestamped trailer")
	if looksLikeGPLog(mixed) {
		t.Error("a monitor log with trailing noise was misrouted")
	}
}

// The rule is a comparison, so a single recognised line decides a file that is
// otherwise unrecognisable — which is the right answer, since the alternative
// parser recognises nothing in it either.
func TestOneRecognisedLineDecides(t *testing.T) {
	for name, line := range map[string]string{
		"macOS": macLine, "event": eventLine, "trace": traceLine,
	} {
		head := append(repeat(dumpLine, 300), line)
		if !looksLikeGPLog(head) {
			t.Errorf("%s format: one recognised line should decide the file", name)
		}
	}
}

func TestSniffEmptyAndBlankOnly(t *testing.T) {
	if looksLikeGPLog(nil) {
		t.Error("an empty head should not claim to be a GlobalProtect log")
	}
	if looksLikeGPLog([]string{"", "   ", "\t"}) {
		t.Error("blank lines should not decide anything")
	}
}

// The routing fix is only worth anything if the rows come out populated, so
// assert on the parsed entries rather than on the predicate alone.
func TestDumpOpeningFileKeepsItsTimestamps(t *testing.T) {
	lines := append(repeat(dumpLine, 60), repeat(macLine, 5)...)
	body := strings.Join(lines, "\n")
	_, st := StructureLogPageStats(strings.NewReader(body), time.Time{}, time.Time{}, 0, 100)
	if st.Timestamped == 0 {
		t.Fatalf("no entry carried a timestamp; the file was parsed as %d "+
			"untimestamped rows", st.FileTotal)
	}
	if st.First == "" || st.Last == "" {
		t.Error("the file span should be reported once timestamps are parsed")
	}
}
