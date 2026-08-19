// Package parser: gplog.go reads the two line formats a GlobalProtect agent
// collection uses, so its logs display and filter like every other log in the
// tool rather than as undifferentiated text.
//
// # The two formats
//
// The event logs (pan_gp_event.log, pan_gpa_event.log, pan_cp_events.log,
// pan_gpa_cp_event.log) are the user-facing narrative, one line per event:
//
//	08/18/2026 13:55:40:423 [Info ]: portal status is Connected.
//
// The component logs (PanGPS.log, PanGPA.log, PanGpHip.log, PanGpHipMp.log)
// are the engineering trace, carrying the process and thread that emitted the
// line and the source line number:
//
//	(P11496-T6520)Info (11298): 08/18/26 13:55:40:474 Connect method is user-logon
//
// # Why the process and thread are kept
//
// The agent is two programs that talk to each other: PanGPS, the Windows
// service that does the work, and PanGPA, the UI the user sees. PanGPA relays
// commands to and from PanGPS and renders the result. Following a connection
// therefore means following a conversation between processes, and the P/T tag
// is what makes one thread's story separable from the others — so it is kept
// at the front of the message where it can be searched and filtered.
package parser

import (
	"bufio"
	"io"
	"regexp"
	"strings"
	"time"
)

var (
	// 08/18/2026 13:55:40:423 [Info ]: message
	gpEventLineRe = regexp.MustCompile(
		`^(\d{2}/\d{2}/\d{4}) (\d{2}:\d{2}:\d{2}):(\d{3})\s*\[([A-Za-z]+)\s*\]:\s?(.*)$`)

	// (P11496-T6520)Info (11298): 08/18/26 13:55:40:474 message
	// PanGPA.log indents many of its lines by one space, so the leading
	// whitespace is optional rather than assumed away.
	gpTraceLineRe = regexp.MustCompile(
		`^\s*\(P(\d+)-T(\d+)\)([A-Za-z]+)\s*\(\s*(\d+)\):\s*(\d{2}/\d{2}/\d{2}) (\d{2}:\d{2}:\d{2}):(\d{3})\s?(.*)$`)

	// A third shape, used by the captive-portal logs (pan_cp_events.log),
	// puts the severity and timestamp before the source line and runs the
	// severity straight into the date when it is long:
	//   (P11496-T14080)info 08/18/26 09:41:41:742 (152): [CP_DETECT] ...
	//   (P11496-T14080)debug08/18/26 09:41:41:742 (152): [CP_GENERAL] ...
	// Matching the severity as letters only is what lets "debug08/18/26"
	// split correctly.
	gpCpLineRe = regexp.MustCompile(
		`^\s*\(P(\d+)-T(\d+)\)([A-Za-z]+)\s*(\d{2}/\d{2}/\d{2}) (\d{2}:\d{2}:\d{2}):(\d{3})\s*\(\s*(\d+)\):\s?(.*)$`)
)

// gpEmbeddedEntryRe finds a second entry written onto the same physical line,
// with no separator. The agent does this when two threads log at once, e.g.
//
//	…Load the SAML Browser08/19/2026 05:30:46:180 [Info ]: ShowPage - using…
//
// which would otherwise bury the second event inside the first one's message.
// It shows up around SAML authentication in particular.
var gpEmbeddedEntryRe = regexp.MustCompile(`.\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}:\d{3}\s*\[`)

// splitGPEmbedded breaks a physical line into the entries it actually holds.
func splitGPEmbedded(line string) []string {
	loc := gpEmbeddedEntryRe.FindStringIndex(line)
	if loc == nil {
		return []string{line}
	}
	// the match starts one byte early so a line that simply *begins* with a
	// timestamp is not split at position zero
	cut := loc[0] + 1
	if cut <= 0 || cut >= len(line) {
		return []string{line}
	}
	out := []string{line[:cut]}
	rest := line[cut:]
	// a line can carry more than two; recurse on what is left
	return append(out, splitGPEmbedded(rest)...)
}

// IsGPLogLine reports whether a line is in any of the GlobalProtect formats.
func IsGPLogLine(line string) bool {
	return gpEventLineRe.MatchString(line) ||
		gpTraceLineRe.MatchString(line) ||
		gpCpLineRe.MatchString(line)
}

// looksLikeGPLog decides the format of a whole file from its opening lines.
// A handful is enough: these logs are uniform, and the first line of a
// component log is often a banner rather than a timestamped entry.
func looksLikeGPLog(head []string) bool {
	checked, matched := 0, 0
	for _, l := range head {
		if strings.TrimSpace(l) == "" {
			continue
		}
		checked++
		if IsGPLogLine(l) {
			matched++
		}
		if checked >= 20 {
			break
		}
	}
	return checked > 0 && matched*2 >= checked
}

// parseGPTime builds a timestamp from the date and time parts. Both formats
// are local time with no zone, so the value is kept as written; the two-digit
// year in component logs is a 2000s year.
func parseGPTime(date, clock string) (time.Time, bool) {
	layout := "01/02/2006 15:04:05"
	if len(date) == 8 { // 08/18/26
		layout = "01/02/06 15:04:05"
	}
	t, err := time.Parse(layout, date+" "+clock)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// StructureGPLog converts a GlobalProtect log into the same labelled,
// timestamped entries the monitor logs produce, so one viewer serves both.
// A line that does not parse — a continuation, a stack dump, a blank — takes
// the timestamp of the entry above it, exactly as the monitor parser does,
// rather than being dropped.
func StructureGPLog(r io.Reader, from, to time.Time) []LogEntry {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var out []LogEntry
	// state carried across lines, so a continuation inherits the entry above it
	st := gpScanState{}

	lineNo := 0
	for sc.Scan() {
		lineNo++
		st.line = lineNo
		// One physical line can hold more than one entry; both keep the same
		// line number, since that is where a search hit would point.
		for _, line := range splitGPEmbedded(strings.TrimRight(sc.Text(), "\r")) {
			out = st.add(out, line, from, to)
		}
	}
	return out
}

// gpScanState is the running timestamp and label a continuation line inherits.
type gpScanState struct {
	cur      time.Time
	ts       string
	label    string
	haveTime bool
	line     int // the physical line currently being read
}

// inRange applies the time filter. Lines seen before any timestamp cannot be
// placed in time, so a filter excludes them; with no filter they are kept.
func (s *gpScanState) inRange(from, to time.Time) bool {
	if !s.haveTime {
		return from.IsZero() && to.IsZero()
	}
	if !from.IsZero() && s.cur.Before(from) {
		return false
	}
	if !to.IsZero() && s.cur.After(to) {
		return false
	}
	return true
}

func (s *gpScanState) stamp(date, clock, millis string) {
	if t, ok := parseGPTime(date, clock); ok {
		s.cur, s.haveTime = t, true
		s.ts = t.Format("2006-01-02 15:04:05") + "." + millis
	}
}

// add parses one logical line and appends the entry it yields, if any.
func (s *gpScanState) add(out []LogEntry, line string, from, to time.Time) []LogEntry {
	if m := gpEventLineRe.FindStringSubmatch(line); m != nil {
		s.stamp(m[1], m[2], m[3])
		s.label = strings.TrimSpace(m[4])
		if s.inRange(from, to) {
			out = append(out, LogEntry{Ts: s.ts, Label: s.label, Msg: m[5], Line: s.line})
		}
		return out
	}

	// The process/thread leads the message on both component formats: it is
	// what separates one thread's story from another's, and it stays
	// searchable. The agent is two programs talking to each other, so that
	// matters more here than in a single-process log.
	if m := gpTraceLineRe.FindStringSubmatch(line); m != nil {
		s.stamp(m[5], m[6], m[7])
		s.label = strings.TrimSpace(m[3])
		if s.inRange(from, to) {
			out = append(out, LogEntry{
				Ts: s.ts, Label: s.label, Msg: "P" + m[1] + "-T" + m[2] + " " + m[8],
				Line: s.line,
			})
		}
		return out
	}

	if m := gpCpLineRe.FindStringSubmatch(line); m != nil {
		s.stamp(m[4], m[5], m[6])
		s.label = strings.TrimSpace(m[3])
		if s.inRange(from, to) {
			out = append(out, LogEntry{
				Ts: s.ts, Label: s.label, Msg: "P" + m[1] + "-T" + m[2] + " " + m[8],
				Line: s.line,
			})
		}
		return out
	}

	if strings.TrimSpace(line) == "" {
		return out
	}
	// a continuation: keep it, under the timestamp of the entry above
	if s.inRange(from, to) {
		out = append(out, LogEntry{Ts: s.ts, Label: s.label, Msg: line, Line: s.line})
	}
	return out
}

/* ---------- one entry point for both log families ---------- */

// headLines reads up to n lines without consuming them from the caller's
// point of view, by returning a reader that replays what it read.
func headLines(r io.Reader, n int) ([]string, io.Reader) {
	br := bufio.NewReaderSize(r, 256<<10)
	var head []string
	var raw []byte
	for len(head) < n {
		line, err := br.ReadString('\n')
		if line != "" {
			raw = append(raw, line...)
			head = append(head, strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			break
		}
	}
	return head, io.MultiReader(strings.NewReader(string(raw)), br)
}
