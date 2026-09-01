package parser

import (
	"bufio"
	"io"
	"regexp"
	"strings"
	"time"
)

// LogEntry is one structured line of a monitor-style log (dp-monitor.log,
// mp-monitor.log, ...): the block timestamp, a derived section label, and
// the original line.
type LogEntry struct {
	Ts    string `json:"ts"`
	Label string `json:"label"`
	Msg   string `json:"msg"`
	// Line is the 1-based line number this entry came from in the source file.
	//
	// It is not the entry's own index: blank lines are dropped, continuation
	// lines are kept, and a GlobalProtect log can carry two entries on one
	// physical line. So an index into this slice drifts from the file's line
	// numbering, and a search hit — which reports a *file* line — cannot be
	// located by index. Carrying the line number is what lets the viewer jump
	// to and highlight the right row.
	Line int `json:"line"`
}

var (
	// "2026-06-09 11:27:40.087 -0700  --- panio"
	blockHdrRe = regexp.MustCompile(`^(\d{4}[-/]\d{2}[-/]\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?\s+[-+]\d{4}\s+---\s+(\S+)`)
	// plain leading timestamp on a line (non-monitor logs)
	leadTsRe = regexp.MustCompile(`^(\d{4}[-/]\d{2}[-/]\d{2})[ T](\d{2}:\d{2}:\d{2})`)

	cpuGroupSecRe = regexp.MustCompile(`^:CPU load sampling by group:`)
	cpuLoadSecRe  = regexp.MustCompile(`^:CPU load \(%\) during last (\d+) seconds:`)
	resourceSecRe = regexp.MustCompile(`^:Resource utilization \(%\) during last (\d+) seconds:`)
	subSectionRe  = regexp.MustCompile(`^:([A-Za-z][A-Za-z0-9 _-]*):$`)
)

// isMonitorLogLine reports whether a line carries a monitor-style timestamp:
// either a "--- <proc>" block header or a plain leading date. It is the
// counterpart to IsGPLogLine, used to decide which parser a file needs.
func isMonitorLogLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return blockHdrRe.MatchString(trimmed) || leadTsRe.MatchString(trimmed)
}

// LogPageStats describes the file as a whole, independently of any time
// filter. Without it an empty result is a dead end: "no entries" cannot
// distinguish a filter that excludes everything from a file whose timestamps
// were not understood, and both look identical on screen.
type LogPageStats struct {
	// Total is the number of entries after filtering; FileTotal is how many
	// the file holds in all.
	Total     int `json:"total"`
	FileTotal int `json:"file_total"`
	// Timestamped is how many entries carry a parsed timestamp. A file where
	// this is zero has a line format the parser does not recognise, which is
	// why a time filter would return nothing from it.
	Timestamped int `json:"timestamped"`
	// First and Last bound the timestamps actually present.
	First string `json:"first,omitempty"`
	Last  string `json:"last,omitempty"`
	// Structured marks a file of one-record-per-line JSON. Those records are
	// long and wrap over many display rows, so the viewer bands them in
	// alternating colours; without it there is no way to see where one record
	// ends and the next begins.
	Structured bool `json:"structured,omitempty"`
}

// StructureLogPage returns one page of entries in range, plus the in-range
// total. StructureLogPageStats gives the same thing with the file-wide figures.
func StructureLogPage(r io.Reader, from, to time.Time, offset, limit int) ([]LogEntry, int) {
	page, st := StructureLogPageStats(r, from, to, offset, limit)
	return page, st.Total
}

// StructureLogPageStats parses the file once without a time filter, so the
// file's real span is known, then applies the filter in memory. Parsing
// unfiltered costs nothing extra — the entries were being built in full
// either way — and it is what lets the caller say *why* a page is empty.
func StructureLogPageStats(r io.Reader, from, to time.Time, offset, limit int) ([]LogEntry, LogPageStats) {
	// A GlobalProtect agent log has its own line formats; sniffing the opening
	// lines picks the right parser without the caller needing to know which
	// kind of archive the file came out of.
	head, rest := headLines(r, logSniffLines)
	var everything []LogEntry
	if looksLikeGPLog(head) {
		everything = StructureGPLog(rest, time.Time{}, time.Time{})
	} else {
		// The year-less formats (syslog, and JSON logs whose "time" is
		// "Jul 14 01:31:52") borrow the year from elsewhere in the same file.
		everything = StructureLogYear(rest, time.Time{}, time.Time{}, looseYearHint(head))
	}

	st := LogPageStats{FileTotal: len(everything), Structured: jsonLinesLog(head)}
	for _, e := range everything {
		if e.Ts == "" {
			continue
		}
		st.Timestamped++
		if st.First == "" || e.Ts < st.First {
			st.First = e.Ts
		}
		if e.Ts > st.Last {
			st.Last = e.Ts
		}
	}

	// The display timestamp sorts lexicographically in chronological order, so
	// the filter is a string comparison — but only once the separators agree:
	// the monitor parser writes 2026/08/24 and the GlobalProtect parser
	// 2026-08-24, and comparing those raw would drop every monitor entry,
	// because '/' sorts above '-'.
	all := everything
	if !from.IsZero() || !to.IsZero() {
		lo := from.Format(logTsLayout)
		hi := to.Format(logTsLayout)
		kept := everything[:0:0]
		for _, e := range everything {
			if e.Ts == "" {
				continue // cannot be placed in time
			}
			ts := normalizeLogTs(e.Ts)
			if !from.IsZero() && ts < lo {
				continue
			}
			// The bound is exact to the second: "to = 15:15" means 15:15:00,
			// so 15:15:30 is outside it. That matches the firewall path's
			// previous behaviour, so the two kinds of log filter alike.
			if !to.IsZero() && len(ts) >= len(hi) && ts[:len(hi)] > hi {
				continue
			}
			kept = append(kept, e)
		}
		all = kept
	}
	total := len(all)
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	end := total
	if limit > 0 && offset+limit < total {
		end = offset + limit
	}
	st.Total = total
	return all[offset:end], st
}

// logTsLayout is the display timestamp format shared by both parsers. It sorts
// lexicographically in chronological order, which is what lets the time filter
// be a string comparison.
const logTsLayout = "2006-01-02 15:04:05"

// logSniffLines is how many opening lines are sampled to choose a parser.
// Twenty was far too few: a file that opens with a long dump looked like it
// had no recognisable format at all.
const logSniffLines = 400

// normalizeLogTs puts a display timestamp into logTsLayout's separator form so
// entries from either parser compare consistently.
func normalizeLogTs(ts string) string {
	if len(ts) >= 10 && ts[4] == '/' {
		return ts[:4] + "-" + ts[5:7] + "-" + ts[8:]
	}
	return ts
}

// StructureLog converts a monitor-style log into labeled, timestamped
// entries. Every line inherits the timestamp of its enclosing "--- <proc>"
// block and a label derived from the section headers inside the block.
// from/to bounds (zero = open) filter on the inherited timestamp.
// StructureLog converts a log into labelled, timestamped entries.
//
// yearHint is used only by the year-less formats parseLooseTs handles.
func StructureLog(r io.Reader, from, to time.Time) []LogEntry {
	return structureLog(r, from, to, 0, false)
}

// StructureLogYear is StructureLog with a year for the formats that omit one,
// and a flag marking a structured-record file so the viewer can band its rows.
func StructureLogYear(r io.Reader, from, to time.Time, yearHint int) []LogEntry {
	return structureLog(r, from, to, yearHint, false)
}

func structureLog(r io.Reader, from, to time.Time, yearHint int, _ bool) []LogEntry {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var (
		out        []LogEntry
		ts         time.Time
		haveTs     bool
		label, sub string
		inResource bool
	)

	parseTs := func(s string) (time.Time, bool) {
		t, err := time.Parse("2006-01-02 15:04:05", strings.ReplaceAll(s, "/", "-"))
		return t, err == nil
	}
	inRange := func() bool {
		if !haveTs {
			return from.IsZero()
		}
		return (from.IsZero() || !ts.Before(from)) && (to.IsZero() || !ts.After(to))
	}
	fmtTs := func() string {
		if !haveTs {
			return ""
		}
		return ts.Format("2006/01/02 15:04:05")
	}

	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimSpace(line)

		// new block: "<ts> -0700 --- panio"
		if m := blockHdrRe.FindStringSubmatch(trimmed); m != nil {
			if t, ok := parseTs(m[1]); ok {
				ts, haveTs = t, true
			}
			label, sub, inResource = m[2], "", false
			if inRange() {
				out = append(out, LogEntry{Ts: fmtTs(), Label: label, Msg: line, Line: lineNo})
			}
			continue
		}

		// other logs: plain leading timestamp keeps time tracking working
		if m := leadTsRe.FindStringSubmatch(trimmed); m != nil {
			if t, ok := parseTs(m[1] + " " + m[2]); ok {
				ts, haveTs = t, true
			}
		} else if t, ok := parseLooseTs(line, yearHint); ok {
			// One of the many other shapes: syslog, ctime, JSON "time", redis,
			// nginx, a fixed-width row with the timestamp on the right. 68 of
			// the 327 log files in a PA-5250 archive had no recognised
			// timestamp at all before this, which left them invisible to the
			// time filter.
			ts, haveTs = t, true
			// The hint tracks rather than latches. reboot.log alternates
			// between lines that carry a year ("Unkown reboot at Wed Mar 12
			// 08:20:21 PDT 2025") and lines that do not ("UI Initiated at Mar
			// 13 10:59:48"), and it spans March 2025 to August 2026 — so one
			// year fixed for the whole file would be wrong for most of it.
			// Each year-bearing line updates the hint the year-less ones use.
			if y := explicitYear(line); y != 0 {
				yearHint = y
			} else if yearHint == 0 {
				yearHint = t.Year()
			}
		}

		// section transitions
		switch {
		case cpuGroupSecRe.MatchString(trimmed):
			label, sub, inResource = "cpu_by_group", "", false
		case cpuLoadSecRe.MatchString(trimmed):
			label = "CPU " + cpuLoadSecRe.FindStringSubmatch(trimmed)[1] + "s"
			sub, inResource = "", false
		case resourceSecRe.MatchString(trimmed):
			label = "resource " + resourceSecRe.FindStringSubmatch(trimmed)[1] + "s"
			sub, inResource = "", true
		default:
			if inResource {
				if m := subSectionRe.FindStringSubmatch(trimmed); m != nil {
					sub = ":" + m[1]
				}
			}
		}

		if !inRange() {
			continue
		}
		lab := label
		if sub != "" {
			lab += " " + sub
		}
		out = append(out, LogEntry{Ts: fmtTs(), Label: lab, Msg: line, Line: lineNo})
	}
	return out
}
