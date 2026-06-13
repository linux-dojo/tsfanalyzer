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

// StructureLogPage returns one page of structured entries plus the total
// in-range entry count, so very large logs can be served in slices.
func StructureLogPage(r io.Reader, from, to time.Time, offset, limit int) ([]LogEntry, int) {
	all := StructureLog(r, from, to)
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
	return all[offset:end], total
}

// StructureLog converts a monitor-style log into labeled, timestamped
// entries. Every line inherits the timestamp of its enclosing "--- <proc>"
// block and a label derived from the section headers inside the block.
// from/to bounds (zero = open) filter on the inherited timestamp.
func StructureLog(r io.Reader, from, to time.Time) []LogEntry {
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

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimSpace(line)

		// new block: "<ts> -0700 --- panio"
		if m := blockHdrRe.FindStringSubmatch(trimmed); m != nil {
			if t, ok := parseTs(m[1]); ok {
				ts, haveTs = t, true
			}
			label, sub, inResource = m[2], "", false
			if inRange() {
				out = append(out, LogEntry{fmtTs(), label, line})
			}
			continue
		}

		// other logs: plain leading timestamp keeps time tracking working
		if m := leadTsRe.FindStringSubmatch(trimmed); m != nil {
			if t, ok := parseTs(m[1] + " " + m[2]); ok {
				ts, haveTs = t, true
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
		out = append(out, LogEntry{fmtTs(), lab, line})
	}
	return out
}
