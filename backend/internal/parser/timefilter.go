package parser

import (
	"bufio"
	"io"
	"regexp"
	"strings"
	"time"
)

// Timestamp formats seen in PAN-OS tech-support logs.
var (
	// 2026-06-09 10:15:02  /  2026/06/09 10:15:02  /  2026-06-09T10:15:02
	isoTsRe = regexp.MustCompile(`\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}`)
	// syslog style: "Jun  9 10:15:02" (no year)
	syslogTsRe = regexp.MustCompile(`(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2} \d{2}:\d{2}:\d{2}`)

	isoNormalizer = strings.NewReplacer("/", "-", "T", " ")
)

// extractTimestamp pulls the first recognizable timestamp out of a log line.
// refYear supplies the year for syslog-style timestamps that lack one.
func extractTimestamp(line string, refYear int) (time.Time, bool) {
	if m := isoTsRe.FindString(line); m != "" {
		if t, err := time.Parse("2006-01-02 15:04:05", isoNormalizer.Replace(m)); err == nil {
			return t, true
		}
	}
	if m := syslogTsRe.FindString(line); m != "" {
		if t, err := time.Parse("Jan _2 15:04:05", normalizeSyslogSpaces(m)); err == nil {
			return t.AddDate(refYear, 0, 0), true
		}
	}
	return time.Time{}, false
}

// normalizeSyslogSpaces collapses "Jun   9" to "Jun  9" so Go's _2 layout matches.
func normalizeSyslogSpaces(s string) string {
	for strings.Contains(s, "   ") {
		s = strings.ReplaceAll(s, "   ", "  ")
	}
	return s
}

// FilterLines copies log lines from r to w, keeping only lines whose
// timestamp falls within [from, to]. Zero bounds are open-ended. Lines
// without their own timestamp (stack traces, continuations) inherit the
// timestamp of the closest preceding timestamped line.
func FilterLines(r io.Reader, w io.Writer, from, to time.Time) error {
	refYear := from.Year()
	if refYear <= 1 {
		refYear = time.Now().UTC().Year()
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	bw := bufio.NewWriter(w)
	defer bw.Flush()

	var last time.Time
	haveTs := false

	for sc.Scan() {
		line := sc.Text()
		if t, ok := extractTimestamp(line, refYear); ok {
			last = t
			haveTs = true
		}

		keep := false
		if !haveTs {
			// content before any timestamp: keep only when no lower bound
			keep = from.IsZero()
		} else {
			keep = (from.IsZero() || !last.Before(from)) && (to.IsZero() || !last.After(to))
		}
		if keep {
			bw.WriteString(line)
			bw.WriteByte('\n')
		}
	}
	return sc.Err()
}
