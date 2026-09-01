// Package parser: logtimestamps.go recognises the timestamp forms used by the
// logs that are neither monitor blocks nor GlobalProtect agent lines.
//
// A survey of a PA-5250 archive found 68 of its 327 log files with no
// recognised timestamp on any line, which meant the time filter matched
// nothing in them and the viewer showed a blank Timestamp column. They are not
// 68 different formats — they are about ten, repeated:
//
//	syslog       Jul 14 01:26:26 INFO: ZRAM mem_limit ...
//	ctime        Tue Jul 14 01:26:27 PDT 2026
//	json         {"level":"info","time":"2026-07-14T01:26:40.961-07:00", ...}
//	redis        7400:C 14 Jul 2026 01:26:28.215 # Redis is starting
//	us-date      07/14/26 01:25:25 fips  INFO: ...
//	bracket-iso  [2026/07/14 02:02:39]   /   00106647 [2026-08-04 15:07:36.0305]
//	clf          ... [14/Jul/2026:01:30:33 -0700] "GET /"
//	php          [14-Jul-2026 08:26:59 UTC] PHP Warning: ...
//	colon-iso    2026:07:14T01:26:41.077-07:00 [9684-9684] main ikemgr started
//	right-col    bootstrap panlogs ... Success  12/11/25 18:58:42
//
// Two of these need explaining. The last puts its timestamp at the *end* of a
// fixed-width row (panrepo/logs/history.log), so nothing anchored at the start
// of the line will ever find it. And several carry no year at all, which is
// why parseLooseTs takes the year from context rather than guessing: a syslog
// line in a December archive read as the current year lands twelve months out.
package parser

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// "Jul 14 01:26:26" and "Aug  6 22:01:53.380" — no year.
	tsSyslogRe = regexp.MustCompile(
		`^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\b`)

	// "Tue Jul 14 01:26:27 PDT 2026" — the year is present, at the end.
	tsCtimeRe = regexp.MustCompile(
		`^[A-Z][a-z]{2},?\s+(?:(\d{1,2})\s+([A-Z][a-z]{2})|([A-Z][a-z]{2})\s+(\d{1,2}))\s+` +
			`(\d{2}):(\d{2}):(\d{2})(?:\s+[A-Z]{2,5})?\s+(\d{4})`)

	// A structured line: {"level":"info","time":"...", ...}. The time itself is
	// then one of the forms below, so it is pulled out and re-parsed.
	tsJSONRe = regexp.MustCompile(`"time"\s*:\s*"([^"]+)"`)

	// "7400:C 14 Jul 2026 01:26:28.215 #"
	tsRedisRe = regexp.MustCompile(
		`^\d+:[A-Z] (\d{1,2}) ([A-Z][a-z]{2}) (\d{4}) (\d{2}):(\d{2}):(\d{2})`)

	// "07/14/26 01:25:25" or "12/11/25 18:58:28" at the start of a line.
	tsUSDateRe = regexp.MustCompile(
		`^(\d{2})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})`)

	// "[2026/07/14 02:02:39]" and "00106647 [2026-08-04 15:07:36.0305]"
	tsBracketISORe = regexp.MustCompile(
		`\[(\d{4})[-/](\d{2})[-/](\d{2}) (\d{2}):(\d{2}):(\d{2})`)

	// nginx/Apache common log: "[14/Jul/2026:01:30:33 -0700]"
	tsCLFRe = regexp.MustCompile(
		`\[(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})`)

	// PHP: "[14-Jul-2026 08:26:59 UTC]"
	tsPHPRe = regexp.MustCompile(
		`\[(\d{2})-([A-Z][a-z]{2})-(\d{4}) (\d{2}):(\d{2}):(\d{2})`)

	// "2026:07:14T01:26:41.077-07:00" — ISO with colons for the date.
	tsColonISORe = regexp.MustCompile(
		`^(\d{4}):(\d{2}):(\d{2})T(\d{2}):(\d{2}):(\d{2})`)

	// RFC3339, as JSON logs and a few others write it.
	tsRFC3339Re = regexp.MustCompile(
		`^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})`)

	// A fixed-width row whose timestamp is the last thing on it:
	//   bootstrap panlogs logs panos-11.1.6-h17    Success  12/11/25 18:58:42
	tsTrailingRe = regexp.MustCompile(
		`(\d{2})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})\s*$`)

	// audit.log: "msg=audit(1784017521.553:6107):" — epoch seconds.
	tsAuditRe = regexp.MustCompile(`\baudit\((\d{9,11})(?:\.\d+)?:\d+\)`)

	// The three below are unanchored and so are tried last, after every
	// anchored pattern has declined the line. An unanchored date will happily
	// match one quoted inside a message body, so it must never get first look.

	// wildfire-monitor.log's banner: "===== 2026-07-14 01:47:26 -0700 ====="
	tsISOAnywhereRe = regexp.MustCompile(
		`(?:^|[^\d])(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})`)

	// reboot.log: "[Unkown reboot at Wed Mar 12 08:20:21 PDT 2025]" — a ctime
	// inside the reason rather than at the start of the line.
	tsCtimeAnywhereRe = regexp.MustCompile(
		`(?:[A-Z][a-z]{2} )?([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})` +
			`(?: [A-Z]{2,5})? (\d{4})`)

	// reboot.log's other spelling: "[UI Initiated at Mar 13 10:59:48]" — no
	// year at all, so it depends on the running year hint.
	tsMonthDayAnywhereRe = regexp.MustCompile(
		`\b([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})\b`)

	months = map[string]int{
		"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
		"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
	}
)

func monthNum(s string) int { return months[strings.ToLower(s)] }

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// mk builds a timestamp, rejecting nonsense rather than letting time.Date
// silently normalise "month 0" into the previous December.
func mk(y, mo, d, h, mi, s int) (time.Time, bool) {
	if mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60 {
		return time.Time{}, false
	}
	return time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC), true
}

// parseLooseTs finds a timestamp in a line that none of the primary patterns
// matched.
//
// yearHint supplies the year for the formats that omit it. It is the year of
// the last fully-specified timestamp seen in the same file, so a December
// archive read in January does not shift a whole file by twelve months. When
// there is no hint and the format carries no year, the line stays unstamped:
// a wrong timestamp is worse than none, because it silently moves lines in and
// out of a time filter.
func parseLooseTs(line string, yearHint int) (time.Time, bool) {
	// A structured line carries its timestamp in a field; unwrap and recurse
	// once on the value.
	if m := tsJSONRe.FindStringSubmatch(line); m != nil {
		if t, ok := parseLooseTs(m[1], yearHint); ok {
			return t, true
		}
		if t, ok := parseBareTs(m[1], yearHint); ok {
			return t, true
		}
	}
	return parseBareTs(line, yearHint)
}

func parseBareTs(line string, yearHint int) (time.Time, bool) {
	if m := tsRFC3339Re.FindStringSubmatch(line); m != nil {
		return mk(atoiOr(m[1], 0), atoiOr(m[2], 0), atoiOr(m[3], 0),
			atoiOr(m[4], 0), atoiOr(m[5], 0), atoiOr(m[6], 0))
	}
	if m := tsColonISORe.FindStringSubmatch(line); m != nil {
		return mk(atoiOr(m[1], 0), atoiOr(m[2], 0), atoiOr(m[3], 0),
			atoiOr(m[4], 0), atoiOr(m[5], 0), atoiOr(m[6], 0))
	}
	if m := tsCtimeRe.FindStringSubmatch(line); m != nil {
		day, mon := m[1], m[2]
		if day == "" {
			day, mon = m[4], m[3]
		}
		return mk(atoiOr(m[7], 0), monthNum(mon), atoiOr(day, 0),
			atoiOr(m[5], 0), atoiOr(m[6], 0), 0)
	}
	if m := tsRedisRe.FindStringSubmatch(line); m != nil {
		return mk(atoiOr(m[3], 0), monthNum(m[2]), atoiOr(m[1], 0),
			atoiOr(m[4], 0), atoiOr(m[5], 0), atoiOr(m[6], 0))
	}
	if m := tsCLFRe.FindStringSubmatch(line); m != nil {
		return mk(atoiOr(m[3], 0), monthNum(m[2]), atoiOr(m[1], 0),
			atoiOr(m[4], 0), atoiOr(m[5], 0), atoiOr(m[6], 0))
	}
	if m := tsPHPRe.FindStringSubmatch(line); m != nil {
		return mk(atoiOr(m[3], 0), monthNum(m[2]), atoiOr(m[1], 0),
			atoiOr(m[4], 0), atoiOr(m[5], 0), atoiOr(m[6], 0))
	}
	if m := tsBracketISORe.FindStringSubmatch(line); m != nil {
		return mk(atoiOr(m[1], 0), atoiOr(m[2], 0), atoiOr(m[3], 0),
			atoiOr(m[4], 0), atoiOr(m[5], 0), atoiOr(m[6], 0))
	}
	if m := tsUSDateRe.FindStringSubmatch(line); m != nil {
		return mk(2000+atoiOr(m[3], 0), atoiOr(m[1], 0), atoiOr(m[2], 0),
			atoiOr(m[4], 0), atoiOr(m[5], 0), atoiOr(m[6], 0))
	}
	// The trailing form is tried before the year-less ones: a fixed-width row
	// can easily contain something that looks like a bare month elsewhere.
	if m := tsTrailingRe.FindStringSubmatch(line); m != nil {
		return mk(2000+atoiOr(m[3], 0), atoiOr(m[1], 0), atoiOr(m[2], 0),
			atoiOr(m[4], 0), atoiOr(m[5], 0), atoiOr(m[6], 0))
	}
	if m := tsSyslogRe.FindStringSubmatch(line); m != nil {
		if yearHint == 0 {
			return time.Time{}, false // no year anywhere: better unstamped
		}
		return mk(yearHint, monthNum(m[1]), atoiOr(m[2], 0),
			atoiOr(m[3], 0), atoiOr(m[4], 0), atoiOr(m[5], 0))
	}

	// audit.log wraps the time in its record id: the value is epoch seconds
	// with milliseconds, followed by a colon and a sequence number.
	//
	//	type=DAEMON_START msg=audit(1784017521.553:6107): op=start ver=3.0
	if m := tsAuditRe.FindStringSubmatch(line); m != nil {
		if sec, err := strconv.ParseInt(m[1], 10, 64); err == nil &&
			sec > 946684800 && sec < 4102444800 { // 2000-01-01 .. 2100-01-01
			return time.Unix(sec, 0).UTC(), true
		}
	}

	// The unanchored forms come last, because they will happily find a date in
	// the middle of a message body. Reaching here means every anchored pattern
	// has already declined the line.
	//
	// wildfire-monitor.log delimits its samples with a banner rather than
	// stamping each line:
	//
	//	============================== 2026-07-14 01:47:26 -0700 =========
	//
	// Once the banner is read the lines beneath it inherit that time, which is
	// the same block-and-inherit model the monitor logs already use.
	if m := tsISOAnywhereRe.FindStringSubmatch(line); m != nil {
		return mk(atoiOr(m[1], 0), atoiOr(m[2], 0), atoiOr(m[3], 0),
			atoiOr(m[4], 0), atoiOr(m[5], 0), atoiOr(m[6], 0))
	}

	// reboot.log keeps its date inside the reason, in two spellings:
	//
	//	SYSTEM REBOOT [Unkown reboot at Wed Mar 12 08:20:21 PDT 2025]
	//	SYSTEM REBOOT [UI Initiated at Mar 13 10:59:48]
	//
	// The first carries a year; the second does not, which is why the caller
	// keeps a running year rather than one per file. reboot.log spans years —
	// the sample archive runs from March 2025 to August 2026 — so a single
	// file-wide year would be wrong for most of it.
	if m := tsCtimeAnywhereRe.FindStringSubmatch(line); m != nil {
		return mk(atoiOr(m[6], 0), monthNum(m[1]), atoiOr(m[2], 0),
			atoiOr(m[3], 0), atoiOr(m[4], 0), atoiOr(m[5], 0))
	}
	if m := tsMonthDayAnywhereRe.FindStringSubmatch(line); m != nil {
		if yearHint == 0 {
			return time.Time{}, false
		}
		return mk(yearHint, monthNum(m[1]), atoiOr(m[2], 0),
			atoiOr(m[3], 0), atoiOr(m[4], 0), atoiOr(m[5], 0))
	}
	return time.Time{}, false
}

// yearAnywhereRe finds a four-digit year next to a clock anywhere in a line,
// not only at the start of one.
//
// Several syslog-format files open with a banner that does carry the year —
//
//	Jul 14 01:26:23 DEBUG: +++++++ Tue Jul 14 01:26:23 2026 +++++++
//
// but the anchored patterns cannot see it, because the line begins with the
// year-less form. Reading the year from the middle of the line is what lets
// the rest of that file be placed in time at all.
var yearAnywhereRe = regexp.MustCompile(`\b(20\d{2})\b`)

// explicitYear returns the four-digit year a line states outright, or 0 when
// it states none. It is what lets the running hint follow a log that spans
// more than one year instead of pinning the whole file to its first.
func explicitYear(line string) int {
	m := yearAnywhereRe.FindStringSubmatch(line)
	if m == nil {
		return 0
	}
	y, err := strconv.Atoi(m[1])
	if err != nil || y < 2000 || y > 2100 {
		return 0
	}
	return y
}

// looseYearHint scans the head of a file for a year, so the year-less formats
// in the same file can borrow it.
func looseYearHint(head []string) int {
	for _, l := range head {
		if t, ok := parseBareTs(l, 0); ok && t.Year() > 1990 {
			return t.Year()
		}
		// a year sitting mid-line, next to a clock
		if strings.Contains(l, ":") {
			if m := yearAnywhereRe.FindStringSubmatch(l); m != nil {
				if y, err := strconv.Atoi(m[1]); err == nil && y >= 2000 && y <= 2100 {
					return y
				}
			}
		}
	}
	return 0
}

// jsonLinesLog reports whether a file is a stream of structured records, which
// the viewer renders with alternating row shading: one record can wrap over
// many rows and without the banding it is impossible to see where one ends.
func jsonLinesLog(head []string) bool {
	checked, hits := 0, 0
	for _, l := range head {
		s := strings.TrimSpace(l)
		if s == "" {
			continue
		}
		checked++
		if strings.HasPrefix(s, "{") && strings.Contains(s, `"time"`) {
			hits++
		}
		if checked >= 40 {
			break
		}
	}
	return checked > 0 && hits*2 >= checked
}
