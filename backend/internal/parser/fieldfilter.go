// Package parser: fieldfilter.go is the "| awk" half of the search language.
//
// Finding the lines is only half the job: a counter search matches thousands
// of samples when what you want is the handful above a threshold. A trailing
// pipe clause filters the lines the search found, the way piping grep into
// awk would:
//
//	pkt_recv -A 10 | $2 > 10000
//	res_swap | $2 > 1000000 AND $1 ~ userid
//	oom | $0 ~ killed
//	sessions | -F',' $3 > 500          comma-separated output
//	route | -F'\s*:\s*' $2 ~ down      any separator, as a regex
//
// Fields are counted from the *message*: the leading timestamp and
// severity/subsystem labels a PAN-OS log line carries are skipped, so on
//
//	2026/08/04 21:00:20 medium general pkt_recv 4523
//
// $1 is "pkt_recv" and $2 is "4523" — the fields you would actually compare.
// $0 is the whole line, unmodified.
//
// The filter applies to matched lines and to their -A/-B context alike, since
// that is what the pipeline it imitates does; a result is dropped only when
// none of its lines survive.
package parser

import (
	"regexp"
	"strconv"
	"strings"
)

/* ---------- deciding where the message starts ---------- */

var (
	// leading timestamps: "2026/08/04 21:00:20", "2026-08-04T21:00:20",
	// "Aug  4 21:00:20", "21:00:20"
	tsDateRe = regexp.MustCompile(`^\d{4}[-/]\d{2}[-/]\d{2}([T ]|$)`)
	tsTimeRe = regexp.MustCompile(`^\d{1,2}:\d{2}(:\d{2})?([.,]\d+)?$`)
	tsMonRe  = regexp.MustCompile(`^(?i)(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)$`)
	tsDayRe  = regexp.MustCompile(`^\d{1,2}$`)
	// the severity and subsystem words PAN-OS puts between the timestamp and
	// the message
	logLabelRe = regexp.MustCompile(`^(?i)(critical|high|medium|low|informational|info|debug|warn|warning|error|err|notice|alert|emerg)$`)
)

// lineToken is one whitespace-delimited word and where it starts, so the
// message can be located as a substring rather than only as a word list.
type lineToken struct {
	s   string
	off int
}

func splitTokens(line string) []lineToken {
	var out []lineToken
	i := 0
	for i < len(line) {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r') {
			i++
		}
		if i >= len(line) {
			break
		}
		start := i
		for i < len(line) && line[i] != ' ' && line[i] != '\t' && line[i] != '\r' {
			i++
		}
		out = append(out, lineToken{s: line[start:i], off: start})
	}
	return out
}

// messageStart returns the offset at which the message begins, skipping a
// leading timestamp and severity label. Anything it does not recognise is
// left alone, so a line that is already bare data starts at its first word.
func messageStart(line string) int {
	f := splitTokens(line)
	i := 0
	// date, or "Mon  4" syslog style
	switch {
	case i < len(f) && tsDateRe.MatchString(f[i].s):
		i++
	case i+1 < len(f) && tsMonRe.MatchString(f[i].s) && tsDayRe.MatchString(f[i+1].s):
		i += 2
	}
	// a time of day, whether or not a date preceded it
	if i < len(f) && tsTimeRe.MatchString(f[i].s) {
		i++
	}
	// at most two label words (severity, then subsystem), and only when a
	// timestamp was actually consumed — otherwise a data line starting with a
	// word like "error" would lose its first field
	if i > 0 {
		if i < len(f) && logLabelRe.MatchString(f[i].s) {
			i++
			// the subsystem word that usually follows the severity
			if i < len(f) && isBareWord(f[i].s) {
				i++
			}
		}
	}
	if i >= len(f) {
		return len(line)
	}
	return f[i].off
}

// messageFields splits a line into awk-style fields on whitespace, skipping
// the leading timestamp and severity label.
func messageFields(line string) []string {
	msg := line[messageStart(line):]
	if strings.TrimSpace(msg) == "" {
		return nil
	}
	return strings.Fields(msg)
}

// messageFieldsSep splits on an explicit separator instead of whitespace, the
// way `awk -F','` does. The timestamp and label are still skipped first, so
// the field numbers mean the same thing with or without -F; empty fields are
// preserved ("a,,b" has three), because with an explicit separator an empty
// field is data rather than noise. Each field is trimmed, since a value after
// a separator is almost always written with a space after it.
func messageFieldsSep(line string, sep *regexp.Regexp) []string {
	msg := line[messageStart(line):]
	if msg == "" {
		return nil
	}
	parts := sep.Split(msg, -1)
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// isBareWord reports whether s looks like a subsystem name rather than data:
// letters, digits, dash and underscore, with at least one letter and no digit
// leading. Numbers are never treated as labels, so a value is never eaten.
func isBareWord(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

/* ---------- the filter ---------- */

type fieldOp int

const (
	opGT fieldOp = iota
	opGE
	opLT
	opLE
	opEQ
	opNE
	opMatch    // ~
	opNotMatch // !~
)

// fieldCond is one comparison, e.g. `$2 > 10000`.
type fieldCond struct {
	field int    // 0 = whole line
	op    fieldOp
	num   float64
	isNum bool
	str   string         // lower-cased, for string comparison
	re    *regexp.Regexp // for ~ and !~
}

// FieldFilter is a conjunction/disjunction of conditions. A nil filter passes
// everything, so callers never need to special-case its absence.
type FieldFilter struct {
	// ors is a disjunction of conjunctions: (a AND b) OR (c)
	ors [][]fieldCond
	// sep is the -F separator, nil for the default whitespace split
	sep  *regexp.Regexp
	Text string // the clause as typed, for display
	Sep  string // the -F separator as typed, for display
	Bad  string // why the clause was ignored, if it was
}

// Active reports whether the filter will actually exclude anything.
func (f *FieldFilter) Active() bool { return f != nil && len(f.ors) > 0 }

// Fields splits a line the way this filter's conditions see it.
func (f *FieldFilter) Fields(line string) []string {
	if f != nil && f.sep != nil {
		return messageFieldsSep(line, f.sep)
	}
	return messageFields(line)
}

// Keep reports whether a line survives the filter.
func (f *FieldFilter) Keep(line string) bool {
	if !f.Active() {
		return true
	}
	fields := f.Fields(line)
	for _, group := range f.ors {
		all := true
		for _, c := range group {
			if !c.eval(line, fields) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func (c fieldCond) eval(line string, fields []string) bool {
	var val string
	if c.field == 0 {
		val = line
	} else if c.field <= len(fields) {
		val = fields[c.field-1]
	} else {
		return false // the field does not exist on this line
	}

	switch c.op {
	case opMatch:
		return c.re != nil && c.re.MatchString(val)
	case opNotMatch:
		return c.re != nil && !c.re.MatchString(val)
	}

	// Numeric when both sides are numbers; otherwise fall back to comparing
	// text, so `$1 == pkt_recv` works as well as `$2 > 10`.
	if c.isNum {
		n, err := parseFieldNumber(val)
		if err != nil {
			return false // a non-numeric field never passes a numeric test
		}
		switch c.op {
		case opGT:
			return n > c.num
		case opGE:
			return n >= c.num
		case opLT:
			return n < c.num
		case opLE:
			return n <= c.num
		case opEQ:
			return n == c.num
		case opNE:
			return n != c.num
		}
		return false
	}

	lv := strings.ToLower(val)
	switch c.op {
	case opEQ:
		return lv == c.str
	case opNE:
		return lv != c.str
	case opGT:
		return lv > c.str
	case opGE:
		return lv >= c.str
	case opLT:
		return lv < c.str
	case opLE:
		return lv <= c.str
	}
	return false
}

// parseFieldNumber accepts the shapes counters actually appear in: plain
// integers, decimals, and values carrying a trailing unit or punctuation
// ("4523,", "1400000kB", "85%").
func parseFieldNumber(s string) (float64, error) {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) {
		c := s[end]
		if (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+' {
			end++
			continue
		}
		break
	}
	if end == 0 {
		return 0, strconv.ErrSyntax
	}
	return strconv.ParseFloat(strings.TrimRight(s[:end], ".+-"), 64)
}

/* ---------- parsing the clause ---------- */

var fieldCondRe = regexp.MustCompile(`^\$(\d+)\s*(!~|~|>=|<=|==|!=|=|>|<)\s*(.+)$`)

// SplitFieldClause separates a query from its trailing pipe filter. The pipe
// must be followed by a `$` or by `-F`, so an unquoted `|` used as OR in the
// search part (the grammar accepts it) is not mistaken for a pipe.
func SplitFieldClause(raw string) (query string, clause string) {
	for i := len(raw) - 1; i >= 0; i-- {
		if raw[i] != '|' {
			continue
		}
		if i > 0 && raw[i-1] == '|' {
			continue // "||" is the OR operator
		}
		rest := strings.TrimSpace(raw[i+1:])
		if strings.HasPrefix(rest, "$") || strings.HasPrefix(rest, "-F") {
			return strings.TrimSpace(raw[:i]), rest
		}
	}
	return raw, ""
}

// sepFlagRe matches a leading -F separator: -F',' -F";" -F: -F'\t' -F'\s*,\s*'
var sepFlagRe = regexp.MustCompile(`^-F\s*('[^']*'|"[^"]*"|\S+)\s*`)

// parseSeparator turns an -F argument into a splitter, following awk's rule:
// a single character is literal, anything longer is a regular expression.
// A space means "runs of whitespace", as it does in awk.
func parseSeparator(arg string) (*regexp.Regexp, string, string) {
	raw := arg
	if len(arg) >= 2 && (arg[0] == '\'' || arg[0] == '"') && arg[len(arg)-1] == arg[0] {
		arg = arg[1 : len(arg)-1]
	}
	// the escapes people actually type for invisible separators
	arg = strings.NewReplacer(`\t`, "\t", `\n`, "\n", `\\`, `\`).Replace(arg)
	if arg == "" {
		return nil, "", "empty -F separator"
	}
	if arg == " " || arg == "\t" {
		return regexp.MustCompile(`\s+`), raw, "" // awk: a space means whitespace runs
	}
	if len([]rune(arg)) == 1 {
		return regexp.MustCompile(regexp.QuoteMeta(arg)), raw, ""
	}
	re, err := regexp.Compile(arg)
	if err != nil {
		// a multi-character separator that is not a valid regex is still a
		// perfectly reasonable literal, e.g. -F'::'
		return regexp.MustCompile(regexp.QuoteMeta(arg)), raw, ""
	}
	return re, raw, ""
}

// ParseFieldFilter builds a filter from a clause like `$2 > 10 AND $1 ~ user`,
// optionally preceded by an awk-style `-F','` separator.
// A clause it cannot parse is reported in Bad and otherwise ignored, so a
// half-typed filter shows everything rather than nothing.
func ParseFieldFilter(clause string) *FieldFilter {
	clause = strings.TrimSpace(clause)
	if clause == "" {
		return nil
	}
	f := &FieldFilter{Text: clause}

	if m := sepFlagRe.FindStringSubmatch(clause); m != nil {
		re, shown, err := parseSeparator(m[1])
		if err != "" {
			f.Bad = err
			return f
		}
		f.sep, f.Sep = re, shown
		clause = strings.TrimSpace(clause[len(m[0]):])
		if clause == "" {
			f.Bad = "-F given with no condition after it"
			return f
		}
	}

	for _, orPart := range splitKeyword(clause, "OR") {
		var group []fieldCond
		for _, andPart := range splitKeyword(orPart, "AND") {
			c, err := parseFieldCond(andPart)
			if err != "" {
				// A clause that cannot be parsed is not applied at all —
				// including the conditions that did parse — so a half-typed
				// filter shows everything rather than an arbitrary subset.
				f.Bad, f.ors = err, nil
				return f
			}
			group = append(group, c)
		}
		if len(group) == 0 {
			f.Bad = "empty condition"
			return f
		}
		f.ors = append(f.ors, group)
	}
	if len(f.ors) == 0 {
		f.Bad = "no conditions"
	}
	return f
}

// splitKeyword splits on a bare AND/OR word (case-insensitive), leaving the
// operands trimmed. Splitting on the word rather than a regex keeps values
// containing "and" intact.
func splitKeyword(s, kw string) []string {
	var out []string
	fields := strings.Fields(s)
	var cur []string
	for _, w := range fields {
		if strings.EqualFold(w, kw) {
			out = append(out, strings.Join(cur, " "))
			cur = nil
			continue
		}
		cur = append(cur, w)
	}
	out = append(out, strings.Join(cur, " "))
	return out
}

func parseFieldCond(s string) (fieldCond, string) {
	s = strings.TrimSpace(s)
	m := fieldCondRe.FindStringSubmatch(s)
	if m == nil {
		if s == "" {
			return fieldCond{}, "empty condition"
		}
		return fieldCond{}, "expected $N followed by > >= < <= == != ~ : " + s
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < 0 {
		return fieldCond{}, "bad field number: " + m[1]
	}
	c := fieldCond{field: n}
	switch m[2] {
	case ">":
		c.op = opGT
	case ">=":
		c.op = opGE
	case "<":
		c.op = opLT
	case "<=":
		c.op = opLE
	case "==", "=":
		c.op = opEQ
	case "!=":
		c.op = opNE
	case "~":
		c.op = opMatch
	case "!~":
		c.op = opNotMatch
	}

	rhs := strings.TrimSpace(m[3])
	rhs = strings.Trim(rhs, `"'`)
	if rhs == "" {
		return fieldCond{}, "missing value after " + m[2]
	}
	if c.op == opMatch || c.op == opNotMatch {
		re, rerr := regexp.Compile("(?i)" + rhs)
		if rerr != nil {
			return fieldCond{}, "bad regex: " + rhs
		}
		c.re = re
		return c, ""
	}
	if v, perr := parseFieldNumber(rhs); perr == nil {
		c.num, c.isNum = v, true
	} else {
		c.str = strings.ToLower(rhs)
	}
	return c, ""
}
