package parser

import (
	"bytes"
	"strings"
	"testing"
)

func TestMessageFieldsSkipsTimestampAndLabel(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		// PAN-OS system log: date, time, severity, subsystem, then the message
		{"2026/08/04 21:00:20 medium general pkt_recv 4523",
			[]string{"pkt_recv", "4523"}},
		{"2026-08-04T21:00:20 high routing BGP peer down",
			[]string{"BGP", "peer", "down"}},
		// syslog style: "Aug  4 21:00:20"
		{"Aug  4 21:00:20 critical general oom killed reportd",
			[]string{"oom", "killed", "reportd"}},
		// a bare counter line, which is what dp-monitor.log looks like
		{"pkt_recv                4523", []string{"pkt_recv", "4523"}},
		// time only, no date. "mp" is not a severity word, so nothing after
		// the timestamp is skipped — only known severities are treated as
		// labels, because guessing would eat real data.
		{"21:00:20 mp process useridd 1400000",
			[]string{"mp", "process", "useridd", "1400000"}},
		// a line whose first word looks like a severity but has no timestamp
		// in front of it: nothing may be eaten
		{"error count 12", []string{"error", "count", "12"}},
		// a number after the timestamp is data, never a label
		{"2026/08/04 21:00:20 4523 6789", []string{"4523", "6789"}},
		{"", nil},
		{"   ", nil},
	}
	for _, c := range cases {
		got := messageFields(c.line)
		if len(got) != len(c.want) {
			t.Errorf("%q: got %v, want %v", c.line, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q: field %d = %q, want %q", c.line, i+1, got[i], c.want[i])
			}
		}
	}
}

func TestFieldFilterComparisons(t *testing.T) {
	line := "2026/08/04 21:00:20 medium general pkt_recv 4523"
	cases := []struct {
		clause string
		want   bool
	}{
		{"$2 > 10", true},
		{"$2 > 10000", false},
		{"$2 >= 4523", true},
		{"$2 <= 4523", true},
		{"$2 < 4523", false},
		{"$2 == 4523", true},
		{"$2 != 4523", false},
		{"$1 == pkt_recv", true},
		{"$1 == PKT_RECV", true}, // string comparison is case-insensitive
		{"$1 != pkt_sent", true},
		{"$1 ~ recv", true},
		{"$1 ~ ^pkt", true},
		{"$1 !~ sent", true},
		{"$0 ~ medium", true},   // $0 is the whole line, labels included
		{"$1 > 10", false},      // a non-numeric field fails a numeric test
		{"$9 > 1", false},       // a field that does not exist fails
		{"$2 > 10 AND $1 ~ pkt", true},
		{"$2 > 10 AND $1 ~ sent", false},
		{"$2 > 99999 OR $1 ~ pkt", true},
		{"$2 > 99999 OR $1 ~ sent", false},
	}
	for _, c := range cases {
		f := ParseFieldFilter(c.clause)
		if f.Bad != "" {
			t.Errorf("%q: unexpected parse error %q", c.clause, f.Bad)
			continue
		}
		if got := f.Keep(line); got != c.want {
			t.Errorf("%q on %q: got %v, want %v", c.clause, line, got, c.want)
		}
	}
}

// Values in real logs carry units and punctuation; a threshold must still
// work on them rather than silently rejecting every line.
func TestFieldFilterNumberShapes(t *testing.T) {
	cases := []struct {
		field  string
		clause string
		want   bool
	}{
		{"4523", "$1 > 100", true},
		{"4523,", "$1 > 100", true},
		{"1400000kB", "$1 > 1000000", true},
		{"85%", "$1 > 80", true},
		{"12.5", "$1 > 12", true},
		{"-3", "$1 < 0", true},
		{"n/a", "$1 > 0", false},
		{"", "$1 > 0", false},
	}
	for _, c := range cases {
		f := ParseFieldFilter(c.clause)
		if got := f.Keep(c.field); got != c.want {
			t.Errorf("field %q with %q: got %v, want %v", c.field, c.clause, got, c.want)
		}
	}
}

// awk's -F: the separator changes what a field is, but not where the message
// starts, so $N means the same thing with or without it.
func TestFieldFilterSeparator(t *testing.T) {
	cases := []struct {
		line   string
		clause string
		want   bool
	}{
		// comma-separated values
		{"a,25000,c", "-F',' $2 > 10000", true},
		{"a,25000,c", "-F',' $2 > 99999", false},
		{"a, 25000 ,c", "-F',' $2 > 10000", true}, // fields are trimmed
		{"a,25000,c", "-F, $2 > 10000", true},     // unquoted separator
		{`a,25000,c`, `-F"," $2 > 10000`, true},   // double quotes
		// the timestamp and label are still skipped first
		{"2026/08/04 21:00:20 medium general a,25000,c", "-F',' $2 > 10000", true},
		{"2026/08/04 21:00:20 medium general a,25000,c", "-F',' $1 == a", true},
		// other separators
		{"a;25000;c", "-F';' $2 > 10000", true},
		{"a:25000:c", "-F: $2 > 10000", true},
		{"a\t25000\tc", `-F'\t' $2 > 10000`, true},
		// longer than one character is a regex
		{"a  :  25000  :  c", `-F'\s*:\s*' $2 > 10000`, true},
		{"a::25000::c", "-F'::' $2 > 10000", true},
		// empty fields are preserved with an explicit separator, so the field
		// numbers after a gap do not shift
		{"a,,25000", `-F',' $2 ~ ^$`, true},
		{"a,,25000", "-F',' $3 > 10000", true},
		// without -F a comma-separated line is one field
		{"a,25000,c", "$2 > 10000", false},
		{"a,25000,c", "$1 ~ 25000", true},
	}
	for _, c := range cases {
		f := ParseFieldFilter(c.clause)
		if f.Bad != "" {
			t.Errorf("%q: unexpected parse error %q", c.clause, f.Bad)
			continue
		}
		if got := f.Keep(c.line); got != c.want {
			t.Errorf("%q on %q: got %v, want %v (fields=%q)",
				c.clause, c.line, got, c.want, f.Fields(c.line))
		}
	}
}

func TestFieldFilterSeparatorErrors(t *testing.T) {
	for _, clause := range []string{"-F", "-F''", `-F""`, "-F',' ", "-F',' garbage"} {
		f := ParseFieldFilter(clause)
		if f.Bad == "" {
			t.Errorf("%q: expected a parse error", clause)
		}
		if f.Active() {
			t.Errorf("%q: a bad clause must not filter anything", clause)
		}
	}
}

func TestSplitFieldClauseWithSeparator(t *testing.T) {
	cases := []struct{ raw, query, clause string }{
		{"sessions | -F',' $3 > 500", "sessions", "-F',' $3 > 500"},
		{"sessions -A 5 | -F: $2 ~ down", "sessions -A 5", "-F: $2 ~ down"},
		// a pipe followed by neither $ nor -F is still the OR operator
		{"a | b", "a | b", ""},
	}
	for _, c := range cases {
		q, cl := SplitFieldClause(c.raw)
		if q != c.query || cl != c.clause {
			t.Errorf("%q: got (%q, %q), want (%q, %q)", c.raw, q, cl, c.query, c.clause)
		}
	}
}

func TestSplitFieldClause(t *testing.T) {
	cases := []struct{ raw, query, clause string }{
		{"pkt_recv | $2 > 10", "pkt_recv", "$2 > 10"},
		{"pkt_recv -A 10 | $2 > 10000", "pkt_recv -A 10", "$2 > 10000"},
		{"pkt_recv", "pkt_recv", ""},
		// a bare | is the OR operator in the search grammar, not a pipe
		{"ospf|bgp", "ospf|bgp", ""},
		{"ospf || bgp", "ospf || bgp", ""},
		// only the last pipe-into-$ counts
		{"a|b | $1 > 2", "a|b", "$1 > 2"},
		{"$notafield", "$notafield", ""},
	}
	for _, c := range cases {
		q, cl := SplitFieldClause(c.raw)
		if q != c.query || cl != c.clause {
			t.Errorf("%q: got (%q, %q), want (%q, %q)", c.raw, q, cl, c.query, c.clause)
		}
	}
}

// A clause that cannot be parsed must not be applied at all — not even the
// part of it that did parse — or the user would see an arbitrary subset with
// no indication why.
func TestFieldFilterBadClauseIsInert(t *testing.T) {
	for _, clause := range []string{
		"$2 >", "$ > 10", "2 > 10", "$2 10", "$2 ~ [unclosed", "$2 > 10 AND garbage",
	} {
		f := ParseFieldFilter(clause)
		if f.Bad == "" {
			t.Errorf("%q: expected a parse error", clause)
		}
		if f.Active() {
			t.Errorf("%q: a bad clause must not filter anything", clause)
		}
		if !f.Keep("anything at all 5") {
			t.Errorf("%q: a bad clause must keep every line", clause)
		}
	}
	// a nil filter (no clause at all) keeps everything too
	var nilF *FieldFilter
	if !nilF.Keep("x") || nilF.Active() {
		t.Error("a nil filter must be inert")
	}
}

/* ---------- the filter inside a search ---------- */

const filterLog = `--- pkt_recv counters ---
rx_packets 5
rx_bytes 25000
rx_errors 0
--- pkt_sent counters ---
tx_packets 900000
`

func TestSearchWithFieldFilterOnMatchedLines(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{"var/log/pan/c.log": filterLog})
	out, err := SearchArchive(bytes.NewReader(tgz), SearchOptions{Query: "packets | $2 > 100"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 {
		t.Fatalf("got %d results, want just tx_packets: %+v", len(out.Results), out.Results)
	}
	if !strings.Contains(out.Results[0].Text, "tx_packets") {
		t.Errorf("wrong line survived: %q", out.Results[0].Text)
	}
	if out.Filter != "$2 > 100" {
		t.Errorf("the clause should be echoed, got %q", out.Filter)
	}
}

// The case the feature exists for: the matched line is a section header with
// no value of its own, and the values are in the -A context.
func TestSearchFieldFilterKeepsAnchorForSurvivingContext(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{"var/log/pan/c.log": filterLog})
	out, err := SearchArchive(bytes.NewReader(tgz),
		SearchOptions{Query: `"pkt_recv counters" -A 3 | $2 > 10`})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(out.Results), out.Results)
	}
	r := out.Results[0]
	if !r.Filtered {
		t.Error("the header line has no $2, so it should be marked as filtered")
	}
	// rx_packets 5 and rx_errors 0 fail; rx_bytes 25000 passes
	if len(r.Context) != 1 || !strings.Contains(r.Context[0].Text, "rx_bytes") {
		t.Errorf("context should be only rx_bytes: %+v", r.Context)
	}
}

// When nothing in a block survives, the block disappears entirely.
func TestSearchFieldFilterDropsBlockWhenNothingSurvives(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{"var/log/pan/c.log": filterLog})
	out, err := SearchArchive(bytes.NewReader(tgz),
		SearchOptions{Query: `"pkt_recv counters" -A 3 | $2 > 999999999`})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range out.Results {
		if r.Type == "line" {
			t.Errorf("nothing should have survived, got %+v", r)
		}
	}
}

// The -A window is n lines, not n surviving lines: the countdown must run
// over filtered-out lines too, exactly as `grep -A n | awk` behaves.
func TestSearchFieldFilterContextWindowCountsFilteredLines(t *testing.T) {
	log := "header here\nv 1\nv 2\nv 500\nv 600\n"
	tgz := buildMultiTgz(t, map[string]string{"var/log/pan/w.log": log})
	out, err := SearchArchive(bytes.NewReader(tgz),
		SearchOptions{Query: "header -A 2 | $2 > 100"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 0 {
		// "v 1" and "v 2" are the two lines in the window and both fail, so
		// the block has nothing left; "v 500" is outside the window
		t.Errorf("the window must not slide past filtered lines: %+v", out.Results)
	}
}

// The field filter must never narrow which *files* are searched: a file is
// excluded only by what the search terms require.
func TestFieldFilterDoesNotAffectTrigramPlan(t *testing.T) {
	a := ParseSearchQuery("pkt_recv")
	b := ParseSearchQuery("pkt_recv | $2 > 10")
	if a.Tri.gate() != b.Tri.gate() {
		t.Errorf("the filter changed the trigram gate: %q vs %q", a.Tri.gate(), b.Tri.gate())
	}
	if b.Filter == nil || !b.Filter.Active() {
		t.Error("the filter clause should have been parsed off the query")
	}
	if a.Filter != nil && a.Filter.Active() {
		t.Error("a query with no clause should have no filter")
	}
}
