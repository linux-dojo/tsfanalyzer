package parser

import (
	"bytes"
	"strings"
	"testing"
)

const searchLogA = `line one nothing here
2026/08/04 21:00:20 medium general OSPF neighbor 10.1.1.2 went down: dead timer expired
line three filler
line four filler
2026/08/04 21:05:00 high routing BGP peer 10.9.9.9 reset
line six filler
2026/08/04 21:10:00 info general everything is fine
`

const searchLogB = `unrelated file
oom-killer invoked by configd
tail line
`

func searchTgz(t *testing.T) []byte {
	t.Helper()
	return buildMultiTgz(t, map[string]string{
		"var/log/pan/alpha.log": searchLogA,
		"var/log/pan/beta.log":  searchLogB,
	})
}

func runSearch(t *testing.T, opts SearchOptions) []SearchResult {
	t.Helper()
	out, err := SearchArchive(bytes.NewReader(searchTgz(t)), opts)
	if err != nil {
		t.Fatal(err)
	}
	return out.Results
}

func lineHits(res []SearchResult) []SearchResult {
	var out []SearchResult
	for _, r := range res {
		if r.Type == "line" {
			out = append(out, r)
		}
	}
	return out
}

func TestSearchBooleanOperators(t *testing.T) {
	cases := []struct {
		q    string
		want int // number of line hits
	}{
		{"ospf", 1},
		{"ospf AND down", 1},
		{"ospf AND bgp", 0},
		{"ospf OR bgp", 2},
		{"general AND NOT ospf", 1}, // the "everything is fine" line
		{"filler", 3},
		{`"went down"`, 1},
		{`"went  down"`, 0}, // exact phrase, double space
		{"neighbou?r", 1},   // regex
		{`10\.\d+\.\d+\.\d+`, 2},
	}
	for _, c := range cases {
		got := lineHits(runSearch(t, SearchOptions{Query: c.q}))
		if len(got) != c.want {
			t.Errorf("query %q: got %d line hits, want %d", c.q, len(got), c.want)
			for _, g := range got {
				t.Logf("   %s:%d %s", g.Path, g.LineNo, g.Text)
			}
		}
	}
}

func TestSearchContextAfter(t *testing.T) {
	res := lineHits(runSearch(t, SearchOptions{Query: "ospf -A 2"}))
	if len(res) != 1 {
		t.Fatalf("got %d hits, want 1", len(res))
	}
	ctx := res[0].Context
	if len(ctx) != 2 {
		t.Fatalf("got %d context lines, want 2: %+v", len(ctx), ctx)
	}
	for _, c := range ctx {
		if c.Before {
			t.Errorf("-A should only produce trailing context: %+v", c)
		}
	}
	if !strings.Contains(ctx[0].Text, "line three") || !strings.Contains(ctx[1].Text, "line four") {
		t.Errorf("wrong trailing context: %+v", ctx)
	}
	// line numbers must follow the match
	if ctx[0].LineNo != res[0].LineNo+1 {
		t.Errorf("context line numbers not contiguous: match=%d first ctx=%d", res[0].LineNo, ctx[0].LineNo)
	}
}

func TestSearchContextBefore(t *testing.T) {
	res := lineHits(runSearch(t, SearchOptions{Query: "bgp -B 2"}))
	if len(res) != 1 {
		t.Fatalf("got %d hits, want 1", len(res))
	}
	ctx := res[0].Context
	if len(ctx) != 2 {
		t.Fatalf("got %d context lines, want 2: %+v", len(ctx), ctx)
	}
	for _, c := range ctx {
		if !c.Before {
			t.Errorf("-B should only produce leading context: %+v", c)
		}
	}
	if !strings.Contains(ctx[1].Text, "line four") {
		t.Errorf("the nearest leading line should be last: %+v", ctx)
	}
}

func TestSearchContextBoth(t *testing.T) {
	res := lineHits(runSearch(t, SearchOptions{Query: "bgp -C 1"}))
	if len(res) != 1 {
		t.Fatalf("got %d hits", len(res))
	}
	var before, after int
	for _, c := range res[0].Context {
		if c.Before {
			before++
		} else {
			after++
		}
	}
	if before != 1 || after != 1 {
		t.Errorf("-C 1 gave before=%d after=%d, want 1/1", before, after)
	}
}

// Context supplied as query parameters must work the same as inline flags.
func TestSearchContextViaOptions(t *testing.T) {
	res := lineHits(runSearch(t, SearchOptions{Query: "ospf", After: 2}))
	if len(res) != 1 || len(res[0].Context) != 2 {
		t.Fatalf("options-supplied context not applied: %+v", res)
	}
}

func TestSearchRestrictedToPaths(t *testing.T) {
	// "oom-killer" only exists in beta.log
	all := lineHits(runSearch(t, SearchOptions{Query: "oom"}))
	if len(all) != 1 {
		t.Fatalf("unrestricted: got %d hits, want 1", len(all))
	}
	// restricting to alpha.log must exclude it
	only := lineHits(runSearch(t, SearchOptions{Query: "oom", Paths: []string{"var/log/pan/alpha.log"}}))
	if len(only) != 0 {
		t.Errorf("restricted search leaked results from other files: %+v", only)
	}
	// restricting to beta.log must find it
	beta := lineHits(runSearch(t, SearchOptions{Query: "oom", Paths: []string{"var/log/pan/beta.log"}}))
	if len(beta) != 1 {
		t.Errorf("restricted search missed the hit in its own file: %+v", beta)
	}
}

// A filename match is useful for a global search but noise when the user has
// already chosen the files to look in.
func TestSearchFileNameMatchesOnlyWhenUnrestricted(t *testing.T) {
	res := runSearch(t, SearchOptions{Query: "alpha"})
	var sawFile bool
	for _, r := range res {
		if r.Type == "file" {
			sawFile = true
		}
	}
	if !sawFile {
		t.Error("a global search should report filename matches")
	}

	res = runSearch(t, SearchOptions{Query: "alpha", Paths: []string{"var/log/pan/alpha.log"}})
	for _, r := range res {
		if r.Type == "file" {
			t.Errorf("a restricted search should not report filename matches: %+v", r)
		}
	}
}

// The per-file cap must be reported, not silently applied: presenting a
// truncated count as the total is what made the result counts look arbitrary.
func TestSearchReportsCaps(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < maxLineHitsPerFile+50; i++ {
		sb.WriteString("repeated needle line\n")
	}
	tgz := buildMultiTgz(t, map[string]string{"var/log/pan/many.log": sb.String()})
	out, err := SearchArchive(bytes.NewReader(tgz), SearchOptions{Query: "needle"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.CappedFiles) != 1 || out.CappedFiles[0] != "var/log/pan/many.log" {
		t.Errorf("the capped file should be named: %+v", out.CappedFiles)
	}
	if out.Limit == 0 {
		t.Error("the limit in force should be reported")
	}
}

func TestSearchRespectsMaxResults(t *testing.T) {
	res := runSearch(t, SearchOptions{Query: "line", MaxResults: 2})
	if len(res) > 2 {
		t.Errorf("got %d results, want at most 2", len(res))
	}
}

func TestParseSearchQueryFlags(t *testing.T) {
	cases := []struct {
		q              string
		before, after  int
	}{
		{"failed -A 5", 0, 5},
		{"failed -B 3", 3, 0},
		{"failed -C 2", 2, 2},
		{"failed -B 3 -A 4", 3, 4},
		{"oom -A5", 0, 5},
		{"plain query", 0, 0},
		{"x -A 999", 0, maxContextLines}, // capped
	}
	for _, c := range cases {
		q := ParseSearchQuery(c.q)
		if q.Before != c.before || q.After != c.after {
			t.Errorf("%q: before=%d after=%d, want %d/%d", c.q, q.Before, q.After, c.before, c.after)
		}
	}
}

// The flags must be stripped from the text that is matched, or "ospf -A 5"
// would look for the literal "-A 5".
func TestParseSearchQueryStripsFlagsFromMatching(t *testing.T) {
	q := ParseSearchQuery("ospf -A 5")
	if !q.Match("OSPF neighbor down") {
		t.Error("the query should still match after the flags are removed")
	}
}

func TestParseSearchQueryDegenerateInput(t *testing.T) {
	for _, raw := range []string{
		"", "   ", "AND", "OR", "NOT", "((((", "))))", `"`, `"unclosed`,
		"a AND AND b", "&&", "!!!", "-A 5", "(a", "a)", "[invalid(regex",
	} {
		q := ParseSearchQuery(raw) // must not panic
		if !q.Empty {
			_ = q.Match("some line of text")
		}
	}
	if !ParseSearchQuery("-A 5").Empty {
		t.Error("a query of only flags should be empty rather than matching everything")
	}
	// an invalid regex must fall back to a literal match, not match nothing
	if !ParseSearchQuery("[invalid(regex").Match("x [invalid(regex y") {
		t.Error("invalid regex should degrade to a literal substring match")
	}
}

func TestSearchEmptyQueryReturnsNothing(t *testing.T) {
	res := runSearch(t, SearchOptions{Query: "   "})
	if len(res) != 0 {
		t.Errorf("an empty query should match nothing, got %+v", res)
	}
}
