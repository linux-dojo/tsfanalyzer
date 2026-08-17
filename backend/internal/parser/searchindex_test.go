package parser

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The index is only allowed to make search faster, never to change what it
// finds. Every test here is ultimately that one assertion: the indexed result
// set equals the result set of a full, unindexed scan.

// buildIndexedCorpus makes an archive with enough files, and enough repetition
// between them, that the trigram filter has real work to do: a term in one
// file must not drag in the others.
func buildIndexedCorpus(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}

	var mp strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&mp, "2026/08/04 21:%02d:00 mp counter pkt_recv %d pkt_sent %d\n", i%60, i*7, i*3)
		fmt.Fprintf(&mp, "2026/08/04 21:%02d:01 mp process useridd res_swap %d\n", i%60, 700000+i*900)
	}
	files["var/log/pan/mp-monitor.log"] = mp.String()

	var dp strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&dp, "2026/08/04 22:%02d:00 dp session-table entries %d\n", i%60, i*11)
		fmt.Fprintf(&dp, "2026/08/04 22:%02d:30 dp PKT_RECV upper case %d\n", i%60, i)
	}
	files["var/log/pan/dp-monitor.log"] = dp.String()

	files["tmp/cli/logs/show_log_system.txt"] = strings.Repeat(
		"2026/08/04 21:00:20 medium general OSPF neighbor 10.1.1.2 went down: dead timer expired\n"+
			"2026/08/04 21:00:25 info general Successfully connect to address 10.0.0.1\n", 40) +
		"2026/08/04 21:10:00 high routing BGP peer 10.9.9.9 reset by neighbour\n" +
		"2026/08/04 21:11:00 critical general kernel: Out of memory: Killed process 1234 (reportd)\n"

	files["var/log/pan/ms.log"] = "nothing interesting in here at all\njust filler text\n"
	files["opt/pancfg/mgmt/mergesp.xml"] = `<config version="10.2.0"><shared/></config>` + "\n"

	// unique needles, one per file, to prove the filter selects the right one
	files["var/log/pan/uniq-alpha.log"] = "alpha zzqqxx-alpha-needle here\n"
	files["var/log/pan/uniq-beta.log"] = "beta zzqqxx-beta-needle here\n"

	for i := 0; i < 12; i++ {
		files[fmt.Sprintf("var/log/pan/bulk-%02d.log", i)] =
			strings.Repeat("routine housekeeping line with common words\n", 30)
	}
	return files
}

// key identifies a result independently of the order results arrived in.
func resultKeys(res []SearchResult) []string {
	out := make([]string, 0, len(res))
	for _, r := range res {
		var ctx []string
		for _, c := range r.Context {
			pos := "after"
			if c.Before {
				pos = "before"
			}
			ctx = append(ctx, fmt.Sprintf("%s:%d:%s", pos, c.LineNo, c.Text))
		}
		out = append(out, fmt.Sprintf("%s|%s|%d|%s|%s",
			r.Type, r.Path, r.LineNo, r.Text, strings.Join(ctx, ";")))
	}
	sort.Strings(out)
	return out
}

// The queries below deliberately cover every construct the planner reasons
// about, and several it must refuse to reason about.
var equivalenceQueries = []SearchOptions{
	{Query: "pkt_recv"},                    // plain literal, two files, mixed case
	{Query: "PKT_RECV"},                    // same, typed in the other case
	{Query: "zzqqxx-alpha-needle"},         // unique to one file
	{Query: "zzqqxx"},                      // shared prefix of two needles
	{Query: "no-such-string-anywhere"},     // matches nothing at all
	{Query: "ospf AND down"},               // implicit and explicit AND
	{Query: "ospf AND pkt_recv"},           // terms that never share a file
	{Query: "ospf OR pkt_recv"},            // alternatives in different files
	{Query: "general AND NOT ospf"},        // NOT: no constraint derivable
	{Query: "NOT ospf"},                    // NOT alone
	{Query: `"went down"`},                 // quoted phrase
	{Query: `"went  down"`},                // phrase that must not match
	{Query: "neighbou?r"},                  // optional character
	{Query: "oom|Out of memory"},           // alternation
	{Query: `10\.\d+\.\d+\.\d+`},           // escapes and classes
	{Query: "res_swap.*9"},                 // literal then wildcard
	{Query: ".*"},                          // matches every line
	{Query: "[0-9]+"},                      // pure character class: no trigram
	{Query: "reportd -A 2"},                // trailing context
	{Query: "BGP -B 3"},                    // leading context
	{Query: "OSPF -C 1"},                   // both
	{Query: "monitor"},                     // matches filenames as well as lines
	{Query: "bulk"},                        // filename-only match
	{Query: "(ospf OR bgp) AND general"},   // grouping
	{Query: "housekeeping", MaxResults: 7}, // cap engaged
	{Query: "entries", Paths: []string{"var/log/pan/dp-monitor.log"}},
	{Query: "pkt_recv", Paths: []string{"var/log/pan/mp-monitor.log", "var/log/pan/ms.log"}},
	{Query: "alpha", Paths: []string{"var/log/pan/uniq-beta.log"}}, // scoped away
}

func TestIndexedSearchMatchesFullScan(t *testing.T) {
	corpus := buildIndexedCorpus(t)
	tgz := buildMultiTgz(t, corpus)
	blob := filepath.Join(t.TempDir(), "corpus.sblob")

	idx, err := BuildSearchIndex(bytes.NewReader(tgz), blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Entries) != len(corpus) {
		t.Fatalf("listed %d files, archive has %d", len(idx.Entries), len(corpus))
	}
	if len(idx.Files) != len(corpus) {
		t.Fatalf("indexed %d files, archive has %d", len(idx.Files), len(corpus))
	}
	if idx.BlobBytes == 0 || idx.Trigrams == 0 {
		t.Fatalf("index looks empty: %d bytes, %d trigrams", idx.BlobBytes, idx.Trigrams)
	}

	for _, opts := range equivalenceQueries {
		// a high cap by default, so the caps themselves don't mask a difference
		o := opts
		if o.MaxResults == 0 {
			o.MaxResults = 5000
		}

		want, err := SearchArchive(bytes.NewReader(tgz), o)
		if err != nil {
			t.Fatalf("%q: full scan: %v", o.Query, err)
		}
		got, err := SearchIndexed(context.Background(), idx, bytes.NewReader(tgz), o)
		if err != nil {
			t.Fatalf("%q: indexed: %v", o.Query, err)
		}

		wk, gk := resultKeys(want.Results), resultKeys(got.Results)
		if len(wk) != len(gk) {
			t.Errorf("query %q: indexed found %d results, full scan found %d",
				o.Query, len(gk), len(wk))
			t.Logf("  candidates=%d scanned=%d of %d files",
				got.Candidates, got.Scanned, len(idx.Files))
			for _, missing := range diffKeys(wk, gk) {
				t.Logf("  MISSED: %s", missing)
			}
			for _, extra := range diffKeys(gk, wk) {
				t.Logf("  EXTRA:  %s", extra)
			}
			continue
		}
		for i := range wk {
			if wk[i] != gk[i] {
				t.Errorf("query %q: result %d differs\n  full:    %s\n  indexed: %s",
					o.Query, i, wk[i], gk[i])
				break
			}
		}
	}
}

func diffKeys(a, b []string) []string {
	have := map[string]bool{}
	for _, k := range b {
		have[k] = true
	}
	var out []string
	for _, k := range a {
		if !have[k] {
			out = append(out, k)
		}
	}
	return out
}

// The point of the index: a rare term must not read the whole archive.
func TestIndexedSearchNarrowsCandidates(t *testing.T) {
	corpus := buildIndexedCorpus(t)
	tgz := buildMultiTgz(t, corpus)
	idx, err := BuildSearchIndex(bytes.NewReader(tgz), filepath.Join(t.TempDir(), "b.sblob"))
	if err != nil {
		t.Fatal(err)
	}

	rare, err := SearchIndexed(context.Background(), idx,
		bytes.NewReader(tgz), SearchOptions{Query: "zzqqxx-alpha-needle"})
	if err != nil {
		t.Fatal(err)
	}
	if rare.Scanned != 1 {
		t.Errorf("a needle unique to one file scanned %d files, want 1", rare.Scanned)
	}
	if !rare.Indexed {
		t.Error("the outcome should report that the index was used")
	}

	// a term that genuinely is everywhere still has to be scanned everywhere
	broad, err := SearchIndexed(context.Background(), idx,
		bytes.NewReader(tgz), SearchOptions{Query: "line"})
	if err != nil {
		t.Fatal(err)
	}
	if broad.Scanned < 2 {
		t.Errorf("a common term scanned only %d files", broad.Scanned)
	}
}

// A binary or empty file has no searchable text, but a full scan still
// reports it when its *name* matches. The index has to list those files even
// though it never reads them, or the two paths would disagree.
func TestIndexedSearchMatchesFilenamesOfUnreadableFiles(t *testing.T) {
	corpus := map[string]string{
		"var/log/pan/needle-binary.log": "head\x00\x00binary payload needle\n",
		"var/log/pan/needle-empty.log":  "",
		"var/log/pan/needle-text.log":   "a line mentioning needle\n",
	}
	tgz := buildMultiTgz(t, corpus)
	idx, err := BuildSearchIndex(bytes.NewReader(tgz), filepath.Join(t.TempDir(), "b.sblob"))
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Entries) != 3 {
		t.Fatalf("all three files must be listed, got %d", len(idx.Entries))
	}

	o := SearchOptions{Query: "needle", MaxResults: 500}
	want, err := SearchArchive(bytes.NewReader(tgz), o)
	if err != nil {
		t.Fatal(err)
	}
	got, err := SearchIndexed(context.Background(), idx, bytes.NewReader(tgz), o)
	if err != nil {
		t.Fatal(err)
	}
	wk, gk := resultKeys(want.Results), resultKeys(got.Results)
	if strings.Join(wk, "\n") != strings.Join(gk, "\n") {
		t.Errorf("indexed and full scan disagree on unreadable files:\n full:\n  %s\n indexed:\n  %s",
			strings.Join(wk, "\n  "), strings.Join(gk, "\n  "))
	}
	// and the binary file's contents must not be searched by either path
	for _, r := range gk {
		if strings.Contains(r, "binary payload") {
			t.Errorf("binary file contents were searched: %s", r)
		}
	}
}

// Results must arrive in the same order from both paths, not merely as the
// same set: the UI lists them in the order they are returned.
func TestIndexedSearchPreservesResultOrder(t *testing.T) {
	tgz := buildMultiTgz(t, buildIndexedCorpus(t))
	idx, err := BuildSearchIndex(bytes.NewReader(tgz), filepath.Join(t.TempDir(), "b.sblob"))
	if err != nil {
		t.Fatal(err)
	}
	for _, qs := range []string{"monitor", "log", "pan", "uniq"} {
		o := SearchOptions{Query: qs, MaxResults: 5000}
		want, _ := SearchArchive(bytes.NewReader(tgz), o)
		got, _ := SearchIndexed(context.Background(), idx, bytes.NewReader(tgz), o)
		if len(want.Results) != len(got.Results) {
			t.Errorf("%q: %d vs %d results", qs, len(got.Results), len(want.Results))
			continue
		}
		// compared without sorting, unlike resultKeys elsewhere: order is the
		// property under test here
		for i := range want.Results {
			w, g := want.Results[i], got.Results[i]
			if w.Type != g.Type || w.Path != g.Path || w.LineNo != g.LineNo || w.Text != g.Text {
				t.Errorf("%q: result %d out of order\n full:    %+v\n indexed: %+v", qs, i, w, g)
				break
			}
		}
	}
}

// A missing blob (restart, disk cleanup) must degrade to a full scan rather
// than return nothing.
func TestIndexedSearchFallsBackWhenBlobMissing(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{"var/log/pan/a.log": "ospf neighbor down\n"})
	idx, err := BuildSearchIndex(bytes.NewReader(tgz), filepath.Join(t.TempDir(), "gone.sblob"))
	if err != nil {
		t.Fatal(err)
	}
	idx.BlobPath = filepath.Join(t.TempDir(), "does-not-exist.sblob")

	out, err := SearchIndexed(context.Background(), idx, bytes.NewReader(tgz), SearchOptions{Query: "ospf"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) == 0 {
		t.Error("a missing blob must fall back to scanning, not silently find nothing")
	}
}

// A cancelled context must stop the scan and say so, not run to completion.
func TestIndexedSearchHonoursDeadline(t *testing.T) {
	tgz := buildMultiTgz(t, buildIndexedCorpus(t))
	idx, err := BuildSearchIndex(bytes.NewReader(tgz), filepath.Join(t.TempDir(), "b.sblob"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := SearchIndexed(ctx, idx, bytes.NewReader(tgz), SearchOptions{Query: "line"})
	if err != nil {
		t.Fatal(err)
	}
	if !out.TimedOut {
		t.Error("a cancelled search should report timed_out so the UI can say the results are partial")
	}
}

/* ---------- the planner, on its own ---------- */

func TestTriPlannerSoundness(t *testing.T) {
	cases := []struct {
		q       string
		wantAny bool   // no constraint derivable
		gate    string // folded mandatory literal, "" for none
	}{
		{q: "pkt_recv", gate: "PKT_RECV"},
		{q: "PKT_recv", gate: "PKT_RECV"},   // case-folded to the same thing
		{q: "ab", wantAny: true, gate: ""},  // shorter than a trigram
		{q: "oom.*killer", gate: "KILLER"},  // longest of the two literals
		{q: `10\.1\.1\.2`, gate: "10.1.1.2"},
		{q: "neighbou?r", gate: "NEIGHBO"},  // the optional char ends the run
		{q: "ospf|bgp", gate: ""},           // alternation: neither is mandatory
		{q: "[0-9]+", wantAny: true},        // class alone requires nothing
		{q: ".*", wantAny: true},
		{q: "NOT ospf", wantAny: true},         // negation constrains nothing
		{q: "ospf AND NOT down", gate: "OSPF"}, // the positive half still counts
		// two surviving alternatives still narrow the files, but no single
		// literal is mandatory, so there is nothing to gate lines on
		{q: "(ospf|bgp) AND general", gate: ""},
	}
	for _, c := range cases {
		q := ParseSearchQuery(c.q)
		if q.Tri.Any != c.wantAny {
			t.Errorf("%q: Any=%v, want %v", c.q, q.Tri.Any, c.wantAny)
		}
		if got := q.Tri.gate(); got != c.gate {
			t.Errorf("%q: gate=%q, want %q", c.q, got, c.gate)
		}
	}
}

// Whatever the planner claims a query requires, a line that matches must
// really contain those trigrams — otherwise the file filter would drop it.
func TestTriPlanIsImpliedByMatches(t *testing.T) {
	lines := []string{
		"2026/08/04 21:00:20 medium general OSPF neighbor 10.1.1.2 went down",
		"pkt_recv 12345 PKT_SENT 6789",
		"kernel: Out of memory: Killed process 1234 (reportd)",
		"mp process useridd res_swap 1400000",
		"Ünïcödé ÖSPF neighbour down",
		"K vs k vs K kelvin",
		"tab\tseparated\tvalues",
	}
	lines = append(lines,
		// the shapes that would expose a wrong assumption about how Go's
		// regexp parser splits a literal before a quantifier: each of these
		// matches a pattern below without containing the whole literal
		"prefix abc here",      // matches abcd*
		"prefix pkt_rec here",  // matches pkt_recv?
		"prefix res_swa here",  // matches res_swap{0,3}
		"prefix osp here",      // matches ospf?
	)
	queries := []string{
		"ospf", "OSPF", "pkt_recv", "oom|Out of memory", "res_swap.*000",
		"neighbou?r", `10\.\d+\.\d+\.\d+`, "kelvin", "k vs", "ünïcödé",
		"separated", "process AND kernel", "memory AND NOT ospf",
		// A trailing quantifier must not leave the character it applies to
		// inside the mandatory literal: "abcd*" requires "abc", not "abcd".
		"abcd*", "pkt_recv?", "res_swap{0,3}", "ospf?", "res_swap{2,}",
		"(pkt_recv)+", "(?:kernel|process)+", "kelvin$", "^tab",
	}
	for _, qs := range queries {
		q := ParseSearchQuery(qs)
		for _, line := range lines {
			if !q.Match(line) {
				continue
			}
			// the line matches, so at least one AND-group must be satisfiable
			// by this line's own trigrams
			if q.Tri.Any {
				continue
			}
			folded := foldLine(nil, []byte(line))
			present := map[uint32]bool{}
			for i := 0; i+3 <= len(folded); i++ {
				present[uint32(folded[i])<<16|uint32(folded[i+1])<<8|uint32(folded[i+2])] = true
			}
			ok := false
			for _, g := range q.Tri.Ors {
				all := true
				for _, tr := range g.tris {
					if !present[tr] {
						all = false
						break
					}
				}
				if all {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("query %q matches %q but the plan requires trigrams the line does not have —\n"+
					"the file filter would have dropped this match", qs, line)
			}
		}
	}
}

// The enumerated cases above only cover shapes I thought of. This one
// generates queries and lines pseudo-randomly (fixed seed, so a failure is
// reproducible) and asserts the same implication: if a line matches, the plan
// must not require a trigram the line lacks. Any planner mistake — including
// a wrong assumption about how Go parses a pattern — shows up here.
func TestTriPlanImplicationRandomised(t *testing.T) {
	rnd := rand.New(rand.NewSource(20260815))
	atoms := []string{
		"ospf", "bgp", "pkt_recv", "res_swap", "kernel", "down", "1.1.1.2",
		"neighbor", "oom", "reportd", "a", "ab", "abc", "_", "-", ".",
	}
	suffixes := []string{"", "", "", "?", "*", "+", "{0,2}", "{2,}", ".*", `\d+`, "[a-z]*"}
	joiners := []string{" ", " AND ", " OR ", " ", " NOT ", "|"}

	build := func() string {
		var sb strings.Builder
		for i, n := 0, 1+rnd.Intn(3); i < n; i++ {
			if i > 0 {
				sb.WriteString(joiners[rnd.Intn(len(joiners))])
			}
			if rnd.Intn(6) == 0 {
				sb.WriteString("(")
				sb.WriteString(atoms[rnd.Intn(len(atoms))])
				sb.WriteString("|")
				sb.WriteString(atoms[rnd.Intn(len(atoms))])
				sb.WriteString(")")
				continue
			}
			sb.WriteString(atoms[rnd.Intn(len(atoms))])
			sb.WriteString(suffixes[rnd.Intn(len(suffixes))])
		}
		return sb.String()
	}
	makeLine := func() string {
		var sb strings.Builder
		for i, n := 0, 1+rnd.Intn(6); i < n; i++ {
			if i > 0 {
				sb.WriteByte(' ')
			}
			w := atoms[rnd.Intn(len(atoms))]
			if rnd.Intn(3) == 0 {
				w = strings.ToUpper(w)
			}
			if rnd.Intn(5) == 0 && len(w) > 1 {
				w = w[:len(w)-1] // a truncated word, to hit boundary cases
			}
			sb.WriteString(w)
		}
		return sb.String()
	}

	for i := 0; i < 4000; i++ {
		qs := build()
		q := ParseSearchQuery(qs)
		if q.Empty || q.Tri.Any {
			continue
		}
		line := makeLine()
		if !q.Match(line) {
			continue
		}
		if !planSatisfiedBy(q.Tri, line) {
			t.Fatalf("unsound plan: query %q matches line %q, but the required "+
				"trigrams are absent from it, so the file filter would drop the match", qs, line)
		}
		// the line gate must agree with the plan for the same reason
		if g := q.Tri.gate(); g != "" {
			if !bytes.Contains(foldLine(nil, []byte(line)), []byte(g)) {
				t.Fatalf("unsound gate: query %q matches line %q but the gate %q is not in it", qs, line, g)
			}
		}
	}
}

// planSatisfiedBy reports whether the line's own trigrams satisfy at least one
// of the plan's AND-groups.
func planSatisfiedBy(tq triQuery, line string) bool {
	if tq.Any {
		return true
	}
	folded := foldLine(nil, []byte(line))
	present := map[uint32]bool{}
	for i := 0; i+3 <= len(folded); i++ {
		present[uint32(folded[i])<<16|uint32(folded[i+1])<<8|uint32(folded[i+2])] = true
	}
	for _, g := range tq.Ors {
		ok := true
		for _, tr := range g.tris {
			if !present[tr] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestFoldAgreesWithCaseInsensitiveMatching(t *testing.T) {
	pairs := [][2]string{
		{"pkt_recv", "PKT_RECV"},
		{"OsPf", "ospf"},
		{"K", "K"}, // KELVIN SIGN folds onto plain K
		{"s", "ſ"}, // LATIN SMALL LETTER LONG S
	}
	for _, p := range pairs {
		if foldString(p[0]) != foldString(p[1]) {
			t.Errorf("fold(%q)=%q != fold(%q)=%q — the index and the matcher would disagree",
				p[0], foldString(p[0]), p[1], foldString(p[1]))
		}
	}
	// folding must be stable: folding twice changes nothing
	for _, s := range []string{"Mixed Case", "Kelvin", "ÜBER", "plain"} {
		if f := foldString(s); foldString(f) != f {
			t.Errorf("fold is not idempotent for %q: %q -> %q", s, f, foldString(f))
		}
	}
}

// Chunk boundaries must not corrupt trigrams: a multi-byte rune split across
// two reads has to be carried, or the index would hold trigrams the query
// side can never produce.
func TestFoldAcrossChunkBoundary(t *testing.T) {
	text := "aaa" + strings.Repeat("é", 200) + "OSPF neighbour down"
	whole := foldLine(nil, []byte(text))

	var pieces []byte
	var carry []byte
	for i := 0; i < len(text); i += 7 { // deliberately awkward chunk size
		end := i + 7
		if end > len(text) {
			end = len(text)
		}
		chunk := append(append([]byte{}, carry...), text[i:end]...)
		pieces, carry = foldBytes(pieces, chunk)
	}
	pieces = append(pieces, carry...)

	if !bytes.Equal(whole, pieces) {
		t.Errorf("chunked folding differs from whole-string folding:\n whole:   %q\n chunked: %q",
			whole, pieces)
	}
}
