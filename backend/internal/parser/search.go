// Package parser: search.go is the archive-wide search.
//
// The query language is shared with the in-file search in the UI:
//
//	ospf AND down            adjacent terms are ANDed implicitly
//	tunnel OR ipsec          OR, and NOT, with the usual precedence
//	"exact phrase"           quoted terms match literally
//	oom.*killer              bare terms are regular expressions
//	(ospf OR bgp) AND -down  parentheses group
//	failed -A 5              grep-style trailing context
//	failed -B 3 -A 3         leading and trailing context
//
// Precedence is NOT > AND > OR. Terms are case-insensitive.
package parser

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// ContextLine is one line of grep-style context around a match.
type ContextLine struct {
	LineNo int    `json:"line_no"`
	Text   string `json:"text"`
	Before bool   `json:"before"` // true if it precedes the match
}

// SearchResult is one hit: either a filename match ("file") or a line match
// ("line"), the latter optionally carrying context lines.
type SearchResult struct {
	Type    string        `json:"type"` // file | line
	Path    string        `json:"path"`
	LineNo  int           `json:"line_no,omitempty"`
	Text    string        `json:"text,omitempty"`
	Context []ContextLine `json:"context,omitempty"`
	// Filtered means this line matched the search but not the field filter.
	// It is kept only as the anchor for context lines that did pass — the
	// usual shape of "find this section header, show the values under it".
	Filtered bool `json:"filtered,omitempty"`
}

// SearchOptions controls one search.
type SearchOptions struct {
	Query string
	// Paths restricts the search to these archive paths. Empty searches
	// everything, which is what the global search does.
	Paths      []string
	Before     int // grep -B
	After      int // grep -A
	MaxResults int
}

const (
	// Caps exist to bound the response, but they must be reported: a silently
	// truncated result set made the counts look arbitrary (a per-file cap of
	// 50 showed as "50 matches" for one file and "150" for three). They are
	// generous now that the index makes a scan cheap.
	defaultMaxResults  = 2000
	maxLineHitsPerFile = 500
	maxContextLines    = 30
)

// SearchOutcome is the result set plus what was left out, so the UI can say
// so rather than presenting a truncated count as the total.
type SearchOutcome struct {
	Results []SearchResult `json:"results"`
	// Truncated is set when the overall cap stopped the scan early.
	Truncated bool `json:"truncated"`
	// CappedFiles lists files where the per-file cap was hit.
	CappedFiles []string `json:"capped_files,omitempty"`
	Limit       int      `json:"limit"`

	// Indexed reports whether the trigram index served this search, and
	// Candidates/Scanned how much of the archive it had to look at — the
	// difference between the two is what the index saved.
	Indexed    bool `json:"indexed"`
	Candidates int  `json:"candidates,omitempty"`
	Scanned    int  `json:"scanned,omitempty"`
	// TimedOut means the deadline stopped the scan, so the results are
	// partial. Reporting it beats letting the request die as a 504.
	TimedOut bool `json:"timed_out,omitempty"`

	// Filter echoes the "| $2 > 10" clause that was applied, and FilterError
	// explains a clause that could not be parsed (in which case none was
	// applied, so the user sees everything rather than nothing).
	Filter      string `json:"filter,omitempty"`
	FilterError string `json:"filter_error,omitempty"`
}

/* ---------- query parsing ---------- */

type queryNode interface {
	match(lower string) bool
	// plan states which trigrams a match requires, for narrowing the set of
	// candidate files. A node that cannot promise anything returns triAny.
	plan() triQuery
}

type termNode struct {
	re      *regexp.Regexp // set for regex terms
	literal string         // set for quoted terms (already lower-cased)
	tq      triQuery       // what this term requires of a file
}

func (t termNode) match(lower string) bool {
	if t.re != nil {
		return t.re.MatchString(lower)
	}
	return strings.Contains(lower, t.literal)
}

func (t termNode) plan() triQuery { return t.tq }

type notNode struct{ a queryNode }
type andNode struct{ a, b queryNode }
type orNode struct{ a, b queryNode }

func (n notNode) match(s string) bool { return !n.a.match(s) }
func (n andNode) match(s string) bool { return n.a.match(s) && n.b.match(s) }
func (n orNode) match(s string) bool  { return n.a.match(s) || n.b.match(s) }

// A negated term says nothing about what a file must contain.
func (n notNode) plan() triQuery { return triAny() }
func (n andNode) plan() triQuery { return triAnd(n.a.plan(), n.b.plan()) }
func (n orNode) plan() triQuery  { return triOr(n.a.plan(), n.b.plan()) }

// SearchQuery is a parsed query plus the context counts pulled out of it.
type SearchQuery struct {
	root   queryNode
	Before int
	After  int
	Empty  bool
	// Tri is the trigram requirement derived from the tree, used to pick
	// candidate files and to gate individual lines.
	Tri triQuery
	// Filter is the trailing "| $2 > 10" clause, if any. It narrows the lines
	// that are shown; it is deliberately not part of Tri, because a file can
	// only be excluded by what the search terms require, never by a value
	// test that a line elsewhere in the file might satisfy.
	Filter *FieldFilter
}

// Match reports whether a line satisfies the query.
func (q *SearchQuery) Match(line string) bool {
	if q == nil || q.Empty || q.root == nil {
		return false
	}
	return q.root.match(strings.ToLower(line))
}

var contextFlagRe = regexp.MustCompile(`(?i)(^|\s)-([ABC])\s*(\d+)`)

// ParseSearchQuery extracts -A/-B/-C context counts and builds the boolean
// tree. An unparseable query degrades to a literal substring search rather
// than failing, so typing mid-query never errors.
func ParseSearchQuery(raw string) *SearchQuery {
	q := &SearchQuery{}

	// peel off a trailing "| $2 > 10" field filter before anything else, so
	// the search half never sees it
	raw, clause := SplitFieldClause(raw)
	q.Filter = ParseFieldFilter(clause)

	// pull out the grep-style context flags first
	body := contextFlagRe.ReplaceAllStringFunc(raw, func(m string) string {
		sub := contextFlagRe.FindStringSubmatch(m)
		n, _ := strconv.Atoi(sub[3])
		if n > maxContextLines {
			n = maxContextLines
		}
		switch strings.ToUpper(sub[2]) {
		case "A":
			q.After = n
		case "B":
			q.Before = n
		case "C":
			q.Before, q.After = n, n
		}
		return " "
	})

	body = strings.TrimSpace(body)
	if body == "" {
		q.Empty = true
		q.Tri = triAny()
		return q
	}
	toks := tokenizeQuery(body)
	p := &queryParser{toks: toks}
	root := p.parseOr()
	if root == nil {
		// fall back to a literal match on the whole body
		lower := strings.ToLower(body)
		root = termNode{literal: lower, tq: triFromLiteral(lower)}
	}
	q.root = root
	q.Tri = root.plan()
	return q
}

type qtok struct {
	kind string // and | or | not | ( | ) | term
	val  string
	quot bool // the term was quoted, so match literally
}

func tokenizeQuery(q string) []qtok {
	var out []qtok
	i := 0
	for i < len(q) {
		c := q[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(' || c == ')':
			out = append(out, qtok{kind: string(c)})
			i++
		case c == '!':
			out = append(out, qtok{kind: "not"})
			i++
		case c == '&':
			if i+1 < len(q) && q[i+1] == '&' {
				i += 2
			} else {
				i++
			}
			out = append(out, qtok{kind: "and"})
		case c == '|':
			if i+1 < len(q) && q[i+1] == '|' {
				i += 2
			} else {
				i++
			}
			out = append(out, qtok{kind: "or"})
		case c == '"' || c == '\'':
			end := strings.IndexByte(q[i+1:], c)
			var v string
			if end < 0 {
				v = q[i+1:]
				i = len(q)
			} else {
				v = q[i+1 : i+1+end]
				i = i + end + 2
			}
			if v != "" {
				out = append(out, qtok{kind: "term", val: v, quot: true})
			}
		default:
			j := i
			for j < len(q) && !strings.ContainsRune(" \t()!&|", rune(q[j])) {
				j++
			}
			w := q[i:j]
			switch strings.ToUpper(w) {
			case "AND":
				out = append(out, qtok{kind: "and"})
			case "OR":
				out = append(out, qtok{kind: "or"})
			case "NOT":
				out = append(out, qtok{kind: "not"})
			default:
				out = append(out, qtok{kind: "term", val: w})
			}
			i = j
		}
	}
	return out
}

type queryParser struct {
	toks []qtok
	pos  int
}

func (p *queryParser) peek() *qtok {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *queryParser) parseOr() queryNode {
	left := p.parseAnd()
	if left == nil {
		return nil
	}
	for t := p.peek(); t != nil && t.kind == "or"; t = p.peek() {
		p.pos++
		right := p.parseAnd()
		if right == nil {
			return left
		}
		left = orNode{left, right}
	}
	return left
}

func (p *queryParser) parseAnd() queryNode {
	left := p.parseNot()
	if left == nil {
		return nil
	}
	for {
		t := p.peek()
		if t == nil || t.kind == "or" || t.kind == ")" {
			break
		}
		if t.kind == "and" {
			p.pos++ // explicit; otherwise adjacency implies AND
		}
		right := p.parseNot()
		if right == nil {
			break
		}
		left = andNode{left, right}
	}
	return left
}

func (p *queryParser) parseNot() queryNode {
	t := p.peek()
	if t == nil {
		return nil
	}
	if t.kind == "not" {
		p.pos++
		if a := p.parseNot(); a != nil {
			return notNode{a}
		}
		return nil
	}
	if t.kind == "(" {
		p.pos++
		inner := p.parseOr()
		if c := p.peek(); c != nil && c.kind == ")" {
			p.pos++
		}
		return inner
	}
	if t.kind == "term" {
		p.pos++
		return makeTerm(*t)
	}
	p.pos++ // stray operator
	return p.parseNot()
}

// makeTerm compiles a bare term as a case-insensitive regex; a quoted term
// is matched literally so that punctuation-heavy phrases need no escaping.
// Each term also carries the trigrams a file must contain for it to match.
func makeTerm(t qtok) queryNode {
	if t.quot {
		lower := strings.ToLower(t.val)
		return termNode{literal: lower, tq: triFromLiteral(lower)}
	}
	re, err := regexp.Compile("(?i)" + t.val)
	if err != nil {
		// an unparseable regex degrades to a literal, so its trigrams are
		// exactly the literal's
		lower := strings.ToLower(t.val)
		return termNode{literal: lower, tq: triFromLiteral(lower)}
	}
	return termNode{re: re, tq: triFromRegexp(t.val)}
}

// noteFilter records the field-filter clause on the outcome so the UI can
// echo it, and can say when a clause was ignored rather than applied.
func (o *SearchOutcome) noteFilter(q *SearchQuery) {
	if q == nil || q.Filter == nil {
		return
	}
	o.Filter = q.Filter.Text
	o.FilterError = q.Filter.Bad
}

/* ---------- the search itself ---------- */

// SearchArchive scans the archive for a query, optionally restricted to a set
// of paths, returning matches with grep-style context.
//
// This is the unindexed path: it inflates the whole archive, so it is the
// fallback (and the oracle the indexed path is tested against) rather than
// what the UI normally hits. See SearchIndexed.
func SearchArchive(r io.ReadSeeker, opts SearchOptions) (*SearchOutcome, error) {
	q := ParseSearchQuery(opts.Query)
	if q.Empty {
		return &SearchOutcome{Results: []SearchResult{}, Limit: 0}, nil
	}
	before, after := q.Before, q.After
	if opts.Before > before {
		before = opts.Before
	}
	if opts.After > after {
		after = opts.After
	}
	max := opts.MaxResults
	if max <= 0 {
		max = defaultMaxResults
	}

	only := map[string]bool{}
	for _, p := range opts.Paths {
		if p = strings.TrimSpace(p); p != "" {
			only[p] = true
		}
	}

	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	res := &SearchOutcome{Results: []SearchResult{}, Limit: max}
	res.noteFilter(q)
	out := res.Results
	// Deliberately no line gate here: this path is the oracle the indexed
	// path is tested against, so it runs the query tree over every line.
	var scratch []byte

	for len(out) < max {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break // tolerate trailing corruption: return what was found
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		p := normalizePath(hdr.Name)
		if p == "" || (len(only) > 0 && !only[p]) {
			continue
		}

		// a path match is itself a result, but only when unrestricted:
		// inside a chosen file the filename is not interesting
		if len(only) == 0 && q.Match(p) {
			out = append(out, SearchResult{Type: "file", Path: p})
			if len(out) >= max {
				break
			}
		}

		br := bufio.NewReaderSize(tr, 64*1024)
		if peek, _ := br.Peek(512); bytes.IndexByte(peek, 0) >= 0 {
			continue // binary
		}
		var capped bool
		out, capped, scratch = searchLines(context.Background(), br, p, q, nil, scratch, before, after, max, out)
		if capped {
			res.CappedFiles = append(res.CappedFiles, p)
		}
	}
	res.Results = out
	res.Truncated = len(out) >= max
	return res, nil
}

// deadlineCheckLines is how often the scan looks at the context: often enough
// to stop promptly, rarely enough that the check costs nothing.
const deadlineCheckLines = 4096

// searchLines scans one file, keeping a ring buffer of preceding lines so
// -B context can be emitted, and a countdown so -A context following a match
// is captured as the scan continues.
//
// gate, when set, is a folded literal that every matching line must contain.
// Testing it with a byte search first is far cheaper than running the regex
// tree, and it means a non-matching line costs no allocation at all: the line
// is only converted to a string once it is a real candidate. scratch is a
// reusable fold buffer, returned so the caller can carry it between files.
func searchLines(ctx context.Context, r io.Reader, path string, q *SearchQuery, gate, scratch []byte, before, after, max int, out []SearchResult) ([]SearchResult, bool, []byte) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	// awaiting is the set of results still collecting trailing context, each
	// with the number of lines it still wants
	type awaiting struct{ idx, need int }
	var pend []awaiting

	ring := make([]ContextLine, 0, before) // the last `before` lines seen
	lineNo := 0
	hits := 0
	start := len(out) // where this file's results begin, for the filter sweep

	for sc.Scan() {
		lineNo++
		raw := sc.Bytes()

		if lineNo%deadlineCheckLines == 0 && ctx.Err() != nil {
			break
		}

		// 1. this line is trailing context for any result still waiting. The
		// countdown runs whether or not the line survives the field filter,
		// because grep emits the next n lines and awk drops some of them —
		// the window is n lines, not n surviving lines.
		if len(pend) > 0 {
			keep := pend[:0]
			text := clip(string(raw))
			survives := q.Filter.Keep(string(raw))
			for _, a := range pend {
				if survives {
					out[a.idx].Context = append(out[a.idx].Context,
						ContextLine{LineNo: lineNo, Text: text})
				}
				if a.need--; a.need > 0 {
					keep = append(keep, a)
				}
			}
			pend = keep
		}

		// 2. does the line itself match? The gate rejects the overwhelming
		// majority of lines without touching the regex engine.
		if hits < maxLineHitsPerFile && len(out) < max {
			candidate := true
			if len(gate) > 0 {
				scratch = foldLine(scratch[:0], raw)
				candidate = bytes.Contains(scratch, gate)
			}
			if candidate && q.Match(string(raw)) {
				passes := q.Filter.Keep(string(raw))
				// A match that fails the filter is only worth keeping if it
				// can still anchor context lines that pass.
				if passes || before > 0 || after > 0 {
					res := SearchResult{
						Type: "line", Path: path, LineNo: lineNo,
						Text: clip(string(raw)), Filtered: !passes,
					}
					for _, cl := range ring {
						if q.Filter.Keep(cl.Text) {
							res.Context = append(res.Context, cl)
						}
					}
					out = append(out, res)
					hits++
					if after > 0 {
						pend = append(pend, awaiting{idx: len(out) - 1, need: after})
					}
				}
			}
		}

		// 3. remember this line as possible leading context for later matches.
		// The ring is unfiltered so it stays a true "last n lines" window;
		// filtering happens when the lines are emitted, above.
		if before > 0 {
			if len(ring) == before {
				ring = ring[1:]
			}
			ring = append(ring, ContextLine{LineNo: lineNo, Text: clip(string(raw)), Before: true})
		}

		// stop once the cap is reached and nothing is still collecting context
		if len(out) >= max && len(pend) == 0 {
			break
		}
	}

	// Drop anchors whose context all failed the filter too: nothing of that
	// block survived, so it should not appear at all.
	if q.Filter.Active() {
		kept := out[:start]
		for _, r := range out[start:] {
			if r.Filtered && len(r.Context) == 0 {
				continue
			}
			kept = append(kept, r)
		}
		out = kept
	}

	// report whether this file had more matches than the per-file cap allowed
	return out, hits >= maxLineHitsPerFile, scratch
}

func clip(s string) string {
	s = strings.TrimRight(s, "\r")
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}
