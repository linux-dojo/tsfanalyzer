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
	defaultMaxResults  = 200
	maxLineHitsPerFile = 50
	maxContextLines    = 30
)

/* ---------- query parsing ---------- */

type queryNode interface {
	match(lower string) bool
}

type termNode struct {
	re      *regexp.Regexp // set for regex terms
	literal string         // set for quoted terms (already lower-cased)
}

func (t termNode) match(lower string) bool {
	if t.re != nil {
		return t.re.MatchString(lower)
	}
	return strings.Contains(lower, t.literal)
}

type notNode struct{ a queryNode }
type andNode struct{ a, b queryNode }
type orNode struct{ a, b queryNode }

func (n notNode) match(s string) bool { return !n.a.match(s) }
func (n andNode) match(s string) bool { return n.a.match(s) && n.b.match(s) }
func (n orNode) match(s string) bool  { return n.a.match(s) || n.b.match(s) }

// SearchQuery is a parsed query plus the context counts pulled out of it.
type SearchQuery struct {
	root   queryNode
	Before int
	After  int
	Empty  bool
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
		return q
	}
	toks := tokenizeQuery(body)
	p := &queryParser{toks: toks}
	root := p.parseOr()
	if root == nil {
		// fall back to a literal match on the whole body
		root = termNode{literal: strings.ToLower(body)}
	}
	q.root = root
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
func makeTerm(t qtok) queryNode {
	if t.quot {
		return termNode{literal: strings.ToLower(t.val)}
	}
	re, err := regexp.Compile("(?i)" + t.val)
	if err != nil {
		return termNode{literal: strings.ToLower(t.val)}
	}
	return termNode{re: re}
}

/* ---------- the search itself ---------- */

// SearchArchive scans the archive for a query, optionally restricted to a set
// of paths, returning matches with grep-style context.
func SearchArchive(r io.ReadSeeker, opts SearchOptions) ([]SearchResult, error) {
	q := ParseSearchQuery(opts.Query)
	if q.Empty {
		return []SearchResult{}, nil
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
	out := []SearchResult{}

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
		out = searchLines(br, p, q, before, after, max, out)
	}
	return out, nil
}

// searchLines scans one file, keeping a ring buffer of preceding lines so
// -B context can be emitted, and a countdown so -A context following a match
// is captured as the scan continues.
func searchLines(r io.Reader, path string, q *SearchQuery, before, after, max int, out []SearchResult) []SearchResult {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	// awaiting is the set of results still collecting trailing context, each
	// with the number of lines it still wants
	type awaiting struct{ idx, need int }
	var pend []awaiting

	ring := make([]ContextLine, 0, before) // the last `before` lines seen
	lineNo := 0
	hits := 0

	for sc.Scan() {
		lineNo++
		line := sc.Text()

		// 1. this line is trailing context for any result still waiting
		if len(pend) > 0 {
			keep := pend[:0]
			for _, a := range pend {
				out[a.idx].Context = append(out[a.idx].Context,
					ContextLine{LineNo: lineNo, Text: clip(line)})
				if a.need--; a.need > 0 {
					keep = append(keep, a)
				}
			}
			pend = keep
		}

		// 2. does the line itself match?
		if hits < maxLineHitsPerFile && len(out) < max && q.Match(line) {
			res := SearchResult{Type: "line", Path: path, LineNo: lineNo, Text: clip(line)}
			if before > 0 {
				res.Context = append(res.Context, ring...)
			}
			out = append(out, res)
			hits++
			if after > 0 {
				pend = append(pend, awaiting{idx: len(out) - 1, need: after})
			}
		}

		// 3. remember this line as possible leading context for later matches
		if before > 0 {
			if len(ring) == before {
				ring = ring[1:]
			}
			ring = append(ring, ContextLine{LineNo: lineNo, Text: clip(line), Before: true})
		}

		// stop once the cap is reached and nothing is still collecting context
		if len(out) >= max && len(pend) == 0 {
			break
		}
	}
	return out
}

func clip(s string) string {
	s = strings.TrimRight(s, "\r")
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}
