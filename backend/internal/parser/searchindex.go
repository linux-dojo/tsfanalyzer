// Package parser: searchindex.go makes archive search fast by doing the
// expensive work once, at parse time, instead of once per query.
//
// Searching the .tgz directly means inflating the whole archive on every
// keystroke-debounced query — for a 100 MB tech-support file that is a
// gigabyte of gunzip plus a regex over every line, which is what made broad
// searches time out. Two artefacts are built instead:
//
//   - a blob: every text file's bytes, uncompressed, concatenated on disk with
//     a span table. Searching a file is then a plain read at an offset, with
//     no decompression at all.
//   - a trigram index: for each 3-byte sequence, the files that contain it.
//     A query's required trigrams narrow thousands of files down to the few
//     that could possibly match, so a rare term is found by reading a few
//     megabytes rather than a gigabyte.
//
// The index is only ever allowed to *narrow* the search. Every construct it
// cannot reason about — alternation with an unanchored branch, NOT, a bare
// character class — degrades to "every file is a candidate", so a query can
// never silently miss a line it would have found in a full scan. The
// equivalence tests in searchindex_test.go assert exactly that.
//
// # Case folding
//
// The matcher is case-insensitive, so the index must be too, and the two must
// agree exactly or the filter would drop real matches. Lower-casing is not
// enough: Go's regexp folds Unicode orbits, so "(?i)k" matches U+212A KELVIN
// SIGN, and strings.ToLower maps U+0130 to plain "i". Both sides therefore
// canonicalise each rune to the smallest member of its case-folding orbit
// after lower-casing — see foldRune. For ASCII that reduces to upper-casing,
// which costs one branch per byte.
package parser

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

/* ---------- case folding, shared by the index and the query ---------- */

// foldRune canonicalises a rune: lower-case it, then take the smallest member
// of its case-folding orbit, so every spelling of a character maps to one
// value. ASCII letters end up upper-cased ('a' -> 'A'), which is also the
// orbit minimum for the awkward cases ('k' with U+212A, 's' with U+017F).
func foldRune(r rune) rune {
	if r < utf8.RuneSelf {
		if r >= 'a' && r <= 'z' {
			return r - 32
		}
		if r >= 'A' && r <= 'Z' {
			return r
		}
		return r
	}
	r = unicode.ToLower(r)
	min := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < min {
			min = f
		}
	}
	return min
}

// foldBytes appends the folded form of src to dst. Any trailing bytes that
// form an incomplete UTF-8 rune are returned rather than folded, so a caller
// streaming in chunks can carry them into the next one; folding a half rune
// would produce a trigram the query side could never reproduce.
func foldBytes(dst, src []byte) ([]byte, []byte) {
	i := 0
	for i < len(src) {
		b := src[i]
		if b < utf8.RuneSelf {
			if b >= 'a' && b <= 'z' {
				b -= 32
			}
			dst = append(dst, b)
			i++
			continue
		}
		r, size := utf8.DecodeRune(src[i:])
		if r == utf8.RuneError && size <= 1 {
			// Invalid, or a rune cut short by the end of the chunk.
			if len(src)-i < utf8.UTFMax {
				return dst, src[i:]
			}
			dst = append(dst, b) // genuinely invalid: pass the byte through
			i++
			continue
		}
		dst = utf8.AppendRune(dst, foldRune(r))
		i += size
	}
	return dst, nil
}

// foldLine folds one whole line. Unlike foldBytes there is no next chunk to
// carry into, so a trailing partial rune is appended as-is: it can only add
// bytes, never remove a match.
func foldLine(dst, src []byte) []byte {
	dst, carry := foldBytes(dst, src)
	return append(dst, carry...)
}

func foldString(s string) string {
	// fast path: already folded (the common case for lower-case ASCII input
	// is not free, so check before allocating)
	ascii := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= utf8.RuneSelf || (c >= 'a' && c <= 'z') {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	return string(foldLine(make([]byte, 0, len(s)+8), []byte(s)))
}

/* ---------- the index ---------- */

// FileSpan locates one archive file's bytes inside the blob.
type FileSpan struct {
	Path string `json:"path"`
	Off  int64  `json:"off"`
	Size int64  `json:"size"`
}

// triCommon marks a trigram that occurs in so many files that it excludes
// nothing. Its posting list is dropped to save memory; the distinction from
// "absent everywhere" matters, because absent means *no* file can match.
const triCommon = int32(-1)

// IndexEntry is one regular file in the archive, in the order the tar lists
// them. File indexes into Files, or is -1 when the file has no searchable
// text in the blob — binary, empty, or past the size cap. Those still have to
// be listed, because a full scan matches them by *name* even when it never
// reads their contents, and the two paths must agree.
type IndexEntry struct {
	Path string `json:"path"`
	File int32  `json:"file"`
}

// SearchIndex is the parse-time artefact that makes search fast.
type SearchIndex struct {
	BlobPath string       `json:"blob_path"`
	Entries  []IndexEntry `json:"entries"`
	Files    []FileSpan   `json:"files"`

	// Unindexed lists text files that are in the archive but not in the blob
	// (the size cap was reached). They are scanned from the .tgz instead, so
	// they are searched — just slowly — rather than skipped.
	Unindexed []string `json:"unindexed,omitempty"`

	BlobBytes int64 `json:"blob_bytes"`
	Postings  int   `json:"postings"`
	Trigrams  int   `json:"trigrams"`

	tri  map[uint32]int32 // trigram -> slot in post, or triCommon
	post [][]int32        // sorted file indices

	// alwaysScan holds files indexed into the blob but with no trigram data
	// (the postings budget ran out). They are candidates for every query.
	alwaysScan []int32
}

const (
	// A tech-support archive inflates to a few gigabytes at most; the cap is
	// a backstop against a pathological file filling the disk.
	maxBlobBytes = 6 << 30
	// Beyond this many files a trigram filters almost nothing, so its list is
	// dropped and the memory reclaimed.
	maxPostingsPerTrigram = 2048
	// Overall postings budget: 24M int32 is roughly 96 MB.
	maxTotalPostings = 24 << 20
)

// triSet collects the distinct trigrams of one file. A map would cost a hash
// lookup per byte of the archive; a 2 MiB bitmap plus a list of what was set
// costs a couple of instructions and clears in proportion to the distinct
// count rather than the address space.
type triSet struct {
	bits []uint64
	list []uint32
}

func newTriSet() *triSet { return &triSet{bits: make([]uint64, (1<<24)/64)} }

func (s *triSet) add(t uint32) {
	w, m := t>>6, uint64(1)<<(t&63)
	if s.bits[w]&m == 0 {
		s.bits[w] |= m
		s.list = append(s.list, t)
	}
}

func (s *triSet) reset() {
	for _, t := range s.list {
		s.bits[t>>6] &^= uint64(1) << (t & 63)
	}
	s.list = s.list[:0]
}

// BuildSearchIndex walks the archive once, writing every text file's bytes to
// blobPath and recording which files contain which trigrams.
func BuildSearchIndex(r io.ReadSeeker, blobPath string) (*SearchIndex, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	blob, err := os.Create(blobPath)
	if err != nil {
		return nil, err
	}
	defer blob.Close()
	bw := bufio.NewWriterSize(blob, 1<<20)

	idx := &SearchIndex{BlobPath: blobPath, tri: map[uint32]int32{}}
	set := newTriSet()
	budget := maxTotalPostings
	var off int64

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break // tolerate trailing corruption, as the other passes do
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		p := normalizePath(hdr.Name)
		if p == "" {
			continue
		}
		// Every regular file is listed, even one whose contents are never
		// read, so that filename matching sees exactly what a full scan sees.
		entry := IndexEntry{Path: p, File: -1}

		br := bufio.NewReaderSize(tr, 64<<10)
		peek, _ := br.Peek(512)
		switch {
		case bytes.IndexByte(peek, 0) >= 0:
			// binary: a full scan skips its contents too
		case off+hdr.Size > maxBlobBytes:
			// no room left in the blob: read this one from the archive instead
			idx.Unindexed = append(idx.Unindexed, p)
		default:
			set.reset()
			// A read error here leaves the file truncated in the blob, but the
			// span records only what was written and the trigrams cover only
			// that, so the two stay consistent. The tar stream is broken at
			// that point anyway, and a full scan would stop in the same place.
			n, _ := copyAndScan(bw, br, set)
			if n > 0 {
				entry.File = int32(len(idx.Files))
				idx.Files = append(idx.Files, FileSpan{Path: p, Off: off, Size: n})
				off += n
				if budget > 0 {
					budget -= idx.addPostings(entry.File, set.list)
				} else {
					// no budget left: this file gets no trigram data, so it is
					// a candidate for every query rather than a missed one
					idx.alwaysScan = append(idx.alwaysScan, entry.File)
				}
			}
		}
		idx.Entries = append(idx.Entries, entry)
	}

	if err := bw.Flush(); err != nil {
		return nil, err
	}
	idx.BlobBytes = off
	idx.Trigrams = len(idx.tri)
	return idx, nil
}

// addPostings records that file fi contains these trigrams, returning how
// much of the budget was consumed. A trigram that grows past the per-trigram
// cap is demoted to "common" and its list freed.
func (idx *SearchIndex) addPostings(fi int32, tris []uint32) int {
	used := 0
	for _, t := range tris {
		slot, ok := idx.tri[t]
		if ok && slot == triCommon {
			continue
		}
		if !ok {
			slot = int32(len(idx.post))
			idx.post = append(idx.post, nil)
			idx.tri[t] = slot
		}
		lst := idx.post[slot]
		if len(lst) >= maxPostingsPerTrigram {
			idx.tri[t] = triCommon
			idx.post[slot] = nil
			idx.Postings -= len(lst)
			used -= len(lst) // the budget is handed back
			continue
		}
		// file indices arrive in increasing order, so the list stays sorted
		idx.post[slot] = append(lst, fi)
		idx.Postings++
		used++
	}
	return used
}

// copyAndScan copies src to dst while folding the bytes on the fly and
// recording the trigrams that result. The blob keeps the original text — the
// UI displays it — while the trigrams come from the folded form.
func copyAndScan(dst io.Writer, src io.Reader, set *triSet) (int64, error) {
	buf := make([]byte, 256<<10)
	fold := make([]byte, 0, (256<<10)+utf8.UTFMax)
	var carry []byte
	var total int64
	var h uint32
	seen := 0

	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)

			chunk := buf[:n]
			if len(carry) > 0 {
				chunk = append(append(make([]byte, 0, len(carry)+n), carry...), chunk...)
			}
			fold, carry = foldBytes(fold[:0], chunk)
			if len(carry) > 0 {
				carry = append(make([]byte, 0, len(carry)), carry...) // buf is reused
			}
			for _, b := range fold {
				h = h<<8 | uint32(b)
				if seen < 2 {
					seen++
					continue
				}
				set.add(h & 0xFFFFFF)
			}
		}
		if rerr != nil {
			if len(carry) > 0 {
				// trailing invalid bytes: fold what is left so nothing is lost
				fold = append(fold[:0], carry...)
				for _, b := range fold {
					h = h<<8 | uint32(b)
					if seen < 2 {
						seen++
						continue
					}
					set.add(h & 0xFFFFFF)
				}
			}
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}

/* ---------- what a query requires ---------- */

// triGroup is a set of trigrams that must *all* be present in a file, plus
// the literal they were derived from, which doubles as a per-line gate.
type triGroup struct {
	tris []uint32
	lit  string // folded; the longest mandatory literal in this group
}

// triQuery is an OR of triGroups: a file is a candidate if any group is
// wholly satisfied. Any means the query yields no usable constraint.
type triQuery struct {
	Any bool
	Ors []triGroup
}

// maxTriGroups bounds the planning work; past it the query is treated as
// unconstrained, which is slower but never wrong.
const maxTriGroups = 32

func triAny() triQuery { return triQuery{Any: true} }

// triFromLiteral requires every trigram of a mandatory substring.
func triFromLiteral(s string) triQuery {
	f := foldString(s)
	if len(f) < 3 {
		return triAny() // nothing to index on
	}
	g := triGroup{lit: f}
	seen := map[uint32]bool{}
	for i := 0; i+3 <= len(f); i++ {
		t := uint32(f[i])<<16 | uint32(f[i+1])<<8 | uint32(f[i+2])
		if !seen[t] {
			seen[t] = true
			g.tris = append(g.tris, t)
		}
	}
	return triQuery{Ors: []triGroup{g}}
}

// triAnd combines two requirements that must both hold. Either side alone is
// a sound filter, so when the cross product would grow too large one side is
// simply dropped.
func triAnd(a, b triQuery) triQuery {
	if a.Any {
		return b
	}
	if b.Any {
		return a
	}
	if len(a.Ors)*len(b.Ors) > maxTriGroups {
		if len(a.Ors) <= len(b.Ors) {
			return a
		}
		return b
	}
	out := triQuery{}
	for _, g1 := range a.Ors {
		for _, g2 := range b.Ors {
			m := triGroup{
				tris: append(append(make([]uint32, 0, len(g1.tris)+len(g2.tris)), g1.tris...), g2.tris...),
				lit:  g1.lit,
			}
			if len(g2.lit) > len(m.lit) {
				m.lit = g2.lit
			}
			out.Ors = append(out.Ors, m)
		}
	}
	return out
}

// triOr combines alternatives: if either side is unconstrained then so is the
// whole, because a file could match through that branch.
func triOr(a, b triQuery) triQuery {
	if a.Any || b.Any {
		return triAny()
	}
	if len(a.Ors)+len(b.Ors) > maxTriGroups {
		return triAny()
	}
	return triQuery{Ors: append(append(make([]triGroup, 0, len(a.Ors)+len(b.Ors)), a.Ors...), b.Ors...)}
}

// gate returns a literal that every matching line must contain, or "" when
// there is none. It exists only when a single group survived: with
// alternatives no one literal is mandatory.
func (q triQuery) gate() string {
	if q.Any || len(q.Ors) != 1 {
		return ""
	}
	if len(q.Ors[0].lit) < 3 {
		return ""
	}
	return q.Ors[0].lit
}

// triFromRegexp derives the trigrams a regex must match. Anything it cannot
// prove is required yields triAny, never a guess.
func triFromRegexp(src string) triQuery {
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return triAny()
	}
	return triFromSyntax(re.Simplify(), 0)
}

func triFromSyntax(re *syntax.Regexp, depth int) triQuery {
	if re == nil || depth > 24 {
		return triAny()
	}
	switch re.Op {
	case syntax.OpLiteral:
		return triFromLiteral(string(re.Rune))

	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return triFromSyntax(re.Sub[0], depth+1)
		}

	case syntax.OpConcat:
		// Adjacent literals are merged first: "10" followed by "\." parses as
		// two literal nodes, and only the joined "10." yields a trigram.
		q := triAny()
		var run []rune
		flush := func() {
			if len(run) > 0 {
				q = triAnd(q, triFromLiteral(string(run)))
				run = run[:0]
			}
		}
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				run = append(run, sub.Rune...)
				continue
			}
			flush()
			q = triAnd(q, triFromSyntax(sub, depth+1))
		}
		flush()
		return q

	case syntax.OpAlternate:
		if len(re.Sub) == 0 {
			return triAny()
		}
		q := triFromSyntax(re.Sub[0], depth+1)
		for _, sub := range re.Sub[1:] {
			if q.Any {
				return q
			}
			q = triOr(q, triFromSyntax(sub, depth+1))
		}
		return q

	case syntax.OpPlus:
		// one or more: whatever the body requires is required at least once
		if len(re.Sub) == 1 {
			return triFromSyntax(re.Sub[0], depth+1)
		}

	case syntax.OpRepeat:
		if re.Min >= 1 && len(re.Sub) == 1 {
			return triFromSyntax(re.Sub[0], depth+1)
		}
	}
	// OpStar, OpQuest, character classes, anchors, OpAnyChar, OpEmptyMatch,
	// zero-width assertions: nothing is required
	return triAny()
}

/* ---------- picking candidate files ---------- */

// candidates returns a per-file mask of the files that could contain a match,
// or nil meaning "no constraint: scan them all".
func (idx *SearchIndex) candidates(tq triQuery) []bool {
	if tq.Any || len(tq.Ors) == 0 {
		return nil
	}
	out := make([]bool, len(idx.Files))
	for _, g := range tq.Ors {
		lists := make([][]int32, 0, len(g.tris))
		absent := false
		for _, t := range g.tris {
			slot, ok := idx.tri[t]
			if !ok {
				absent = true // no file contains this trigram
				break
			}
			if slot == triCommon {
				continue // too common to narrow anything
			}
			lists = append(lists, idx.post[slot])
		}
		if absent {
			continue // this alternative cannot match anywhere
		}
		if len(lists) == 0 {
			return nil // every trigram was common: no constraint at all
		}
		// intersect from the shortest list, so the work is bounded by the
		// rarest trigram rather than the commonest
		sort.Slice(lists, func(i, j int) bool { return len(lists[i]) < len(lists[j]) })
		acc := lists[0]
		for _, l := range lists[1:] {
			acc = intersectSorted(acc, l)
			if len(acc) == 0 {
				break
			}
		}
		for _, fi := range acc {
			if int(fi) < len(out) {
				out[fi] = true
			}
		}
	}
	for _, fi := range idx.alwaysScan {
		if int(fi) < len(out) {
			out[fi] = true
		}
	}
	return out
}

// intersectSorted returns the common members of two sorted lists, into a new
// slice so neither input is disturbed.
func intersectSorted(a, b []int32) []int32 {
	out := make([]int32, 0, minInt(len(a), len(b)))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, a[i])
			i++
			j++
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

/* ---------- the indexed search ---------- */

// SearchIndexed answers a query from the index: candidate files come from the
// trigram postings and are read straight out of the blob, with no gzip and no
// tar walk. It falls back to a full archive scan whenever the index cannot be
// used, so the result is the same either way — only the time differs.
func SearchIndexed(ctx context.Context, idx *SearchIndex, arch io.ReadSeeker, opts SearchOptions) (*SearchOutcome, error) {
	if idx == nil || len(idx.Entries) == 0 {
		return SearchArchive(arch, opts)
	}
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

	blob, err := os.Open(idx.BlobPath)
	if err != nil {
		// the cache is gone (restart, cleanup): correctness first
		return SearchArchive(arch, opts)
	}
	defer blob.Close()

	only := map[string]bool{}
	for _, p := range opts.Paths {
		if p = strings.TrimSpace(p); p != "" {
			only[p] = true
		}
	}

	res := &SearchOutcome{Results: []SearchResult{}, Limit: max, Indexed: true}
	res.noteFilter(q)
	out := res.Results

	cand := idx.candidates(q.Tri)
	gate := []byte(q.Tri.gate())
	res.Candidates = len(idx.Files)
	if cand != nil {
		res.Candidates = 0
		for _, c := range cand {
			if c {
				res.Candidates++
			}
		}
	}

	// Archive order, so filename and line matches interleave exactly as they
	// do in a full scan; only the files that are read differ.
	scratch := make([]byte, 0, 4096)
	for _, e := range idx.Entries {
		if len(out) >= max {
			break
		}
		if err := ctx.Err(); err != nil {
			res.TimedOut = true
			break
		}
		if len(only) > 0 && !only[e.Path] {
			continue
		}
		// a path match is itself a result, but only when unrestricted: inside
		// a chosen file the filename is not interesting
		if len(only) == 0 && q.Match(e.Path) {
			out = append(out, SearchResult{Type: "file", Path: e.Path})
			if len(out) >= max {
				break
			}
		}
		if e.File < 0 || int(e.File) >= len(idx.Files) {
			continue // binary, empty, or read from the archive below
		}
		if cand != nil && !cand[e.File] {
			continue
		}
		f := idx.Files[e.File]
		sec := io.NewSectionReader(blob, f.Off, f.Size)
		br := bufio.NewReaderSize(sec, 256<<10)
		var capped bool
		out, capped, scratch = searchLines(ctx, br, f.Path, q, gate, scratch, before, after, max, out)
		if capped {
			res.CappedFiles = append(res.CappedFiles, f.Path)
		}
		res.Scanned++
	}

	// Files left out of the blob are read from the archive instead. This is
	// the slow path, but it keeps the guarantee that nothing is skipped.
	if len(idx.Unindexed) > 0 && len(out) < max && !res.TimedOut {
		wanted := make([]string, 0, len(idx.Unindexed))
		for _, p := range idx.Unindexed {
			if len(only) == 0 || only[p] {
				wanted = append(wanted, p)
			}
		}
		if len(wanted) > 0 {
			sub, serr := SearchArchive(arch, SearchOptions{
				Query: opts.Query, Paths: wanted, Before: before, After: after,
				MaxResults: max - len(out),
			})
			if serr == nil {
				out = append(out, sub.Results...)
				res.CappedFiles = append(res.CappedFiles, sub.CappedFiles...)
			}
		}
	}

	res.Results = out
	res.Truncated = len(out) >= max
	return res, nil
}
