package parser

import "testing"

// A regex containing the characters that double as boolean operators must
// survive the tokenizer. Bare terms are compiled as regexes, but '(', ')', '|'
// and '!' are operators, so an unquoted (?:a|b)\d+ was torn into a group
// containing an OR of two words and never reached regexp.Compile — the search
// then returned nothing and looked as though regexes were unsupported.
func TestSlashDelimitedRegexIsNotTokenized(t *testing.T) {
	q := ParseSearchQuery(`/(?:alpha|beta)\d+[Ss]/`)
	for _, line := range []string{"alpha42S", "beta7s", "xx beta007S yy"} {
		if !q.root.match(line) {
			t.Errorf("%q should match the regex", line)
		}
	}
	for _, line := range []string{"alpha", "beta", "gamma42S", "alphaS"} {
		if q.root.match(line) {
			t.Errorf("%q should not match", line)
		}
	}
}

// The same pattern without delimiters is the boolean reading, and both are
// legitimate — which is why the user has to say which one they mean.
func TestBareParenPipeStaysBoolean(t *testing.T) {
	q := ParseSearchQuery(`(alpha|beta)`)
	if !q.root.match("beta only") {
		t.Error("the boolean reading should still OR the two words")
	}
}

func TestRegexTermCaseInsensitive(t *testing.T) {
	q := ParseSearchQuery(`/GATEWAY \w+ failed/`)
	if !q.root.match("gateway login failed") {
		t.Error("regex terms match case-insensitively, like bare terms")
	}
}

// A slash that is not opening a regex — a path fragment — must still search.
func TestUnterminatedSlashIsALiteralPath(t *testing.T) {
	q := ParseSearchQuery(`var/log/pan`)
	if !q.root.match("reading var/log/pan/ms.log") {
		t.Error("a path with slashes should search as a word, not a broken regex")
	}
}

// An escaped slash belongs to the pattern rather than closing it.
func TestEscapedSlashInsideRegex(t *testing.T) {
	q := ParseSearchQuery(`/\d+\/\d+ bytes/`)
	if !q.root.match("sent 12/34 bytes") {
		t.Error(`\/ should be a literal slash inside the pattern`)
	}
}

// Regex terms combine with the boolean operators around them.
func TestRegexTermCombinesWithBooleans(t *testing.T) {
	q := ParseSearchQuery(`/tunnel|gateway/ && failed`)
	if !q.root.match("gateway handshake failed") {
		t.Error("a regex term should AND with a following word")
	}
	if q.root.match("gateway handshake ok") {
		t.Error("the AND arm must still be required")
	}
}

// An explicit regex that does not compile must not lose the query.
func TestBrokenRegexDegradesToLiteral(t *testing.T) {
	q := ParseSearchQuery(`/[unclosed/`)
	if !q.root.match("an [unclosed bracket") {
		t.Error("a broken regex should fall back to a literal match")
	}
}

// -A/-B/-C used to be clamped to 30 silently, so a larger request looked
// ignored rather than limited.
func TestContextFlagsAcceptLargeValues(t *testing.T) {
	if got := ParseSearchQuery("pkt_recv -A 200").After; got != 200 {
		t.Errorf("-A 200 gave After=%d, want 200", got)
	}
	if got := ParseSearchQuery("pkt_recv -C 1000").Before; got != 1000 {
		t.Errorf("-C 1000 gave Before=%d, want 1000", got)
	}
	if got := ParseSearchQuery("pkt_recv -A 99999").After; got != maxContextLines {
		t.Errorf("-A 99999 gave After=%d, want the ceiling %d", got, maxContextLines)
	}
	if maxContextLines < 1000 {
		t.Errorf("the context ceiling is %d; it should allow at least 1000", maxContextLines)
	}
}
