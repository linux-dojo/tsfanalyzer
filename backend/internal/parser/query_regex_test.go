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

// The reported failure, end to end.
//
// "^\s*enforcer exception IPv4 ..." returned nothing, and the reason was not
// the regex engine: a line on disk reads
//
//	P 823-T4099  08/24/2026 11:47:16:126 Info ( 224): enforcer exception IPv4 8.8.8.8 - 8.8.8.8
//
// so "^" is anchored to the process id, not to the text. grep would return
// nothing too. An anchored pattern therefore gets a second attempt against the
// line with its log prefix removed.
func TestAnchoredRegexMatchesPastTheLogPrefix(t *testing.T) {
	pattern := `/^\s*enforcer exception IPv4 \d{1,3}(?:\.\d{1,3}){3} - \d{1,3}(?:\.\d{1,3}){3}$/`
	q := ParseSearchQuery(pattern)
	for name, line := range map[string]string{
		"macOS":   "p 823-t4099  08/24/2026 11:47:16:126 info ( 224): enforcer exception ipv4 8.8.8.8 - 8.8.8.8",
		"trace":   "(p11496-t6520)info (11298): 08/18/26 13:55:40:474 enforcer exception ipv4 255.255.192.0 - 255.255.255.255",
		"captive": "(p11496-t14080)debug08/18/26 09:41:41:742 (152): enforcer exception ipv4 255.252.0.0 - 255.255.255.255",
		"event":   "08/18/2026 13:55:40:423 [info ]: enforcer exception ipv4 255.254.0.0 - 255.255.255.255",
		"driver":  "08/24/2026 11:47:13.455179[info   318]: enforcer exception ipv4 255.255.255.255 - 255.255.255.255",
	} {
		if !q.root.match(line) {
			t.Errorf("%s format: anchored pattern did not reach past the log prefix", name)
		}
	}
}

// The fallback must not turn an anchored pattern into a substring search.
func TestAnchoredRegexStillDiscriminates(t *testing.T) {
	q := ParseSearchQuery(`/^\s*enforcer exception IPv4 \d{1,3}(?:\.\d{1,3}){3} - \d{1,3}(?:\.\d{1,3}){3}$/`)
	for _, line := range []string{
		"p 823-t4099  08/24/2026 11:47:16:126 info ( 224): enforcer exception: no app list defined.",
		"(p11496-t6520)info (11298): 08/18/26 13:55:40:474 st,set enforcer exclude route 8.8.8.8/32",
		"p 823-t4099  08/24/2026 11:47:16:126 info ( 224): trailing text enforcer exception ipv4 8.8.8.8 - 8.8.8.8 more",
		"2026-06-09 11:27:40.087 -0700  --- panio",
	} {
		if q.root.match(line) {
			t.Errorf("should not match: %q", line)
		}
	}
}

// The prefix stripper runs on a case-folded line, so it cannot require the
// uppercase "P"/"-T" the parsing patterns use. Reusing those patterns here
// silently disabled the whole fallback.
func TestStripFoldedLogPrefixIsCaseInsensitive(t *testing.T) {
	line := "p 823-t4099  08/24/2026 11:47:16:126 info ( 224): enforcer exception ipv4 8.8.8.8 - 8.8.8.8"
	msg, ok := stripFoldedLogPrefix(line)
	if !ok {
		t.Fatal("a lower-cased agent line should still have its prefix recognised")
	}
	if msg != "enforcer exception ipv4 8.8.8.8 - 8.8.8.8" {
		t.Errorf("stripped to %q", msg)
	}
	if _, ok := stripFoldedLogPrefix("2026-06-09 11:27:40.087 -0700  --- panio"); ok {
		t.Error("a monitor line has no agent prefix to strip")
	}
}

// An unanchored pattern keeps plain whole-line semantics, so the extra work is
// confined to the case that needs it.
func TestUnanchoredRegexIsNotGivenTheFallback(t *testing.T) {
	q := ParseSearchQuery(`/enforcer exception ipv4/`)
	if !q.root.match("p 823-t4099  08/24/2026 11:47:16:126 info ( 224): enforcer exception ipv4 8.8.8.8 - 8.8.8.8") {
		t.Error("an unanchored pattern should match the whole line as before")
	}
}
