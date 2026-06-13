// Package parser contains the regex-based extractors that pull values of
// interest out of Palo Alto tech-support archives. Each section of the file
// gets its own extractor so new ones can be added without touching the rest.
package parser

import (
	"archive/tar"
	"bufio"
	"errors"
	"io"
	"regexp"
	"strings"
)

// KV is one parsed "key: value" line. Order is preserved as found in the file.
type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

var (
	ErrNoSystemInfo = errors.New("no 'show system info' section found in archive")

	// .txt files under tmp/cli/ anywhere in the archive (entries may or may
	// not carry a leading "./" or other prefix).
	cliTxtRe = regexp.MustCompile(`(?:^|/)tmp/cli/[^/]+\.txt$`)

	// The CLI command header line, e.g. "> show system info" or
	// "--- show system info ---".
	cmdRe = regexp.MustCompile(`\bshow\s+system\s+info\b`)

	// A "key: value" line. Keys are lowercase words joined by dashes/underscores.
	kvRe = regexp.MustCompile(`^([A-Za-z0-9_-]+):\s*(.*)$`)
)

const (
	startKey = "hostname"
	endKey   = "device-certificate-status"
)

// ExtractSystemInfo streams a tech-support archive and returns the key/value
// block of the "show system info" output, from "hostname:" through
// "device-certificate-status:" inclusive.
func ExtractSystemInfo(r io.ReadSeeker) ([]KV, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg || !cliTxtRe.MatchString(hdr.Name) {
			continue
		}
		if kv := scanSystemInfo(tr); len(kv) > 0 {
			return kv, nil
		}
	}
	return nil, ErrNoSystemInfo
}

// scanSystemInfo reads one CLI dump and returns the system-info block, or nil.
func scanSystemInfo(r io.Reader) []KV {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	inSection := false
	collecting := false
	var out []KV

	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))

		if !inSection {
			if cmdRe.MatchString(line) {
				inSection = true
			}
			continue
		}

		m := kvRe.FindStringSubmatch(line)

		if !collecting {
			if m != nil && m[1] == startKey {
				collecting = true
				out = append(out, KV{Key: m[1], Value: m[2]})
			} else if cmdRe.MatchString(line) {
				// a second occurrence of the command; stay in section
				continue
			}
			continue
		}

		if m == nil {
			// tolerate blank/continuation lines inside the block
			if line == "" {
				continue
			}
			// non key:value content ends the block
			break
		}
		out = append(out, KV{Key: m[1], Value: m[2]})
		if m[1] == endKey {
			return out
		}
	}
	// Reached EOF (or block end) without the end key: accept what we have
	// only if it looks like a real block.
	if collecting && len(out) > 3 {
		return out
	}
	return nil
}
