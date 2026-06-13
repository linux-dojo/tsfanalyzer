package parser

import (
	"archive/tar"
	"bufio"
	"bytes"
	"io"
	"strings"
)

// SearchResult is one hit from an archive-wide search: either a filename
// match ("file") or a content match ("line").
type SearchResult struct {
	Type   string `json:"type"` // file | line
	Path   string `json:"path"`
	LineNo int    `json:"line_no,omitempty"`
	Text   string `json:"text,omitempty"`
}

const maxLineHitsPerFile = 20

// SearchArchive scans the whole archive for the query (case-insensitive),
// matching both file paths and log lines, up to maxResults hits.
func SearchArchive(r io.ReadSeeker, query string, maxResults int) ([]SearchResult, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(query)
	var out []SearchResult

	for len(out) < maxResults {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break // tolerate trailing corruption: return what we found
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		p := normalizePath(hdr.Name)
		if p == "" {
			continue
		}

		if strings.Contains(strings.ToLower(p), q) {
			out = append(out, SearchResult{Type: "file", Path: p})
			if len(out) >= maxResults {
				break
			}
		}

		// content scan; skip binary-looking files
		br := bufio.NewReaderSize(tr, 64*1024)
		if peek, _ := br.Peek(512); bytes.IndexByte(peek, 0) >= 0 {
			continue
		}
		sc := bufio.NewScanner(br)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		lineNo, hits := 0, 0
		for sc.Scan() && hits < maxLineHitsPerFile && len(out) < maxResults {
			lineNo++
			line := sc.Text()
			if !strings.Contains(strings.ToLower(line), q) {
				continue
			}
			txt := strings.TrimSpace(line)
			if len(txt) > 240 {
				txt = txt[:240] + "…"
			}
			out = append(out, SearchResult{Type: "line", Path: p, LineNo: lineNo, Text: txt})
			hits++
		}
	}
	return out, nil
}
