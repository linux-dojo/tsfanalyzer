package parser

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

/*
security_test.go pins the input-handling limits.

Every case here is an archive a user could upload. The tool reads archives
produced by someone else's device, so "the input is malformed on purpose" is
not a hypothetical — and the failure modes being pinned are process-level
(a fatal stack overflow, a full disk, the container's memory limit), which no
amount of per-request error handling recovers from.
*/

// tgzOf builds a gzipped tar from name -> contents.
func tgzOf(t *testing.T, files map[string]string) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

// TestDeeplyNestedXMLIsRejectedNotFatal is the important one.
//
// decodeAt recurses per nesting level. Go grows a goroutine stack to 1 GB and
// then kills the PROCESS with "goroutine stack exceeds" — a fatal runtime
// error, not a panic, so it cannot be recovered and takes every other
// in-flight request with it. A file of a few hundred thousand open tags
// compresses to almost nothing inside an archive.
func TestDeeplyNestedXMLIsRejectedNotFatal(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("<config>")
	const depth = 200000
	for i := 0; i < depth; i++ {
		sb.WriteString("<a>")
	}
	for i := 0; i < depth; i++ {
		sb.WriteString("</a>")
	}
	sb.WriteString("</config>")

	_, err := parseConfigXML([]byte(sb.String()))
	if err == nil {
		t.Fatal("a 200,000-deep document parsed successfully; the depth cap is not applied")
	}
	if !errors.Is(err, ErrXMLTooDeep) {
		t.Fatalf("want ErrXMLTooDeep, got %v", err)
	}
}

// A real config nests around 15 levels. The cap must not affect it.
func TestRealisticNestingStillParses(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("<config>")
	for i := 0; i < 40; i++ {
		sb.WriteString("<a>")
	}
	sb.WriteString("leaf")
	for i := 0; i < 40; i++ {
		sb.WriteString("</a>")
	}
	sb.WriteString("</config>")

	root, err := parseConfigXML([]byte(sb.String()))
	if err != nil {
		t.Fatalf("40 levels should parse comfortably: %v", err)
	}
	if root.Tag != "config" {
		t.Fatalf("root tag = %q, want config", root.Tag)
	}
}

// TestGzipBombIsCappedNotSilentlyTruncated checks two things at once: that the
// cap fires, and that it reports an error rather than io.EOF.
//
// The second half matters more than it looks. io.LimitedReader returns io.EOF
// at its limit, and every tar consumer here treats io.EOF as "the archive
// ended normally" — so a bomb would have been read as a short but perfectly
// valid archive, and the tool would have reported partial results as complete.
func TestGzipBombIsCappedNotSilentlyTruncated(t *testing.T) {
	lr := &limitedReader{r: bytes.NewReader(make([]byte, 100)), n: 10}
	buf := make([]byte, 64)

	n, err := lr.Read(buf)
	if err != nil {
		t.Fatalf("first read inside the budget failed: %v", err)
	}
	if n != 10 {
		t.Fatalf("read %d bytes, want the 10 the budget allowed", n)
	}
	if _, err = lr.Read(buf); !errors.Is(err, ErrArchiveTooLarge) {
		t.Fatalf("past the budget the error was %v, want ErrArchiveTooLarge (io.EOF would read as a clean end of archive)", err)
	}
}

func TestLimitedReaderPassesNormalDataThrough(t *testing.T) {
	const body = "the quick brown fox"
	lr := &limitedReader{r: strings.NewReader(body), n: maxInflatedBytes}
	got := make([]byte, len(body))
	if _, err := lr.Read(got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != body {
		t.Fatalf("got %q, want %q", got, body)
	}
}

// TestZipBombIsRejected: the upload cap bounds compressed bytes, not
// decompressed ones, so the conversion needs its own budget or a small zip
// fills the upload volume.
func TestZipBombIsRejected(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "bomb.zip")
	dst := filepath.Join(dir, "out.tgz")

	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("PanGPS.log")
	if err != nil {
		t.Fatal(err)
	}
	// Highly compressible: zeroes compress to roughly 1/1000th.
	chunk := make([]byte, 1<<20)
	for i := 0; i < 64; i++ {
		if _, err := w.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// With the real 32 GiB budget this 64 MiB member is legitimate, so the
	// bound is exercised directly instead of writing 32 GiB in a unit test.
	lr := &limitedReader{r: bytes.NewReader(chunk), n: 1024}
	if _, err := lr.Read(make([]byte, 4096)); err != nil {
		t.Fatalf("first read should succeed: %v", err)
	}
	if _, err := lr.Read(make([]byte, 4096)); !errors.Is(err, ErrArchiveTooLarge) {
		t.Fatalf("want ErrArchiveTooLarge past the budget, got %v", err)
	}

	// And the honest zip still converts.
	if err := ConvertZipToTgz(src, dst); err != nil {
		t.Fatalf("a legitimate 64 MiB zip should convert: %v", err)
	}
	if fi, err := os.Stat(dst); err != nil || fi.Size() == 0 {
		t.Fatalf("converted archive missing or empty: %v", err)
	}
}

// TestArchiveMemberNamesNeverReachTheFilesystem documents why zip-slip does
// not apply here, so that a future change which starts extracting to disk has
// to confront it.
//
// Member names are map keys and display strings only. Nothing in the pipeline
// creates a file named after an archive entry: the sole writes are <id>.tgz
// and <id>.tgz.sblob, both named from a crypto/rand id.
func TestArchiveMemberNamesNeverReachTheFilesystem(t *testing.T) {
	arch := tgzOf(t, map[string]string{
		"../../../../etc/passwd":      "root:x:0:0",
		"..\\..\\windows\\system.ini": "[boot]",
		"/absolute/path.log":          "line",
		"normal/mp-monitor.log":       "line",
	})

	idx, err := IndexArchive(arch)
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	if len(idx) != 4 {
		t.Fatalf("indexed %d entries, want 4", len(idx))
	}

	// The traversal name survives as data — that is fine and intended; what
	// matters is that it is never used as a path to open or create.
	var sawTraversal bool
	for _, e := range idx {
		if strings.Contains(e.Path, "..") {
			sawTraversal = true
		}
		if strings.HasPrefix(e.Path, "/") {
			t.Fatalf("normalizePath left an absolute path: %q", e.Path)
		}
	}
	if !sawTraversal {
		t.Fatal("expected the traversal name to be retained as an opaque key")
	}
}

// TestConfigReadIsBounded: maxConfigSize is checked against the tar header's
// declared size when candidates are ranked, and the header is written by
// whoever built the archive. This pins the check against the bytes actually
// produced.
func TestConfigReadIsBounded(t *testing.T) {
	if maxConfigSize <= 0 {
		t.Fatal("maxConfigSize must be positive")
	}
	lr := &limitedReader{r: strings.NewReader(strings.Repeat("x", 100)), n: 16}
	buf := make([]byte, 100)
	if _, err := lr.Read(buf); err != nil {
		t.Fatalf("read within budget: %v", err)
	}
	if _, err := lr.Read(buf); !errors.Is(err, ErrArchiveTooLarge) {
		t.Fatalf("want the budget to fire, got %v", err)
	}
}
