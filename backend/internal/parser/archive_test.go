package parser

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
	"time"
)

func buildMultiTgz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(content))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestIndexArchive(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"./var/log/pan/ms.log":     "a",
		"var/log/system.log.old":   "bb",
		"opt/pancfg/mgmt/saved/x":  "ccc",
		"tmp/cli/techsupport.txt":  "dddd",
		"var/log/dp-log/dp.log.1":  "e",
	})
	idx, err := IndexArchive(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if len(idx) != 5 {
		t.Fatalf("got %d entries, want 5", len(idx))
	}
	for _, e := range idx {
		if strings.HasPrefix(e.Path, "./") || strings.HasPrefix(e.Path, "/") {
			t.Fatalf("path not normalized: %q", e.Path)
		}
	}
}

func TestEntryReader(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"var/log/a.log": "hello-a",
		"var/log/b.log": "hello-b",
	})
	er, err := EntryReader(bytes.NewReader(tgz), "var/log/b.log")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(er)
	if string(data) != "hello-b" {
		t.Fatalf("got %q", data)
	}
	if _, err := EntryReader(bytes.NewReader(tgz), "var/log/missing.log"); err != ErrEntryNotFound {
		t.Fatalf("expected ErrEntryNotFound, got %v", err)
	}
}

func TestFilterLines(t *testing.T) {
	logText := `2026-06-09 10:00:00 first line
continuation of first
2026-06-09 11:00:00 second line
Jun  9 11:30:00 syslog style line
2026-06-09 12:00:00 third line
`
	from, _ := time.Parse("2006-01-02 15:04:05", "2026-06-09 10:30:00")
	to, _ := time.Parse("2006-01-02 15:04:05", "2026-06-09 11:45:00")

	var out bytes.Buffer
	if err := FilterLines(strings.NewReader(logText), &out, from, to); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(got, "first line") || strings.Contains(got, "third line") {
		t.Fatalf("out-of-range lines kept:\n%s", got)
	}
	if !strings.Contains(got, "second line") || !strings.Contains(got, "syslog style line") {
		t.Fatalf("in-range lines missing:\n%s", got)
	}
}

func TestFilterLinesContinuationInherits(t *testing.T) {
	logText := `2026-06-09 11:00:00 parent
  child continuation line
2026-06-09 13:00:00 outside
`
	from, _ := time.Parse("2006-01-02 15:04:05", "2026-06-09 10:00:00")
	to, _ := time.Parse("2006-01-02 15:04:05", "2026-06-09 12:00:00")
	var out bytes.Buffer
	if err := FilterLines(strings.NewReader(logText), &out, from, to); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "child continuation") {
		t.Fatalf("continuation line dropped:\n%s", out.String())
	}
	if strings.Contains(out.String(), "outside") {
		t.Fatalf("out-of-range line kept:\n%s", out.String())
	}
}
