package parser

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"strings"
)

// ArchiveEntry is one regular file inside the tech-support archive.
type ArchiveEntry struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

var ErrEntryNotFound = errors.New("file not found in archive")

// normalizePath strips "./" and leading "/" so paths are stable lookup keys.
func normalizePath(name string) string {
	name = strings.TrimPrefix(name, "./")
	return strings.TrimPrefix(name, "/")
}

// maxInflatedBytes caps how much a single archive may decompress to.
//
// Gzip reaches ratios of roughly 1000:1 on repetitive input, so the 512 MiB
// upload limit bounds only the bytes on the wire — not the bytes produced.
// A 10 MiB file of zeroes inflates to about 10 GiB, and every pass that walks
// the tar would decompress all of it: the index pass has to inflate content
// merely to skip past it and reach the next header.
//
// This is generous against real archives. The largest tech-support file seen
// is a little over 4 GiB inflated, so 32 GiB is a backstop against a
// deliberately hostile upload rather than a working limit.
const maxInflatedBytes = 32 << 30

// ErrArchiveTooLarge means the archive decompressed past maxInflatedBytes.
var ErrArchiveTooLarge = errors.New("archive decompresses to more than the supported size")

// limitedReader fails the whole read once n bytes have been produced.
//
// io.LimitedReader reports io.EOF at the limit, which every caller here would
// read as "the archive ended normally" — a bomb would look like a short but
// valid file. This reports a distinguishable error instead.
type limitedReader struct {
	r io.Reader
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, ErrArchiveTooLarge
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// openTar opens the archive as gzip-compressed tar, falling back to a plain
// uncompressed tar (some tools produce .tgz files that are not gzipped).
//
// The decompressed stream is capped: see maxInflatedBytes. Capping here rather
// than in each caller means every pass — index, search blob, counters, config,
// signatures, GP — inherits the protection, and a pass added later cannot
// forget it.
func openTar(r io.ReadSeeker) (*tar.Reader, error) {
	if gz, err := gzip.NewReader(r); err == nil {
		return tar.NewReader(&limitedReader{r: gz, n: maxInflatedBytes}), nil
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	// An uncompressed tar cannot exceed the stored file, which the upload
	// limit already bounds, so it needs no wrapper.
	return tar.NewReader(r), nil
}

// IndexArchive lists every regular file in the archive, whatever its name or
// extension (.log, .log.old, log.1, extensionless, ...). A read error after
// some entries were already indexed is tolerated (truncated/trailing-garbage
// archives are common); the partial index is returned.
func IndexArchive(r io.ReadSeeker) ([]ArchiveEntry, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	var out []ArchiveEntry
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if len(out) > 0 {
				return out, nil // keep what we have
			}
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		p := normalizePath(hdr.Name)
		if p == "" {
			continue
		}
		out = append(out, ArchiveEntry{Path: p, Size: hdr.Size})
	}
	return out, nil
}

// EntryReader returns a reader positioned at the named file inside the archive.
// The returned reader is only valid while r remains open.
func EntryReader(r io.ReadSeeker, path string) (io.Reader, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, ErrEntryNotFound
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeReg && normalizePath(hdr.Name) == path {
			return tr, nil
		}
	}
}
