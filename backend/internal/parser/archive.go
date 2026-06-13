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

// openTar opens the archive as gzip-compressed tar, falling back to a plain
// uncompressed tar (some tools produce .tgz files that are not gzipped).
func openTar(r io.ReadSeeker) (*tar.Reader, error) {
	if gz, err := gzip.NewReader(r); err == nil {
		return tar.NewReader(gz), nil
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
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
