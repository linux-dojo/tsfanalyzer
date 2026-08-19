// Package parser: zip.go accepts the other container the tool is handed.
//
// A firewall tech-support file is always a gzipped tar. A GlobalProtect agent
// collection is a .zip on Windows (GlobalProtectLogs_<user>_<stamp>.zip) and a
// .tgz elsewhere. Rather than teach the index, the search blob, the entry
// reader and every parser to speak a second container format, a .zip is
// converted to .tar.gz once at upload. Everything downstream stays unchanged
// and there is only one code path to reason about.
package parser

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"strings"
)

// ErrNotZip means the file is not a zip archive, so no conversion applies.
var ErrNotZip = errors.New("not a zip archive")

// LooksLikeZip reports whether a file begins with the zip local-file header.
// The extension is not trusted: what matters is what the bytes are.
func LooksLikeZip(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	// "PK\x03\x04" for a normal archive; the empty and spanned variants are
	// included so an odd-but-valid zip is still recognised
	return magic[0] == 'P' && magic[1] == 'K' &&
		(magic[2] == 3 || magic[2] == 5 || magic[2] == 7)
}

// ConvertZipToTgz rewrites a zip archive as a gzipped tar at dst. Directory
// entries are dropped (the tar consumers only look at regular files), and a
// member that cannot be read is skipped rather than failing the whole upload:
// a single unreadable log should not cost the user the other twenty-five.
func ConvertZipToTgz(src, dst string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return ErrNotZip
	}
	defer zr.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)

	written := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := normalizePath(strings.ReplaceAll(f.Name, `\`, "/"))
		if name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		rc, oerr := f.Open()
		if oerr != nil {
			continue // unreadable member: keep the rest
		}
		hdr := &tar.Header{
			Name:    name,
			Mode:    0o644,
			Size:    int64(f.UncompressedSize64),
			ModTime: f.Modified,
		}
		if werr := tw.WriteHeader(hdr); werr != nil {
			rc.Close()
			return werr
		}
		n, cerr := io.Copy(tw, rc)
		rc.Close()
		if cerr != nil {
			return cerr
		}
		if n != hdr.Size {
			// The declared size and the actual bytes disagree; the tar stream
			// is now inconsistent and cannot be salvaged.
			return errors.New("zip member " + name + " was shorter than declared")
		}
		written++
	}

	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if written == 0 {
		return errors.New("zip archive contains no files")
	}
	return nil
}
