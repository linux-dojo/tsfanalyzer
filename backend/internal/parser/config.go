// Package parser: config.go extracts the running (or candidate) PAN-OS
// configuration from a tech-support archive as a generic XML tree.
//
// The PAN-OS config schema is deeply nested but very regular: almost
// everything is a repeated <entry name="..."> list under a section tag
// (<security>, <address>, <zone>, ...), and policy rulebases add one more
// <rules> wrapper around their entries. Rather than hand-writing a Go
// struct per object/policy type (there are dozens across Policies /
// Objects / Network / Device), this keeps the full tree generic and lets
// the frontend walk it the same way a user would click through the
// firewall's own tabs.
package parser

import (
	"archive/tar"
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strings"
)

// ConfigNode is one generic XML element: its tag name, attributes, any
// direct text, and its child elements in document order. The PAN-OS
// config is fully reconstructable from this shape, and it serializes to
// JSON exactly as-is for the frontend to search and render.
type ConfigNode struct {
	Tag      string            `json:"tag"`
	Attrs    map[string]string `json:"attrs,omitempty"`
	Text     string            `json:"text,omitempty"`
	Children []*ConfigNode     `json:"children,omitempty"`
}

var ErrNoConfig = errors.New("no PAN-OS config XML found in archive")

// configNameRe matches the well-known config file names PAN-OS
// tech-support bundles use ("running-config.xml", "candidate-config.xml",
// and similar), wherever in the archive they live.
var configNameRe = regexp.MustCompile(`(?i)(running|candidate)[-_]?config.*\.xml$`)

const (
	sniffBytes    = 4096     // enough to reach past any XML decl/comment to the root tag
	maxConfigSize = 96 << 20 // ignore implausibly large "config" candidates
)

// ExtractConfig scans the archive for the PAN-OS configuration and returns
// it as a generic node tree rooted at <config>. Files named like
// "running-config.xml" are preferred (favoring one with "running" in the
// name over "candidate"); if none are found by name, any .xml file whose
// root element is literally "config" is used as a fallback, since some
// platforms/versions place the file at a different path.
func ExtractConfig(r io.ReadSeeker) (*ConfigNode, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}

	var byName []byte
	var byNamePreferred bool // true once byName came from a "*running*" file
	var byRoot []byte

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break // tolerate trailing corruption; use whatever we already found
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := normalizePath(hdr.Name)
		if !strings.HasSuffix(strings.ToLower(name), ".xml") {
			continue
		}
		if hdr.Size <= 0 || hdr.Size > maxConfigSize {
			continue
		}

		nameMatch := configNameRe.MatchString(name)
		if !nameMatch && byRoot != nil {
			// Already have a root-tag fallback; skip reading files that
			// don't look like a config by name since we no longer need one.
			continue
		}

		data, rerr := io.ReadAll(tr)
		if rerr != nil {
			continue
		}

		if nameMatch {
			preferred := strings.Contains(strings.ToLower(name), "running")
			if byName == nil || (preferred && !byNamePreferred) {
				byName, byNamePreferred = data, preferred
			}
			continue
		}

		if byRoot == nil && sniffRootTag(data) == "config" {
			byRoot = data
		}
	}

	data := byName
	if data == nil {
		data = byRoot
	}
	if data == nil {
		return nil, ErrNoConfig
	}
	return parseConfigXML(data)
}

// sniffRootTag returns the local name of the first start element found in
// data, or "" if none is found. Used to identify config files that weren't
// named like one, without paying for a full tree decode on every XML file
// in the archive.
func sniffRootTag(data []byte) string {
	limit := data
	if len(limit) > sniffBytes {
		limit = limit[:sniffBytes]
	}
	dec := xml.NewDecoder(bytes.NewReader(limit))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		if se, ok := tok.(xml.StartElement); ok {
			return se.Name.Local
		}
	}
}

func parseConfigXML(data []byte) (*ConfigNode, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok {
			root := &ConfigNode{}
			if err := root.decode(dec, se); err != nil {
				return nil, err
			}
			return root, nil
		}
	}
}

// decode fills n from start and consumes tokens up to and including the
// matching end element, recursing into children.
func (n *ConfigNode) decode(dec *xml.Decoder, start xml.StartElement) error {
	n.Tag = start.Name.Local
	if len(start.Attr) > 0 {
		n.Attrs = make(map[string]string, len(start.Attr))
		for _, a := range start.Attr {
			n.Attrs[a.Name.Local] = a.Value
		}
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			child := &ConfigNode{}
			// xml.Decoder reuses its internal attribute storage between
			// tokens, so the start element must be copied before recursing.
			if err := child.decode(dec, t.Copy()); err != nil {
				return err
			}
			n.Children = append(n.Children, child)
		case xml.CharData:
			if s := strings.TrimSpace(string(t)); s != "" {
				if n.Text != "" {
					n.Text += " "
				}
				n.Text += s
			}
		case xml.EndElement:
			return nil
		}
	}
}
