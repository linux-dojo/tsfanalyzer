// Package parser: config.go extracts the PAN-OS configuration from a
// tech-support archive as a generic XML tree.
//
// The PAN-OS config schema is deeply nested but very regular: almost
// everything is a repeated <entry name="..."> list under a section tag
// (<security>, <address>, <zone>, ...), and policy rulebases add one more
// <rules> wrapper around their entries. Rather than hand-writing a Go
// struct per object/policy type (there are dozens across Policies /
// Objects / Network / Device), this keeps the full tree generic and lets
// the frontend walk it the same way a user would click through the
// firewall's own tabs.
//
// Finding the file is not as simple as looking for "running-config.xml".
// A Panorama-managed device keeps several configs side by side under
// /opt/pancfg/mgmt (the local running config, the pushed shared policy,
// the merged config, dated snapshots), and which one is present varies by
// platform and PAN-OS version. So every .xml under that directory is
// considered, largest first, on the reasoning that the biggest file is the
// most complete view of what the device is actually running.
package parser

import (
	"archive/tar"
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"sort"
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

// ConfigCandidate is one XML file that could hold the configuration.
// Reported back so the UI can explain itself when nothing usable is found.
type ConfigCandidate struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Picked bool   `json:"picked"`
	Reason string `json:"reason,omitempty"` // why it was rejected
}

// ConfigDoc is the chosen configuration plus where it came from.
//
// Root is populated on demand rather than retained after parsing: a
// Panorama merged config is tens of megabytes of XML, which becomes a very
// large pointer-heavy tree, and holding one per uploaded file was enough to
// exhaust the API container. The archive is already on disk, so the tree is
// rebuilt per request and discarded.
type ConfigDoc struct {
	Root *ConfigNode `json:"root,omitempty"`
	Path string      `json:"path"`
	Size int64       `json:"size"`
	// PanoramaManaged is set when the config carries Panorama fingerprints:
	// pre/post rulebases, device groups or templates.
	PanoramaManaged bool              `json:"panorama_managed"`
	Markers         []string          `json:"markers,omitempty"` // which fingerprints were seen
	Candidates      []ConfigCandidate `json:"candidates"`
}

var ErrNoConfig = errors.New("no PAN-OS config XML found in archive")

var (
	// the directory a PAN-OS device keeps its configurations in
	mgmtDirRe = regexp.MustCompile(`(?i)(^|/)opt/pancfg/mgmt/`)
	// well-known names, used to break ties and as a fallback outside the mgmt dir
	configNameRe = regexp.MustCompile(`(?i)(running|candidate|merged|pushed|panorama)[-_]?.*config.*\.xml$|mergesp\.xml$`)
)

const (
	sniffBytes    = 4096      // enough to reach past any XML decl/comment to the root tag
	maxConfigSize = 192 << 20 // ignore implausibly large "config" candidates
	maxTries      = 8         // bound the work when an archive has many XML files
)

// ExtractConfig locates the device configuration and returns it as a
// generic node tree. Candidates are ranked: XML under /opt/pancfg/mgmt
// largest-first, then well-known config names elsewhere, then anything
// else whose root element is <config>. The first candidate that parses
// into a <config> tree wins.
func ExtractConfig(r io.ReadSeeker) (*ConfigDoc, error) {
	all, err := listXMLCandidates(r)
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, ErrNoConfig
	}

	ranked := rankConfigCandidates(all)

	doc := &ConfigDoc{Candidates: make([]ConfigCandidate, 0, len(ranked))}
	tried := 0
	for i := range ranked {
		c := ranked[i]
		if c.Size <= 0 || c.Size > maxConfigSize {
			c.Reason = "size out of range"
			doc.Candidates = append(doc.Candidates, c)
			continue
		}
		if tried >= maxTries {
			c.Reason = "not attempted"
			doc.Candidates = append(doc.Candidates, c)
			continue
		}
		tried++

		data, rerr := readEntry(r, c.Path)
		if rerr != nil {
			c.Reason = "unreadable: " + rerr.Error()
			doc.Candidates = append(doc.Candidates, c)
			continue
		}
		if root := sniffRootTag(data); root != "config" {
			c.Reason = "root element is <" + root + ">, not <config>"
			doc.Candidates = append(doc.Candidates, c)
			continue
		}
		c.Picked = true
		doc.Candidates = append(doc.Candidates, c)
		doc.Path, doc.Size = c.Path, c.Size
		// scanned on the raw bytes so no tree has to be built or retained
		doc.Markers = panoramaMarkersInBytes(data)
		doc.PanoramaManaged = len(doc.Markers) > 0
		// record the rest as unattempted, for diagnostics
		for j := i + 1; j < len(ranked); j++ {
			rest := ranked[j]
			rest.Reason = "not needed"
			doc.Candidates = append(doc.Candidates, rest)
		}
		return doc, nil
	}
	return nil, ErrNoConfig
}

// listXMLCandidates walks the archive once and notes every .xml file.
func listXMLCandidates(r io.ReadSeeker) ([]ConfigCandidate, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	var out []ConfigCandidate
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break // tolerate trailing corruption; use what we have
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		p := normalizePath(hdr.Name)
		if !strings.HasSuffix(strings.ToLower(p), ".xml") {
			continue
		}
		out = append(out, ConfigCandidate{Path: p, Size: hdr.Size})
	}
	return out, nil
}

// rankConfigCandidates orders candidates by how likely they are to be the
// device configuration: inside /opt/pancfg/mgmt first (largest first, since
// the biggest file is the most complete config), then recognizable config
// names elsewhere, then everything else largest-first.
func rankConfigCandidates(in []ConfigCandidate) []ConfigCandidate {
	tier := func(c ConfigCandidate) int {
		switch {
		case mgmtDirRe.MatchString(c.Path):
			return 0
		case configNameRe.MatchString(c.Path):
			return 1
		default:
			return 2
		}
	}
	out := make([]ConfigCandidate, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		ti, tj := tier(out[i]), tier(out[j])
		if ti != tj {
			return ti < tj
		}
		if out[i].Size != out[j].Size {
			return out[i].Size > out[j].Size // largest first
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// readEntry pulls one file's bytes out of the archive.
func readEntry(r io.ReadSeeker, path string) ([]byte, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	entry, err := EntryReader(r, path)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(entry)
}

/* ---------- Panorama fingerprints ---------- */

// panoramaMarkerTags are elements that only appear once a device is managed
// by Panorama: pushed policy lands in pre/post rulebases, and device-group
// or template metadata comes down with it.
var panoramaMarkerTags = []string{
	"pre-rulebase", "post-rulebase", "device-group", "template-stack", "template", "panorama",
}

// panoramaMarkersInBytes reports which Panorama fingerprints appear in the
// raw config XML. Scanning bytes avoids building a tree just to answer this.
func panoramaMarkersInBytes(data []byte) []string {
	var out []string
	for _, t := range panoramaMarkerTags {
		if bytes.Contains(data, []byte("<"+t+">")) || bytes.Contains(data, []byte("<"+t+" ")) {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// ParseConfigTree reads one config file out of the archive and parses it.
// Called per request so the tree is transient rather than retained.
func ParseConfigTree(r io.ReadSeeker, path string) (*ConfigNode, error) {
	data, err := readEntry(r, path)
	if err != nil {
		return nil, err
	}
	return parseConfigXML(data)
}

/* ---------- XML decoding ---------- */

// sniffRootTag returns the local name of the first start element found in
// data, or "" if none is found. Used to identify config files without
// paying for a full tree decode on every XML file in the archive.
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
