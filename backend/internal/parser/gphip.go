// Package parser: gphip.go reads the HIP report the GlobalProtect agent sends
// to the gateway after every tunnel comes up.
//
// # Getting hold of it
//
// The agent writes the report into PanGPS.log twice. The first copy is emitted
// in chunks tagged "HipMissingPatchReport.txt_output:", and those chunks are
// split at arbitrary byte offsets — mid-attribute, even mid-word
// ("…name="Windows Firewall" versi" / "on="10.0.19041.6328"…"). Reassembling
// them is possible but fragile. The second copy is bracketed cleanly:
//
//	---------------Full hip report ---------
//	<?xml version="1.0" encoding="UTF-8"?> … </hip-report>
//	---------------End of full hip report ---------
//
// so that is what is used, taking the last such block since it corresponds to
// the most recent submission. When the log has none, the standalone
// pan_gp_hrpt.xml in the bundle is used instead — it can be older, so it is
// only a fallback.
//
// # Shape of the output
//
// The report is deeply nested and every category has a different shape. Rather
// than force one schema onto all of them, the categories are read into the few
// tables that matter — products, missing patches, interfaces — and *also*
// flattened into (category, item, field, value) rows. The flat rows are what
// makes a single search box able to match a product version, a MAC address, a
// KB number or an encryption state without the user knowing where each lives.
package parser

import (
	"archive/tar"
	"bufio"
	"encoding/xml"
	"io"
	"sort"
	"strings"
	"time"
)

/* ---------- model ---------- */

// HIPRow is one fact from the report, flattened so every field is searchable.
type HIPRow struct {
	Category string `json:"category"`
	Item     string `json:"item,omitempty"`
	Field    string `json:"field"`
	Value    string `json:"value"`
}

// HIPProduct is one security product the endpoint reported.
type HIPProduct struct {
	Category string `json:"category"`
	Vendor   string `json:"vendor,omitempty"`
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	// anti-malware specifics
	DefVersion    string `json:"def_version,omitempty"`
	EngineVersion string `json:"engine_version,omitempty"`
	DefDate       string `json:"def_date,omitempty"`
	RealTime      string `json:"real_time_protection,omitempty"`
	LastScan      string `json:"last_full_scan,omitempty"`
	// firewall / patch-management
	Enabled string `json:"enabled,omitempty"`
	// disk-backup
	LastBackup string `json:"last_backup,omitempty"`
	// disk-encryption: one line per drive, kept together for display
	Drives []HIPDrive `json:"drives,omitempty"`
}

type HIPDrive struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// HIPPatch is one entry from the missing-patches list.
type HIPPatch struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
	KB          string `json:"kb,omitempty"`
	Bulletin    string `json:"bulletin,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Category    string `json:"category,omitempty"`
	Installed   string `json:"installed,omitempty"`
}

// HIPInterface is one network adapter as the report saw it.
type HIPInterface struct {
	ID          string   `json:"id,omitempty"`
	Description string   `json:"description,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	IPv4        []string `json:"ipv4,omitempty"`
	IPv6        []string `json:"ipv6,omitempty"`
}

// HIPReport is a parsed HIP report.
type HIPReport struct {
	GeneratedAt string `json:"generated_at,omitempty"`
	Version     string `json:"version,omitempty"`
	Source      string `json:"source,omitempty"` // where it was read from

	ClientVersion string `json:"client_version,omitempty"`
	OS            string `json:"os,omitempty"`
	OSVendor      string `json:"os_vendor,omitempty"`
	Domain        string `json:"domain,omitempty"`
	HostName      string `json:"host_name,omitempty"`
	HostID        string `json:"host_id,omitempty"`
	UserName      string `json:"user_name,omitempty"`
	IPAddress     string `json:"ip_address,omitempty"`

	Products   []HIPProduct   `json:"products"`
	Patches    []HIPPatch     `json:"patches"`
	Interfaces []HIPInterface `json:"interfaces"`
	// Categories the report carried but that held nothing, which is itself
	// worth seeing: an empty data-loss-prevention list means no product found.
	EmptyCategories []string `json:"empty_categories,omitempty"`
	Rows            []HIPRow `json:"rows"`
}

/* ---------- a small generic XML tree ---------- */

type xnode struct {
	name  string
	attrs map[string]string
	text  string
	kids  []*xnode
}

func (n *xnode) child(name string) *xnode {
	for _, k := range n.kids {
		if k.name == name {
			return k
		}
	}
	return nil
}

func (n *xnode) children(name string) []*xnode {
	var out []*xnode
	for _, k := range n.kids {
		if k.name == name {
			out = append(out, k)
		}
	}
	return out
}

func (n *xnode) txt(name string) string {
	if c := n.child(name); c != nil {
		return strings.TrimSpace(c.text)
	}
	return ""
}

// parseXNode decodes arbitrary XML into a tree. The HIP report mixes attributes
// and elements freely and varies by category, so a generic tree is more robust
// than a struct per shape.
func parseXNode(r io.Reader) (*xnode, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	var root *xnode
	var stack []*xnode
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// tolerate a truncated tail: return what was built
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &xnode{name: t.Name.Local, attrs: map[string]string{}}
			for _, a := range t.Attr {
				n.attrs[a.Name.Local] = a.Value
			}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.kids = append(parent.kids, n)
			} else if root == nil {
				root = n
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text += string(t)
			}
		}
	}
	if root == nil {
		return nil, io.ErrUnexpectedEOF
	}
	return root, nil
}

/* ---------- locating the report ---------- */

const (
	hipFullStart = "---------------Full hip report ---------"
	hipFullEnd   = "---------------End of full hip report ---------"
)

// ExtractHIPReport returns the most recent HIP report in the collection.
func ExtractHIPReport(r io.ReadSeeker) (*HIPReport, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}

	best := struct {
		xml string
		age int
		src string
	}{age: 1 << 30}
	var standalone string

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := strings.ToLower(baseName(hdr.Name))
		switch {
		case strings.HasPrefix(base, "pangps") && strings.HasSuffix(base, ".log"):
			age := rotationIndex(base)
			if x := lastFullHIPBlock(tr); x != "" && age <= best.age {
				// a newer file wins; within one file the last block already won
				best.xml, best.age, best.src = x, age, baseName(hdr.Name)
			}
		case strings.HasSuffix(base, "hrpt.xml"), base == "hipreport.xml":
			if b, rerr := io.ReadAll(io.LimitReader(tr, 16<<20)); rerr == nil {
				standalone = string(b)
			}
		}
	}

	raw, src := best.xml, best.src
	if raw == "" {
		raw, src = standalone, "pan_gp_hrpt.xml"
	}
	if strings.TrimSpace(raw) == "" {
		return nil, ErrEntryNotFound
	}
	rep := parseHIPReport(raw)
	rep.Source = src
	return rep, nil
}

// lastFullHIPBlock returns the final complete "Full hip report" block in a log.
// Only the bracketed copy is used: the chunked one is split at arbitrary byte
// offsets, sometimes inside an attribute value.
func lastFullHIPBlock(r io.Reader) string {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	var cur strings.Builder
	var last string
	collecting := false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.Contains(line, hipFullStart):
			collecting = true
			cur.Reset()
		case strings.Contains(line, hipFullEnd):
			if collecting && strings.Contains(cur.String(), "</hip-report>") {
				last = cur.String()
			}
			collecting = false
		case collecting:
			// the log prefixes each line; the XML itself starts at the first
			// '<' on the line that opens the document
			cur.WriteString(stripLogPrefix(line))
			cur.WriteByte('\n')
		}
	}
	return last
}

// stripLogPrefix removes a "(Pn-Tn)Dump ( 204): dd/mm/yy hh:mm:ss:mmm " prefix
// when the line carries one, leaving the payload untouched otherwise.
func stripLogPrefix(line string) string {
	if m := gpTraceLineRe.FindStringSubmatch(line); m != nil {
		return m[8]
	}
	if m := gpCpLineRe.FindStringSubmatch(line); m != nil {
		return m[8]
	}
	return line
}

/* ---------- parsing ---------- */

func parseHIPReport(raw string) *HIPReport {
	rep := &HIPReport{
		Products:   []HIPProduct{},
		Patches:    []HIPPatch{},
		Interfaces: []HIPInterface{},
		Rows:       []HIPRow{},
	}
	// drop anything before the declaration or root element
	if i := strings.Index(raw, "<hip-report"); i > 0 {
		raw = raw[i:]
	}
	root, err := parseXNode(strings.NewReader(raw))
	if err != nil || root == nil {
		return rep
	}

	rep.GeneratedAt = root.txt("generate-time")
	rep.Version = root.txt("hip-report-version")
	rep.UserName = root.txt("user-name")
	rep.IPAddress = root.txt("ip-address")
	if rep.HostName == "" {
		rep.HostName = root.txt("host-name")
	}

	cats := root.child("categories")
	if cats == nil {
		return rep
	}
	for _, cat := range cats.children("entry") {
		name := cat.attrs["name"]
		switch name {
		case "host-info":
			rep.readHostInfo(cat)
		default:
			rep.readProductCategory(name, cat)
		}
	}

	rep.buildRows()
	return rep
}

func (rep *HIPReport) readHostInfo(cat *xnode) {
	rep.ClientVersion = cat.txt("client-version")
	rep.OS = cat.txt("os")
	rep.OSVendor = cat.txt("os-vendor")
	rep.Domain = cat.txt("domain")
	if v := cat.txt("host-name"); v != "" {
		rep.HostName = v
	}
	rep.HostID = cat.txt("host-id")

	if ni := cat.child("network-interface"); ni != nil {
		for _, e := range ni.children("entry") {
			iface := HIPInterface{
				ID:          e.attrs["name"],
				Description: e.txt("description"),
				MAC:         e.txt("mac-address"),
			}
			if v4 := e.child("ip-address"); v4 != nil {
				for _, a := range v4.children("entry") {
					if a.attrs["name"] != "" {
						iface.IPv4 = append(iface.IPv4, a.attrs["name"])
					}
				}
			}
			if v6 := e.child("ipv6-address"); v6 != nil {
				for _, a := range v6.children("entry") {
					if a.attrs["name"] != "" {
						iface.IPv6 = append(iface.IPv6, a.attrs["name"])
					}
				}
			}
			rep.Interfaces = append(rep.Interfaces, iface)
		}
	}
}

// readProductCategory handles every non-host category. They share the
// list/entry/ProductInfo/Prod skeleton and differ only in which extra elements
// sit beside Prod, so the differences are read opportunistically.
func (rep *HIPReport) readProductCategory(name string, cat *xnode) {
	found := 0
	if list := cat.child("list"); list != nil {
		for _, e := range list.children("entry") {
			pi := e.child("ProductInfo")
			if pi == nil {
				continue
			}
			prod := pi.child("Prod")
			p := HIPProduct{Category: name}
			if prod != nil {
				p.Vendor = prod.attrs["vendor"]
				p.Name = prod.attrs["name"]
				p.Version = prod.attrs["version"]
				p.DefVersion = prod.attrs["defver"]
				p.EngineVersion = prod.attrs["engver"]
				if y, mo, d := prod.attrs["dateyear"], prod.attrs["datemon"], prod.attrs["dateday"]; y != "" {
					p.DefDate = y + "-" + pad2(mo) + "-" + pad2(d)
				}
			}
			p.RealTime = pi.txt("real-time-protection")
			p.LastScan = pi.txt("last-full-scan-time")
			p.Enabled = pi.txt("is-enabled")
			p.LastBackup = pi.txt("last-backup-time")
			if dr := pi.child("drives"); dr != nil {
				for _, d := range dr.children("entry") {
					p.Drives = append(p.Drives, HIPDrive{
						Name:  d.txt("drive-name"),
						State: d.txt("enc-state"),
					})
				}
			}
			if p.Name != "" {
				rep.Products = append(rep.Products, p)
				found++
			}
		}
	}

	if mp := cat.child("missing-patches"); mp != nil {
		for _, e := range mp.children("entry") {
			rep.Patches = append(rep.Patches, HIPPatch{
				Title:       e.txt("title"),
				Description: e.txt("description"),
				Vendor:      e.txt("vendor"),
				KB:          e.txt("kb-article-id"),
				Bulletin:    e.txt("security-bulletin-id"),
				Severity:    e.txt("severity"),
				Category:    e.txt("category"),
				Installed:   e.txt("is-installed"),
			})
			found++
		}
	}

	if found == 0 {
		rep.EmptyCategories = append(rep.EmptyCategories, name)
	}
}

func pad2(s string) string {
	if len(s) == 1 {
		return "0" + s
	}
	return s
}

// buildRows flattens everything into searchable rows. One search box then
// covers a product version, a MAC address, a KB number or a drive state
// without the user needing to know which table holds it.
func (rep *HIPReport) buildRows() {
	add := func(cat, item, field, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		rep.Rows = append(rep.Rows, HIPRow{Category: cat, Item: item, Field: field, Value: value})
	}

	add("report", "", "generated", rep.GeneratedAt)
	add("report", "", "report version", rep.Version)
	add("report", "", "source", rep.Source)
	add("host-info", "", "client-version", rep.ClientVersion)
	add("host-info", "", "os", rep.OS)
	add("host-info", "", "os-vendor", rep.OSVendor)
	add("host-info", "", "domain", rep.Domain)
	add("host-info", "", "host-name", rep.HostName)
	add("host-info", "", "host-id", rep.HostID)
	add("host-info", "", "user-name", rep.UserName)
	add("host-info", "", "ip-address", rep.IPAddress)

	for _, i := range rep.Interfaces {
		item := i.Description
		if item == "" {
			item = i.ID
		}
		add("network-interface", item, "adapter id", i.ID)
		add("network-interface", item, "mac-address", i.MAC)
		for _, a := range i.IPv4 {
			add("network-interface", item, "ipv4", a)
		}
		for _, a := range i.IPv6 {
			add("network-interface", item, "ipv6", a)
		}
	}

	for _, p := range rep.Products {
		add(p.Category, p.Name, "vendor", p.Vendor)
		add(p.Category, p.Name, "version", p.Version)
		add(p.Category, p.Name, "definition version", p.DefVersion)
		add(p.Category, p.Name, "engine version", p.EngineVersion)
		add(p.Category, p.Name, "definition date", p.DefDate)
		add(p.Category, p.Name, "real-time protection", p.RealTime)
		add(p.Category, p.Name, "last full scan", p.LastScan)
		add(p.Category, p.Name, "enabled", p.Enabled)
		add(p.Category, p.Name, "last backup", p.LastBackup)
		for _, d := range p.Drives {
			add(p.Category, p.Name, "drive "+d.Name, d.State)
		}
	}

	for _, q := range rep.Patches {
		item := q.Title
		add("missing-patch", item, "category", q.Category)
		add("missing-patch", item, "severity", q.Severity)
		add("missing-patch", item, "kb-article-id", q.KB)
		add("missing-patch", item, "security-bulletin-id", q.Bulletin)
		add("missing-patch", item, "vendor", q.Vendor)
		add("missing-patch", item, "installed", q.Installed)
		add("missing-patch", item, "description", q.Description)
	}

	for _, c := range rep.EmptyCategories {
		add(c, "", "products found", "none")
	}

	sort.SliceStable(rep.Rows, func(i, j int) bool {
		if rep.Rows[i].Category != rep.Rows[j].Category {
			return rep.Rows[i].Category < rep.Rows[j].Category
		}
		return rep.Rows[i].Item < rep.Rows[j].Item
	})
}

// HIPGeneratedTime parses the report's own timestamp, for comparing it against
// the tunnel that submitted it — a report generated long before the connection
// is a stale one.
func HIPGeneratedTime(rep *HIPReport) (time.Time, bool) {
	if rep == nil || rep.GeneratedAt == "" {
		return time.Time{}, false
	}
	t, err := time.Parse("01/02/2006 15:04:05", strings.TrimSpace(rep.GeneratedAt))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
