// Package parser: appstats.go builds per-application traffic statistics from
// the dataplane's own accounting rather than from a single CLI snapshot.
//
// Two pieces are joined:
//
//   - The "--- panio_infreq" block in dp-monitor.log* carries the per-app
//     table keyed by numeric application ID, repeated over time, so it gives
//     a time series rather than one instant.
//   - The content database at opt/pancfg/mgmt/updates/curcontent/.../global.xml
//     maps those IDs to application names (<entry name="ibm-tsm" id="109">).
//
// The mapping file is not always collected. When it is missing the IDs are
// still reported, labelled "app-<id>", so the table remains usable — just
// without friendly names.
package parser

import (
	"archive/tar"
	"bufio"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

/* ---------- application ID -> name ---------- */

var (
	// The installed content DB lives at
	// opt/pancfg/mgmt/updates/curcontent/global/global.xml; the previously
	// installed version sits alongside it under oldcontent. Both are matched
	// but curcontent wins, so a stale mapping never shadows the current one.
	appIDCurRe = regexp.MustCompile(`(?i)(^|/)updates/curcontent/.*global\.xml$`)
	appIDOldRe = regexp.MustCompile(`(?i)(^|/)updates/oldcontent/.*global\.xml$`)
	// last resort: any other global.xml under an updates/content directory
	appIDAnyRe = regexp.MustCompile(`(?i)(^|/)(updates|content)/.*global\.xml$`)

	// <entry name="ibm-tsm" id="109">  — attribute order is not guaranteed,
	// so both orders are matched
	appEntryNameFirstRe = regexp.MustCompile(`<entry\s+name="([^"]+)"\s+id="(\d+)"`)
	appEntryIDFirstRe   = regexp.MustCompile(`<entry\s+id="(\d+)"\s+name="([^"]+)"`)
)

const maxAppIDFileBytes = 512 << 20

// ExtractAppIDs returns the application ID to name mapping from the content
// database. A missing file is not an error: an empty map means callers fall
// back to numeric labels.
func ExtractAppIDs(r io.ReadSeeker) (map[int]string, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	// tier 0 = curcontent (installed), 1 = oldcontent, 2 = anything else.
	// The archive is walked once and the best tier found is used; a lower
	// tier is only consulted when nothing better was present.
	best := 99
	byTier := map[int]map[int]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break // tolerate trailing corruption
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size <= 0 || hdr.Size > maxAppIDFileBytes {
			continue
		}
		p := normalizePath(hdr.Name)
		tier := -1
		switch {
		case appIDCurRe.MatchString(p):
			tier = 0
		case appIDOldRe.MatchString(p):
			tier = 1
		case appIDAnyRe.MatchString(p):
			tier = 2
		}
		if tier < 0 {
			continue
		}
		if byTier[tier] == nil {
			byTier[tier] = map[int]string{}
		}
		scanAppIDs(tr, byTier[tier])
		if tier < best {
			best = tier
		}
	}
	if best == 99 {
		return map[int]string{}, nil
	}
	return byTier[best], nil
}

// AppIDSource names the content DB tier that was used, for display.
func AppIDSource(path string) string {
	switch {
	case appIDCurRe.MatchString(path):
		return "curcontent"
	case appIDOldRe.MatchString(path):
		return "oldcontent"
	default:
		return "content"
	}
}

// scanAppIDs reads the content DB line by line. The file can be tens of
// megabytes, so it is scanned with regexes rather than decoded into a tree.
func scanAppIDs(r io.Reader, out map[int]string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "<entry") || !strings.Contains(line, "id=") {
			continue
		}
		for _, m := range appEntryNameFirstRe.FindAllStringSubmatch(line, -1) {
			if id, err := strconv.Atoi(m[2]); err == nil {
				if _, seen := out[id]; !seen {
					out[id] = m[1]
				}
			}
		}
		for _, m := range appEntryIDFirstRe.FindAllStringSubmatch(line, -1) {
			if id, err := strconv.Atoi(m[1]); err == nil {
				if _, seen := out[id]; !seen {
					out[id] = m[2]
				}
			}
		}
	}
}

// AppLabel names an application ID, falling back to "app-<id>" when the
// content database was not collected.
func AppLabel(id int, names map[int]string) string {
	if n, ok := names[id]; ok && n != "" {
		return n
	}
	return "app-" + strconv.Itoa(id)
}

/* ---------- AppStats derived from the counter series ---------- */

// appStatsCounterRe matches the counters emitted from the panio_infreq block,
// e.g. dp__appstats__vsys1_ssl_bytes.
var appStatsCounterRe = regexp.MustCompile(`^(mp|dp)__appstats__vsys([^_]+)_(.+)_(sessions|packets|bytes|app_changed|threats)$`)

// AppStatsFromSeries rebuilds the application table from the collected
// counters, using each application's most recent sample. The counters are
// cumulative, so the latest value is the volume to date; the series itself
// remains available for graphing the trend.
func AppStatsFromSeries(series Series, plane string) *AppStats {
	type key struct{ vsys, app string }
	acc := map[key]*AppStat{}
	var order []key

	for name, pts := range series {
		m := appStatsCounterRe.FindStringSubmatch(name)
		if m == nil || m[1] != plane || len(pts) == 0 {
			continue
		}
		vsys, app, metric := m[2], m[3], m[4]
		k := key{vsys, app}
		st, ok := acc[k]
		if !ok {
			st = &AppStat{App: app, Vsys: vsys}
			acc[k] = st
			order = append(order, k)
		}
		latest := pts[len(pts)-1].Value // cumulative: newest sample is the total
		switch metric {
		case "sessions":
			st.Sessions = latest
		case "packets":
			st.Packets = latest
		case "bytes":
			st.Bytes = latest
		case "app_changed":
			st.AppChanged = latest
		case "threats":
			st.Threats = latest
		}
	}
	if len(order) == 0 {
		return nil
	}

	out := &AppStats{Rows: make([]AppStat, 0, len(order)), Vsyses: []string{}}
	seenVsys := map[string]bool{}
	sort.Slice(order, func(i, j int) bool {
		if order[i].vsys != order[j].vsys {
			return order[i].vsys < order[j].vsys
		}
		return order[i].app < order[j].app
	})
	for _, k := range order {
		st := acc[k]
		out.Rows = append(out.Rows, *st)
		if !seenVsys[st.Vsys] {
			seenVsys[st.Vsys] = true
			out.Vsyses = append(out.Vsyses, st.Vsys)
		}
	}
	finalizeAppStats(out)
	return out
}

// finalizeAppStats computes the totals, each row's share of them, and the
// per-session ratios. Shared by both sources so the two agree.
func finalizeAppStats(out *AppStats) {
	out.TotalSessions, out.TotalPackets, out.TotalBytes = 0, 0, 0
	out.TotalAppChanged, out.TotalThreats = 0, 0
	for _, r := range out.Rows {
		out.TotalSessions += r.Sessions
		out.TotalPackets += r.Packets
		out.TotalBytes += r.Bytes
		out.TotalAppChanged += r.AppChanged
		out.TotalThreats += r.Threats
	}
	for i := range out.Rows {
		r := &out.Rows[i]
		r.SessionsPct = pct(r.Sessions, out.TotalSessions)
		r.PacketsPct = pct(r.Packets, out.TotalPackets)
		r.BytesPct = pct(r.Bytes, out.TotalBytes)
		r.AppChangedPct = pct(r.AppChanged, out.TotalAppChanged)
		r.ThreatsPct = pct(r.Threats, out.TotalThreats)
		r.PacketsPerSession = ratio(r.Packets, r.Sessions)
		r.BytesPerSession = ratio(r.Bytes, r.Sessions)
		r.AvgPacketSize = ratio(r.Bytes, r.Packets)
	}
}
