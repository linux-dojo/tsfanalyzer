// Package parser: cli.go pulls structured data out of the CLI dump that a
// tech-support archive keeps at tmp/cli/<name>.txt — the file containing the
// output of dozens of "> show ..." commands run at collection time.
//
// Two sections are extracted here: the per-application traffic table from
// "show running application statistics", and the installed licences from
// "request license info".
package parser

import (
	"archive/tar"
	"bufio"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrNoAppStats = errors.New("no 'show running application statistics' output found in archive")
	ErrNoLicenses = errors.New("no 'request license info' output found in archive")

	// a CLI command echo: "> show running application statistics"
	cliCmdRe = regexp.MustCompile(`^>\s+(.*\S)\s*$`)
)

/* ---------- application statistics ---------- */

// AppStat is one application's traffic, with the shares and per-session
// figures derived from it.
type AppStat struct {
	App  string `json:"app"`
	Vsys string `json:"vsys"`

	Sessions   float64 `json:"sessions"`
	Packets    float64 `json:"packets"`
	Bytes      float64 `json:"bytes"`
	AppChanged float64 `json:"app_changed"`
	Threats    float64 `json:"threats"`

	// share of the totals, as percentages
	SessionsPct   float64 `json:"sessions_pct"`
	PacketsPct    float64 `json:"packets_pct"`
	BytesPct      float64 `json:"bytes_pct"`
	AppChangedPct float64 `json:"app_changed_pct"`
	ThreatsPct    float64 `json:"threats_pct"`

	// derived ratios
	PacketsPerSession float64 `json:"packets_per_session"`
	BytesPerSession   float64 `json:"bytes_per_session"`
	AvgPacketSize     float64 `json:"avg_packet_size"`
}

// AppStats is the whole table plus the totals the shares are computed from.
type AppStats struct {
	Rows   []AppStat `json:"rows"`
	Vsyses []string  `json:"vsyses"`

	// which output the table came from, and whether numeric application IDs
	// could be resolved to names (the content DB is not always collected)
	Source        string `json:"source"`
	NamesResolved bool   `json:"names_resolved"`

	TotalSessions   float64 `json:"total_sessions"`
	TotalPackets    float64 `json:"total_packets"`
	TotalBytes      float64 `json:"total_bytes"`
	TotalAppChanged float64 `json:"total_app_changed"`
	TotalThreats    float64 `json:"total_threats"`

	// what the device itself printed on the Total line, kept so a mismatch
	// with our own sum is visible rather than hidden
	ReportedSessions float64 `json:"reported_sessions"`
	ReportedPackets  float64 `json:"reported_packets"`
	ReportedBytes    float64 `json:"reported_bytes"`
}

var (
	appStatsCmdRe = regexp.MustCompile(`(?i)^show running application statistics`)
	vsysLineRe    = regexp.MustCompile(`(?i)^Vsys:\s*(\S+)`)
	dashesRe      = regexp.MustCompile(`^[- ]+$`)
)

// ExtractAppStats finds the application statistics table in the CLI dump.
func ExtractAppStats(r io.ReadSeeker) (*AppStats, error) {
	body, err := cliSection(r, appStatsCmdRe)
	if err != nil {
		return nil, err
	}
	return parseAppStats(body), nil
}

// parseAppStats reads the table body. Columns are not sliced by position:
// an application name longer than the header's column width shifts the
// numbers right (e.g. "paloalto-userid-agent 1  26 ..."), and a name may
// itself contain a "(report-as)" part. The five trailing numeric fields are
// therefore taken from the end, and whatever precedes them is the name.
func parseAppStats(lines []string) *AppStats {
	out := &AppStats{Rows: []AppStat{}, Vsyses: []string{}}
	vsys := ""
	seenVsys := map[string]bool{}

	for _, raw := range lines {
		line := strings.TrimRight(raw, " \t")
		if strings.TrimSpace(line) == "" || dashesRe.MatchString(line) {
			continue
		}
		if m := vsysLineRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			vsys = m[1]
			if !seenVsys[vsys] {
				seenVsys[vsys] = true
				out.Vsyses = append(out.Vsyses, vsys)
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "number of apps") || strings.HasPrefix(lower, "app (report-as)") {
			continue
		}

		f := strings.Fields(trimmed)
		if len(f) < 6 {
			continue
		}
		nums, ok := trailingNumbers(f, 5)
		if !ok {
			continue
		}
		name := strings.Join(f[:len(f)-5], " ")

		if strings.EqualFold(name, "Total") {
			out.ReportedSessions, out.ReportedPackets, out.ReportedBytes = nums[0], nums[1], nums[2]
			continue
		}
		out.Rows = append(out.Rows, AppStat{
			App: name, Vsys: vsys,
			Sessions: nums[0], Packets: nums[1], Bytes: nums[2],
			AppChanged: nums[3], Threats: nums[4],
		})
	}

	// totals are summed from the rows rather than trusted from the Total line,
	// so the percentages always add up to 100
	finalizeAppStats(out)
	return out
}

// trailingNumbers parses the last n fields as numbers.
func trailingNumbers(f []string, n int) ([]float64, bool) {
	if len(f) < n+1 {
		return nil, false
	}
	out := make([]float64, n)
	for i := 0; i < n; i++ {
		v, err := strconv.ParseFloat(f[len(f)-n+i], 64)
		if err != nil {
			return nil, false
		}
		out[i] = v
	}
	return out, true
}

func pct(v, total float64) float64 {
	if total <= 0 {
		return 0
	}
	return v / total * 100
}

func ratio(a, b float64) float64 {
	if b <= 0 {
		return 0
	}
	return a / b
}

/* ---------- licences ---------- */

// License is one "License entry:" block from "request license info".
type License struct {
	Feature     string `json:"feature"`
	Description string `json:"description"`
	Serial      string `json:"serial"`
	Authcode    string `json:"authcode,omitempty"`
	Issued      string `json:"issued,omitempty"`
	Expires     string `json:"expires,omitempty"`
	Expired     string `json:"expired,omitempty"`
	BaseLicense string `json:"base_license,omitempty"`
	Other       []KV   `json:"other,omitempty"` // any field not modelled above
}

var (
	licenseCmdRe   = regexp.MustCompile(`(?i)^request license info`)
	licenseEntryRe = regexp.MustCompile(`(?i)^License entry:`)
	licenseKvRe    = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9 ?/_-]*?):\s*(.*)$`)
)

// ExtractLicenses returns every licence installed on the device.
func ExtractLicenses(r io.ReadSeeker) ([]License, error) {
	body, err := cliSection(r, licenseCmdRe)
	if err != nil {
		return nil, err
	}
	return parseLicenses(body), nil
}

func parseLicenses(lines []string) []License {
	out := []License{}
	var cur *License
	flush := func() {
		if cur != nil && (cur.Feature != "" || cur.Description != "") {
			out = append(out, *cur)
		}
		cur = nil
	}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if licenseEntryRe.MatchString(line) {
			flush()
			cur = &License{}
			continue
		}
		if cur == nil {
			continue
		}
		m := licenseKvRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, val := strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
		switch strings.ToLower(key) {
		case "feature":
			cur.Feature = val
		case "description":
			cur.Description = val
		case "serial":
			cur.Serial = val
		case "authcode":
			cur.Authcode = val
		case "issued":
			cur.Issued = val
		case "expires":
			cur.Expires = val
		case "expired?", "expired":
			cur.Expired = val
		case "base license":
			cur.BaseLicense = val
		default:
			cur.Other = append(cur.Other, KV{Key: key, Value: val})
		}
	}
	flush()
	return out
}

/* ---------- CLI dump plumbing ---------- */

// cliSection returns the lines that follow the first command matching cmdRe,
// up to the next command echo. The CLI dump is a sequence of "> command"
// blocks, so a section ends where the next one begins.
func cliSection(r io.ReadSeeker, cmdRe *regexp.Regexp) ([]string, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break // tolerate trailing corruption
		}
		if hdr.Typeflag != tar.TypeReg || !cliTxtRe.MatchString(normalizePath(hdr.Name)) {
			continue
		}
		if body := scanCLISection(tr, cmdRe); len(body) > 0 {
			return body, nil
		}
	}
	return nil, errors.New("command output not found in the CLI dump")
}

func scanCLISection(r io.Reader, cmdRe *regexp.Regexp) []string {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []string
	inSection := false
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if m := cliCmdRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			if inSection {
				break // next command: this section is done
			}
			if cmdRe.MatchString(m[1]) {
				inSection = true
			}
			continue
		}
		if inSection {
			out = append(out, line)
		}
	}
	return out
}
