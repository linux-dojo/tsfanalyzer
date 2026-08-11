// Package parser: anomalies.go turns the PAN-OS system log (typically
// tmp/cli/logs/show_log_system.txt in a tech-support archive) into a short
// list of recurring events — "OSPF neighbor down happened 14 times",
// "LACP down happened 3 times" — instead of hundreds of near-identical
// lines. The same underlying issue rarely logs with identical text (the
// IP, interface, or peer name differs each time), so lines are grouped
// either by a recognized event type (OSPF/LACP/HA/BFD/VPN/...) or, for
// anything not specifically recognized, by a normalized template with the
// variable parts (IPs, ports, interface names, ...) blanked out.
package parser

import (
	"archive/tar"
	"bufio"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// AnomalyEvent is one parsed line from the PAN-OS system log.
type AnomalyEvent struct {
	Ts          time.Time
	Severity    string
	Subtype     string
	Description string
}

// AnomalyOccurrence is a single firing of a grouped event: when it
// happened plus the original, un-normalized log text. The raw description
// is kept per occurrence (not just one sample per group) so clicking a
// point on the graph can show exactly which file/neighbor/tunnel that
// specific incident was about.
type AnomalyOccurrence struct {
	Ts          time.Time `json:"ts"`
	Description string    `json:"description"`
}

// AnomalyGroup is every system-log line recognized as the same underlying
// issue, counted and timestamped together so the frontend can graph when
// it occurred.
type AnomalyGroup struct {
	Label       string              `json:"label"`
	Severity    string              `json:"severity"` // worst severity seen across the group
	Subtype     string              `json:"subtype"`
	Count       int                 `json:"count"`
	Sample      string              `json:"sample"` // one representative raw description
	Occurrences []AnomalyOccurrence `json:"occurrences"`
}

var ErrNoSystemLog = errors.New("no PAN-OS system log (show_log_system) found in archive")

// sysLogLineRe matches one "show log system" line:
//
//	2026/08/04 21:00:20 medium   general   general   0  Failed to check ...
//
// columns are receive-time, severity, subtype, object, an event/session
// number (not currently used), and the free-text description.
var sysLogLineRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s+\S+\s+\d+\s+(.*)$`)

// ExtractAnomalies scans the archive for the system log and returns
// recurring events grouped and sorted by how often they occurred (most
// frequent first).
func ExtractAnomalies(r io.ReadSeeker) ([]AnomalyGroup, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	var events []AnomalyEvent
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break // tolerate trailing corruption; use whatever was found
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.ToLower(normalizePath(hdr.Name))
		if !strings.HasSuffix(name, ".txt") || !strings.Contains(name, "show_log_system") {
			continue
		}
		found = true
		events = append(events, parseSystemLogEvents(tr)...)
	}
	if !found {
		return nil, ErrNoSystemLog
	}
	return GroupAnomalies(events), nil
}

func parseSystemLogEvents(r io.Reader) []AnomalyEvent {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []AnomalyEvent
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		m := sysLogLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ts, err := time.Parse("2006/01/02 15:04:05", m[1])
		if err != nil {
			continue
		}
		out = append(out, AnomalyEvent{
			Ts:          ts,
			Severity:    strings.ToLower(m[2]),
			Subtype:     strings.ToLower(m[3]),
			Description: strings.TrimSpace(m[4]),
		})
	}
	return out
}

/* ---------- noise filtering ---------- */

// noisePatterns match routine, expected-to-repeat chatter that never
// indicates a problem worth surfacing (e.g. successful periodic
// reconnects to update servers, which vary only by IP/port/conn-id and
// otherwise say nothing useful). Extend this list as more noisy patterns
// turn up in real archives.
var noisePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^successfully connect(ed)? to (address|server|host)\b`),
	regexp.MustCompile(`(?i)^successfully (resolved|downloaded|updated|sent)\b`),
}

func isNoise(desc string) bool {
	for _, re := range noisePatterns {
		if re.MatchString(desc) {
			return true
		}
	}
	return false
}

/* ---------- known-event classification ---------- */

type knownPattern struct {
	label string
	re    *regexp.Regexp
}

// knownPatterns give a clean, recognizable label to the event categories
// that come up most often in firewall troubleshooting, even though the
// exact wording (which neighbor, which interface, which peer) varies
// every time they fire. Checked in order; the first match wins.
var knownPatterns = []knownPattern{
	// Device telemetry upload failures name a per-hour .tgz file, so the
	// filename differs on every single occurrence. They're all the same
	// underlying "telemetry didn't reach the cloud" problem and must
	// collapse into one group regardless of date/hour in the name.
	{"Device Telemetry Send Failure", regexp.MustCompile(`(?i)(device telemetry|_dt_|dt_\d).*(fail|error|unable|couldn.t)|fail.*(send|upload).*(_dt_|telemetry)`)},
	{"Device Telemetry Error", regexp.MustCompile(`(?i)device telemetry`)},
	{"LACP Down", regexp.MustCompile(`(?i)lacp.*(down|fail|timeout|expired)`)},
	{"LACP Up", regexp.MustCompile(`(?i)lacp.*(up|established)`)},
	{"HA Failover", regexp.MustCompile(`(?i)\bha\b.*(failover|failed over|state changed|link (down|monitor) failure|state.*(active|passive|suspended))`)},
	{"BFD Session Down", regexp.MustCompile(`(?i)bfd.*(down|timeout|expired|session.*down)`)},
	{"OSPF Neighbor Down", regexp.MustCompile(`(?i)ospf.*(neighbor|adjacency).*(down|dead|lost|fail)`)},
	{"BGP Peer Down", regexp.MustCompile(`(?i)bgp.*(peer|neighbor).*(down|reset|fail|lost)`)},
	{"IPSec/VPN Tunnel Down", regexp.MustCompile(`(?i)(ipsec|vpn|tunnel).*(down|fail|disconnect|negotiation failed)`)},
	{"Route Flap", regexp.MustCompile(`(?i)route.*(flap|withdraw|removed)`)},
	{"Interface Link Down", regexp.MustCompile(`(?i)\binterface\b.*\blink\b.*\bdown\b`)},
	{"Interface Link Up", regexp.MustCompile(`(?i)\binterface\b.*\blink\b.*\bup\b`)},
	{"Dataplane/Management CPU High", regexp.MustCompile(`(?i)(dataplane|management).*cpu.*(high|resource)`)},
	{"Session Table Full", regexp.MustCompile(`(?i)session (table|resource).*(full|exhaust)`)},
	{"Content Update Failure", regexp.MustCompile(`(?i)(content|wildfire|antivirus).*(upgrade|update).*(fail|error|couldn.t connect)`)},
	{"Certificate Expiring/Expired", regexp.MustCompile(`(?i)certificate.*expir`)},
	{"License Issue", regexp.MustCompile(`(?i)license.*(expir|invalid|fail)`)},
}

/* ---------- generic normalization (fallback for unrecognized events) ---------- */

var (
	connIDRe = regexp.MustCompile(`(?i)conn id:\s*\S+`)
	// quoted filenames vary per occurrence (timestamped .tgz uploads, log
	// rotations, ...); collapsing the whole quoted span keeps them together
	quotedFileRe = regexp.MustCompile(`'[^']*'`)
	// bare timestamped archive names, for the cases that aren't quoted
	tgzRe   = regexp.MustCompile(`\S+\.tgz\b`)
	ifaceRe = regexp.MustCompile(`(ethernet|ae)\d+(/\d+)?(\.\d+)?`)
	macRe   = regexp.MustCompile(`[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}`)
	ipRe    = regexp.MustCompile(`\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?`)
	portRe  = regexp.MustCompile(`(?i)port:?\s*\d+`)
	// NOTE: deliberately not \b\d+\b — "_" counts as a word character, so
	// \b never fires between an underscore and a digit. That made
	// underscore-delimited serials/dates/hours (PA_00790..._20260801_1530)
	// survive normalization and split one recurring event into a separate
	// group per hour.
	numRe = regexp.MustCompile(`\d+`)
)

// normalizeTemplate blanks out the parts of a description that vary
// occurrence-to-occurrence (filenames, addresses, ports, interface names,
// ids, plain numbers) so lines describing the same kind of event collapse
// into one group even without a hand-written knownPattern for it.
func normalizeTemplate(desc string) string {
	s := desc
	s = connIDRe.ReplaceAllString(s, "conn id: <id>")
	s = quotedFileRe.ReplaceAllString(s, "'<file>'")
	s = tgzRe.ReplaceAllString(s, "<file>")
	s = ifaceRe.ReplaceAllString(s, "<iface>")
	s = macRe.ReplaceAllString(s, "<mac>")
	s = ipRe.ReplaceAllString(s, "<ip>")
	s = portRe.ReplaceAllString(s, "port: <port>")
	s = numRe.ReplaceAllString(s, "<n>")
	return strings.TrimSpace(s)
}

func classify(desc string) string {
	for _, kp := range knownPatterns {
		if kp.re.MatchString(desc) {
			return kp.label
		}
	}
	t := normalizeTemplate(desc)
	if len(t) > 110 {
		t = t[:110] + "…"
	}
	return t
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "informational", "info":
		return 1
	default:
		return 0
	}
}

// GroupAnomalies collapses events into AnomalyGroups by classify()'s
// label, dropping known-noise lines, and returns them ordered by severity
// (critical first, then high/medium/low/info) with the most frequent
// events first inside each severity band.
func GroupAnomalies(events []AnomalyEvent) []AnomalyGroup {
	groups := make(map[string]*AnomalyGroup)
	var order []string

	for _, e := range events {
		if isNoise(e.Description) {
			continue
		}
		label := classify(e.Description)
		g, ok := groups[label]
		if !ok {
			g = &AnomalyGroup{Label: label, Severity: e.Severity, Subtype: e.Subtype, Sample: e.Description}
			groups[label] = g
			order = append(order, label)
		}
		g.Count++
		g.Occurrences = append(g.Occurrences, AnomalyOccurrence{Ts: e.Ts, Description: e.Description})
		if severityRank(e.Severity) > severityRank(g.Severity) {
			g.Severity = e.Severity
		}
	}

	out := make([]AnomalyGroup, 0, len(order))
	for _, label := range order {
		g := groups[label]
		sort.Slice(g.Occurrences, func(i, j int) bool { return g.Occurrences[i].Ts.Before(g.Occurrences[j].Ts) })
		out = append(out, *g)
	}
	// severity first (critical → info), then most frequent within a band
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := severityRank(out[i].Severity), severityRank(out[j].Severity)
		if si != sj {
			return si > sj
		}
		return out[i].Count > out[j].Count
	})
	return out
}
