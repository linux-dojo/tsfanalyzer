// Package parser: gp.go turns a GlobalProtect agent collection into the two
// things you want first — what this endpoint is, and what happened when it
// tried to connect.
//
// The agent is two cooperating programs. PanGPS is the Windows service that
// does the work: pre-login, portal login, gateway selection, HIP, the tunnel.
// PanGPA is the UI the user sees; it relays commands to and from PanGPS over
// a local IPC channel and renders the result. pan_gp_event.log is the
// service's own narrative of that work in plain language, which makes it the
// right source for a timeline; the component logs behind it carry the detail.
package parser

import (
	"archive/tar"
	"bufio"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

/* ---------- overview ---------- */

// GPOverview is the endpoint and the agent on it.
type GPOverview struct {
	// from the agent's own logs
	ClientVersion string `json:"client_version,omitempty"`
	ServiceVer    string `json:"service_version,omitempty"`
	Portal        string `json:"portal,omitempty"`
	Gateway       string `json:"gateway,omitempty"`
	User          string `json:"user,omitempty"`
	ConnectMethod string `json:"connect_method,omitempty"`
	FinalState    string `json:"final_state,omitempty"`

	// from SystemInfo.txt, when the collection includes it
	HostName   string `json:"host_name,omitempty"`
	OSName     string `json:"os_name,omitempty"`
	OSVersion  string `json:"os_version,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	Model      string `json:"model,omitempty"`
	TotalMemMB string `json:"total_mem_mb,omitempty"`
	BootTime   string `json:"boot_time,omitempty"`

	// from the HIP report, when present
	HipUser     string `json:"hip_user,omitempty"`
	HipHostID   string `json:"hip_host_id,omitempty"`
	HipIP       string `json:"hip_ip,omitempty"`
	HipGenerate string `json:"hip_generated,omitempty"`

	// window covered by the logs
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
}

var (
	gpVersionRe = regexp.MustCompile(
		`GlobalProtect service started \(client version: ([^,]+), OS version: ([^)]*)\)`)
	gpSvcVerRe   = regexp.MustCompile(`Start PanGPS service \(ver: ([^)]+)\)`)
	gpPortalRe   = regexp.MustCompile(`(?i)portal (?:login completed with address|pre ?- ?login to the portal) (\S+)`)
	gpPortalAny  = regexp.MustCompile(`(?i)(?:for|to) portal ([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z0-9.\-]+)`)
	gpUserRe     = regexp.MustCompile(`(?i)cookie for portal \S+ and user (\S+)`)
	gpMethodRe   = regexp.MustCompile(`(?i)Connect method is (\S+)`)
	gpStatusRe   = regexp.MustCompile(`(?i)portal status is (.+?)\.?$`)
	gpGatewayRe  = regexp.MustCompile(`(?i)gateway ([A-Za-z0-9][A-Za-z0-9.\-]*), priority`)
	sysInfoKeyRe = regexp.MustCompile(`^([A-Z][A-Za-z /()]+):\s{2,}(.*\S)\s*$`)
)

// ExtractGPOverview reads the small number of files that describe the host
// and the agent. Every field is optional: collections vary by platform and
// by GP version, and a missing file must not cost the rest of the tab.
func ExtractGPOverview(r io.ReadSeeker) (*GPOverview, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	ov := &GPOverview{}
	var firstTs, lastTs time.Time

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
		switch base := strings.ToLower(baseName(hdr.Name)); {
		case base == "systeminfo.txt":
			readSystemInfo(tr, ov)
		case strings.HasSuffix(base, "hrpt.xml"), base == "hipreport.xml":
			readHipReport(tr, ov)
		case base == "pan_gp_event.log":
			readGPEventSummary(tr, ov, &firstTs, &lastTs)
		case base == "pangps.log":
			readGPSSummary(tr, ov)
		}
	}

	if !firstTs.IsZero() {
		ov.FirstSeen = firstTs.Format("2006-01-02 15:04:05")
	}
	if !lastTs.IsZero() {
		ov.LastSeen = lastTs.Format("2006-01-02 15:04:05")
	}
	return ov, nil
}

func baseName(p string) string {
	p = normalizePath(strings.ReplaceAll(p, `\`, "/"))
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// readSystemInfo parses the output of Windows `systeminfo`, which is a
// two-column "Key:   value" listing with continuation lines that are ignored.
func readSystemInfo(r io.Reader, ov *GPOverview) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		m := sysInfoKeyRe.FindStringSubmatch(strings.TrimRight(sc.Text(), "\r"))
		if m == nil {
			continue
		}
		switch strings.TrimSpace(m[1]) {
		case "Host Name":
			ov.HostName = m[2]
		case "OS Name":
			ov.OSName = m[2]
		case "OS Version":
			ov.OSVersion = m[2]
		case "System Manufacturer":
			ov.Vendor = m[2]
		case "System Model":
			ov.Model = m[2]
		case "Total Physical Memory":
			ov.TotalMemMB = m[2]
		case "System Boot Time":
			ov.BootTime = m[2]
		}
	}
}

func readHipReport(r io.Reader, ov *GPOverview) {
	b, err := io.ReadAll(io.LimitReader(r, 8<<20))
	if err != nil {
		return
	}
	s := string(b)
	get := func(tag string) string {
		re := regexp.MustCompile(`(?s)<` + tag + `>(.*?)</` + tag + `>`)
		if m := re.FindStringSubmatch(s); m != nil {
			return strings.TrimSpace(m[1])
		}
		return ""
	}
	ov.HipUser = get("user-name")
	ov.HipHostID = get("host-id")
	ov.HipIP = get("ip-address")
	ov.HipGenerate = get("generate-time")
	if ov.HostName == "" {
		ov.HostName = get("host-name")
	}
}

func readGPEventSummary(r io.Reader, ov *GPOverview, first, last *time.Time) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		m := gpEventLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if t, ok := parseGPTime(m[1], m[2]); ok {
			if first.IsZero() || t.Before(*first) {
				*first = t
			}
			if last.IsZero() || t.After(*last) {
				*last = t
			}
		}
		msg := m[5]
		if v := gpVersionRe.FindStringSubmatch(msg); v != nil {
			ov.ClientVersion = strings.TrimSpace(v[1])
			if ov.OSName == "" {
				ov.OSName = strings.TrimSpace(v[2])
			}
		}
		if v := gpPortalRe.FindStringSubmatch(msg); v != nil {
			ov.Portal = v[1]
		} else if ov.Portal == "" {
			if v := gpPortalAny.FindStringSubmatch(msg); v != nil {
				ov.Portal = v[1]
			}
		}
		if v := gpUserRe.FindStringSubmatch(msg); v != nil && !strings.EqualFold(v[1], "pre-logon") {
			ov.User = v[1]
		}
		if v := gpMethodRe.FindStringSubmatch(msg); v != nil {
			ov.ConnectMethod = v[1]
		}
		// the last status wins: it is where the agent ended up
		if v := gpStatusRe.FindStringSubmatch(msg); v != nil {
			ov.FinalState = strings.TrimSpace(v[1])
		}
	}
}

func readGPSSummary(r io.Reader, ov *GPOverview) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if ov.ServiceVer == "" {
			if m := gpSvcVerRe.FindStringSubmatch(line); m != nil {
				ov.ServiceVer = m[1]
			}
		}
		if ov.Gateway == "" {
			if m := gpGatewayRe.FindStringSubmatch(line); m != nil {
				ov.Gateway = m[1]
			}
		}
		if ov.ServiceVer != "" && ov.Gateway != "" {
			return
		}
	}
}

/* ---------- connection timeline ---------- */

// GPEvent is one step in a connection attempt.
type GPEvent struct {
	Ts       time.Time `json:"ts"`
	Severity string    `json:"severity"` // Info | Error
	Phase    string    `json:"phase"`    // prelogin | portal | auth | gateway | hip | tunnel | discovery | service
	Message  string    `json:"message"`
	Source   string    `json:"source"` // the log it came from
	// Outcome marks the events worth colouring: ok | fail | "".
	Outcome string `json:"outcome,omitempty"`
}

// gpPhaseRule classifies an event line into a phase of the connection, and
// says whether it represents a success or a failure. Order matters: the first
// match wins, so the specific patterns precede the general ones.
type gpPhaseRule struct {
	re      *regexp.Regexp
	phase   string
	outcome string
}

var gpPhaseRules = []gpPhaseRule{
	// outcomes first, so a specific success or failure is never swallowed by
	// the broader pattern for the same phase
	{regexp.MustCompile(`(?i)failed to pre ?- ?login`), "prelogin", "fail"},
	{regexp.MustCompile(`(?i)auth failed|authentication failed`), "auth", "fail"},
	{regexp.MustCompile(`(?i)portal status is Connected|portal login completed`), "portal", "ok"},
	{regexp.MustCompile(`(?i)invalid portal|portal is unresponsive`), "portal", "fail"},
	{regexp.MustCompile(`(?i)gateway is unresponsive|no network connectivity`), "gateway", "fail"},
	{regexp.MustCompile(`(?i)tunnel is up|tunnel connected|tunnel established`), "tunnel", "ok"},

	{regexp.MustCompile(`(?i)service started|PanGPS service|service stopped`), "service", ""},
	// the captive-portal detector and its embedded browser are a separate
	// concern from the connection itself, and would otherwise dominate
	{regexp.MustCompile(`(?i)captive|CP_DETECT|CP_GENERAL|CP Log|webview|CPanCPView`), "captive-portal", ""},
	{regexp.MustCompile(`(?i)portal pre ?- ?login|prelogin|CheckServerCert`), "prelogin", ""},
	// PanPUAC is the cached portal auth cookie: loading, decrypting or
	// failing to open it is part of the authentication story
	{regexp.MustCompile(`(?i)PanPUAC|cookie|SSO starts|logging into portal|portal login starts|SAML|auth`), "auth", ""},
	{regexp.MustCompile(`(?i)connect method|prelogon status|portal`), "portal", ""},
	{regexp.MustCompile(`(?i)gateway`), "gateway", ""},
	{regexp.MustCompile(`(?i)hip`), "hip", ""},
	{regexp.MustCompile(`(?i)network discovery|discovering (internal|external)`), "discovery", ""},
	{regexp.MustCompile(`(?i)disconnect|tunnel`), "tunnel", ""},
}

func classifyGPEvent(msg, severity string) (string, string) {
	for _, r := range gpPhaseRules {
		if r.re.MatchString(msg) {
			out := r.outcome
			if out == "" && strings.EqualFold(severity, "Error") {
				out = "fail"
			}
			return r.phase, out
		}
	}
	if strings.EqualFold(severity, "Error") {
		return "", "fail"
	}
	return "", ""
}

// gpEventLogs are the plain-language narratives, in the order they are most
// useful; the component traces are deliberately not included, as they would
// bury the story in tens of thousands of debug lines.
var gpEventLogs = map[string]bool{
	"pan_gp_event.log":     true,
	"pan_gpa_event.log":    true,
	"pan_cp_events.log":    true,
	"pan_gpa_cp_event.log": true,
}

// ExtractGPTimeline collects every event-log line into one ordered narrative,
// tagged with the phase of the connection it belongs to.
func ExtractGPTimeline(r io.ReadSeeker, limit int) ([]GPEvent, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	var out []GPEvent
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
		if !gpEventLogs[base] {
			continue
		}
		sc := bufio.NewScanner(tr)
		sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
		for sc.Scan() {
			m := gpEventLineRe.FindStringSubmatch(strings.TrimRight(sc.Text(), "\r"))
			if m == nil {
				continue
			}
			t, ok := parseGPTime(m[1], m[2])
			if !ok {
				continue
			}
			sev := strings.TrimSpace(m[4])
			phase, outcome := classifyGPEvent(m[5], sev)
			out = append(out, GPEvent{
				Ts: t, Severity: sev, Phase: phase,
				Message: m[5], Source: base, Outcome: outcome,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Ts.Before(out[j].Ts) })
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:] // the most recent activity is the interesting end
	}
	if out == nil {
		out = []GPEvent{}
	}
	return out, nil
}
