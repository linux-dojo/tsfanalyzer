// Package parser: gpfacts.go reads the GlobalProtect service trace
// (PanGPS.log) for the details the event log does not carry.
//
// pan_gp_event.log is the user-facing narrative — "portal status is Connected"
// — and it is what the attempt model in gpflow.go is built from. PanGPS.log is
// the service's own trace, and it is where the actual stage boundaries are
// written:
//
//	----Portal Pre-login starts----
//	----Portal Login starts----
//	----Portal Processing starts----
//	----Network Discover starts----
//	----Gateway Pre-login starts----
//	----Gateway Login starts----
//	----Tunnel Creation starts----
//
// along with the portal's pre-login response, the certificate check result,
// whether the GlobalProtect enforcer is in place, how internal host detection
// resolved, and the configuration the gateway pushed back. Those are facts
// about the connection rather than steps in it, so they are collected here and
// shown on Overview, while the stage sequence itself stays with the attempt.
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

// GPCertCheck is one portal certificate verification.
//
// The return code alone does not decide whether the check failed, and reading
// it that way would be badly misleading. Across the sample collections
// CheckServerCert returned 0x1002 sixty-three times, and in all sixty-three
// the pre-login went on to be issued and the connection succeeded — 0x1002
// accompanies a local trust-store lookup that did not find the certificate
// ("Failed to X509_LOOKUP_load_file") while the hostname still matched the
// subject alternative name. 0x2000 is likewise followed by "Skip
// CheckServerCert result", i.e. the agent is told to ignore it.
//
// So what is recorded is the code *and* whether the pre-login proceeded, and
// only a check that stopped the flow is reported as a failure. Otherwise a
// working connection would raise dozens of certificate alarms.
type GPCertCheck struct {
	At        time.Time `json:"at"`
	Portal    string    `json:"portal,omitempty"`
	Code      string    `json:"code"`
	Verify    string    `json:"verify,omitempty"` // verifyportalcert=yes|no
	Proceeded bool      `json:"proceeded"`
	Skipped   bool      `json:"skipped,omitempty"` // "Skip CheckServerCert result"
	// Failed is set only when the check was not skipped and no pre-login
	// followed it.
	Failed bool   `json:"failed"`
	Detail string `json:"detail,omitempty"`
}

// GPPrelogin is the portal's answer to the pre-login request. Reaching this
// point with status Success means the portal was contacted and answered; it
// says nothing yet about the user's credentials.
type GPPrelogin struct {
	At     time.Time `json:"at"`
	Portal string    `json:"portal,omitempty"`
	Status string    `json:"status,omitempty"`
	// CCUsername is the username the firewall extracted from a client
	// certificate. A non-empty value means the portal asked for a client
	// certificate, accepted the one presented, and read the identity out of
	// it — so the password prompt that follows (if any) is a second factor
	// rather than the only one.
	CCUsername    string `json:"cc_username,omitempty"`
	ConnectedIP   string `json:"connected_ip,omitempty"`
	AuthMessage   string `json:"auth_message,omitempty"`
	SAMLBrowser   string `json:"saml_default_browser,omitempty"`
	PanOSVersion  string `json:"panos_version,omitempty"`
	AutoSubmit    string `json:"autosubmit,omitempty"`
	UsernameLabel string `json:"username_label,omitempty"`
}

// ClientCert reports whether the portal authenticated this client by
// certificate, which is exactly the question "is <ccusername> populated".
func (p GPPrelogin) ClientCert() bool { return strings.TrimSpace(p.CCUsername) != "" }

// GPEnforcer is the state of the GlobalProtect traffic enforcer.
//
// The enforcer is what blocks traffic while the agent is disconnected, so
// whether it is on changes what a failed connection costs the user: their
// access, or merely their tunnel.
//
// Deciding this from "does the word enforcer appear" is wrong, and that is the
// mistake this type exists to prevent. The service logs enforcer *exception*
// configuration constantly whether or not enforcement is on — exception lists
// pushed from the portal, exclude routes programmed into the driver, FQDN and
// app lists — and several of those lines say the opposite of what they seem
// to. In the sample collections:
//
//   - "Enforcer already loaded." is preceded by "Enforcer is not found".
//   - "Enforcer,Always On, 401 entries found in filter objects" is a filter
//     *category* being enumerated during "Enforcer,RemoveAllFilters", i.e.
//     during teardown.
//   - "enforcer exception: no app list defined." and "No enforcer ip exception
//     list defined!" report the absence of a list.
//   - "enforcer is blocking(only if Enforcer is enabled)" is conditional on
//     the very thing being asked.
//
// Both sample collections were in fact disabled — "GetEnforcer state = 0"
// followed by "GetEnforcer disabled", 132 times, with no contradicting
// statement anywhere — while an earlier version of this parser reported the
// enforcer as present in both.
//
// So only explicit statements of state count, the last one wins, and
// configuration is recorded separately as configuration.
type GPEnforcer struct {
	// State is "enabled", "disabled" or "unknown", as of the last statement
	// made while this portal was in force.
	State string    `json:"state"`
	At    time.Time `json:"at,omitempty"`
	// Deciding is the line that settled it, so the answer is checkable.
	Deciding string `json:"deciding,omitempty"`
	// EverEnabled and Flips describe a state that moves. On a machine that
	// connects and disconnects repeatedly the enforcer is switched on and off
	// with it, so a single yes/no taken from the end of the log says more about
	// when the collection was gathered than about the configuration.
	EverEnabled bool `json:"ever_enabled,omitempty"`
	Flips       int  `json:"flips,omitempty"`

	// Policy counts exception lines that carry actual content pushed by this
	// portal. Driver counts route programming into the driver, which happens
	// during tunnel setup whether or not the portal configured anything.
	// Keeping them apart is what makes "configured on this portal" answerable.
	Policy int `json:"policy,omitempty"`
	Driver int `json:"driver,omitempty"`

	// The lists themselves, which are the substance of the configuration.
	IPExceptions []string `json:"ip_exceptions,omitempty"`
	FQDNs        []string `json:"fqdns,omitempty"`

	Exceptions int      `json:"exceptions,omitempty"`
	Domains    int      `json:"domains,omitempty"`
	Wildcards  int      `json:"wildcards,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
}

// Configured reports whether this portal pushed enforcer policy.
//
// Only content-bearing lines count. The agent also re-logs summary counts —
// "enforcer exception: 3 fqdn entries", "parsed 0 single and 3 wildcard" —
// which describe whatever is currently loaded, so they survive a switch to a
// portal that configured nothing. In the two-portal sample the lab portal
// pushes "enforcer ip exception is 8.8.8.8,..." and an FQDN list while the
// Prisma portal pushes neither, yet both log the summary counts; counting
// those would report the Prisma portal as configured, which is the bug this
// distinction exists to prevent.
func (e GPEnforcer) Configured() bool {
	return len(e.IPExceptions) > 0 || len(e.FQDNs) > 0 || e.Exceptions > 0
}

// Present reports whether enforcement is actually on.
func (e GPEnforcer) Present() bool { return e.State == "enabled" }

// GPHostDetection is the internal host detection result.
//
// Internal host detection is how the agent decides it is already inside the
// network: the portal gives it an IP and the hostname that IP should reverse-
// resolve to, and the agent does the lookup. A match means "internal", and the
// agent either stops (nothing to connect to) or uses the internal gateway
// list — so a *failed* lookup on a machine that really is internal sends it
// out to an external gateway instead, which is a confusing state to debug.
type GPHostDetection struct {
	Configured bool      `json:"configured"`
	At         time.Time `json:"at,omitempty"`
	IP         string    `json:"ip,omitempty"`
	Host       string    `json:"host,omitempty"`
	// Lookup is the in-addr.arpa name actually queried.
	Lookup string `json:"lookup,omitempty"`
	// Resolved is the hostname that came back, Err the error code. Error 0 is
	// a successful detection.
	Resolved string `json:"resolved,omitempty"`
	Err      string `json:"err,omitempty"`
	OK       bool   `json:"ok"`
	IPv6     bool   `json:"ipv6"`
	Detail   string `json:"detail,omitempty"`
}

// GPGatewayConfig is the configuration the gateway pushed after login.
type GPGatewayConfig struct {
	Gateway string    `json:"gateway"`
	At      time.Time `json:"at"`
	// ConfigName is the <portal> element of the pushed configuration, which is
	// *not* a portal address: it is the name of the agent config profile the
	// gateway matched, e.g. "GP-Gateway-N" or
	// "GlobalProtect_External_Gateway-N". Treating it as a portal address
	// would invent portals that do not exist and corrupt the portal grouping,
	// so it is named for what it is.
	ConfigName string `json:"config_name,omitempty"`
	User       string `json:"user,omitempty"`
	// Fields holds the single-valued elements in the order they appeared, so
	// the view can list the configuration without this parser having to know
	// every element PAN-OS might send.
	Fields []GPConfigField `json:"fields,omitempty"`
	// The routing decision is the part people actually come here for.
	AccessRoutes  []string `json:"access_routes,omitempty"`
	ExcludeRoutes []string `json:"exclude_routes,omitempty"`
	DNS           []string `json:"dns,omitempty"`
	DNSSuffix     []string `json:"dns_suffix,omitempty"`
	WINS          []string `json:"wins,omitempty"`
	// Truncated marks a config the log cut off mid-element. The agent writes
	// the XML into a bounded log line, so a large configuration is clipped —
	// the ipsec block is the usual casualty. Saying so is better than showing
	// a partial config as if it were the whole one.
	Truncated bool `json:"truncated,omitempty"`
}

// GPConfigField is one name/value pair from the gateway configuration.
type GPConfigField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SplitTunnel reports whether the gateway is doing split tunnelling, which is
// the practical reading of the access routes: a single default route means all
// traffic goes down the tunnel.
func (c GPGatewayConfig) SplitTunnel() bool {
	if len(c.ExcludeRoutes) > 0 {
		return true
	}
	for _, r := range c.AccessRoutes {
		if r == "0.0.0.0/0" || r == "::/0" {
			return false
		}
	}
	return len(c.AccessRoutes) > 0
}

// GPPortalFacts is everything the trace says while one portal was in force.
//
// These facts are portal-scoped in reality and were previously collected
// collection-wide, so switching portal in the UI changed nothing: a lab
// portal's enforcer lists and gateway configuration were shown under a Prisma
// portal that had pushed neither.
type GPPortalFacts struct {
	Portal         string            `json:"portal"`
	Enforcer       GPEnforcer        `json:"enforcer"`
	HostDetection  GPHostDetection   `json:"host_detection"`
	CertChecks     []GPCertCheck     `json:"cert_checks,omitempty"`
	Prelogins      []GPPrelogin      `json:"prelogins,omitempty"`
	GatewayConfigs []GPGatewayConfig `json:"gateway_configs,omitempty"`
	Stages         []GPTraceStage    `json:"stages,omitempty"`
}

// GPFacts is the trace split by portal, plus a merged view for when no portal
// is selected.
type GPFacts struct {
	All     GPPortalFacts   `json:"all"`
	Portals []GPPortalFacts `json:"portals,omitempty"`
}

// For returns the facts for one portal, or the merged view when the name is
// empty or unknown.
func (f *GPFacts) For(portal string) GPPortalFacts {
	if portal != "" {
		for _, p := range f.Portals {
			if p.Portal == portal {
				return p
			}
		}
	}
	return f.All
}

// GPTraceStage is one "----X starts----" boundary from the service trace.
type GPTraceStage struct {
	At    time.Time `json:"at"`
	Name  string    `json:"name"`
	Stage GPStage   `json:"stage"`
}

// CertFailures returns only the checks that actually stopped a pre-login.
func (f GPPortalFacts) CertFailures() []GPCertCheck {
	var out []GPCertCheck
	for _, c := range f.CertChecks {
		if c.Failed {
			out = append(out, c)
		}
	}
	return out
}

var (
	gpTraceStartRe = regexp.MustCompile(`----\s*([A-Za-z][A-Za-z0-9 \-]*?)\s*starts\s*----`)

	gpCertCheckRe = regexp.MustCompile(`CheckServerCert return (0x[0-9a-fA-F]+)`)
	gpVerifyRe    = regexp.MustCompile(`(?i)verifyportalcert\s*=\s*(\w+)`)
	gpCertSkipRe  = regexp.MustCompile(`(?i)Skip CheckServerCert result`)

	gpPreloginResultRe = regexp.MustCompile(`(?i)prelogin to portal result is`)
	gpPreloginSentRe   = regexp.MustCompile(`(?i)/global-protect/prelogin\.esp`)
	// The request line names the portal it is being sent to, which is the one
	// unambiguous place the portal address appears at pre-login time.
	gpReqPortalRe = regexp.MustCompile(`REQID=\d+,IPADDR=([^,]+),PORT=`)

	// Enforcer state. Only these lines are statements about whether
	// enforcement is on; everything else mentioning the enforcer is
	// configuration. See the note on GPEnforcer for why that distinction
	// matters — the configuration lines appear in their hundreds on endpoints
	// where the enforcer is switched off.
	gpEnforcerOffRe = regexp.MustCompile(`(?i)` +
		`enforcer is not enabled|` +
		`getenforcer disabled|` +
		`getenforcer state = 0\b|` +
		`enforcer is unloaded|` +
		`enforcer needs to be loaded first|` +
		`turn off traffic enforcer|` +
		`stop-enforcer`)
	// A non-zero state, or the service saying plainly that it is enabled.
	// "Enforcer,Always On" is deliberately absent: it names a filter-object
	// category during RemoveAllFilters, not a state.
	gpEnforcerOnRe = regexp.MustCompile(`(?i)` +
		`getenforcer state = [1-9]\d*\b|` +
		`enforcer is enabled(?:\.|$|[^)])`)

	// Configuration, counted but never treated as evidence of enforcement,
	// and split by whether it carries content.
	//
	// gpEnforcerPolicyRe is the portal pushing a list. gpEnforcerDriverRe is
	// the agent programming routes into the driver during tunnel setup, which
	// happens regardless. The summary lines ("N fqdn entries", "parsed N
	// single and M wildcard") are deliberately in neither: they restate what
	// is already loaded and therefore follow the agent across a portal switch.
	gpEnforcerPolicyRe = regexp.MustCompile(`(?i)` +
		`enforcer ip exception is\s+\S|` +
		`enforcer exception: fqdn is\s+\S|` +
		`enforcer set exceptions \d+|` +
		`enforcer exception ipv\d`)
	gpEnforcerDriverRe = regexp.MustCompile(`(?i)` +
		`set enforcer exclude route|` +
		`traffic enforcement:`)
	gpEnforcerSummaryRe = regexp.MustCompile(`(?i)` +
		`enforcer exception: \d+ fqdn entries|` +
		`parsed \d+ single and \d+ wildcard`)
	gpEnforcerIPListRe   = regexp.MustCompile(`(?i)enforcer ip exception is\s+(\S+)`)
	gpEnforcerFQDNListRe = regexp.MustCompile(`(?i)enforcer exception: fqdn is\s+(\S+)`)

	// Lines that announce an *absent* list. They mention the enforcer and look
	// like configuration, but say the opposite, so they are excluded before
	// any of the counting above.
	gpEnforcerEmptyRe = regexp.MustCompile(`(?i)` +
		`no enforcer ip exception list defined|` +
		`no fqdn ist defined|` + // the agent's own spelling
		`no app list defined|` +
		`no trusted host list defined|` +
		`is not enabled`)
	gpEnforcerCountRe = regexp.MustCompile(`(?i)[Ee]nforcer set exceptions (\d+)-(\d+)`)
	gpEnforcerDomRe   = regexp.MustCompile(`(?i)parsed (\d+) single and (\d+) wildcard domain entries`)

	// Internal host detection.
	gpIHDNoneRe    = regexp.MustCompile(`(?i)No internal host detection defined`)
	gpIHDNoV6Re    = regexp.MustCompile(`(?i)No ipv6 internal host detection`)
	gpIHDIPRe      = regexp.MustCompile(`^IP\s+(\S+)\s*$`)
	gpIHDHostRe    = regexp.MustCompile(`^host\s+(\S+)\s*$`)
	gpIHDLookupRe  = regexp.MustCompile(`(?i)Reverse DNS lookup:\s*(\S+)`)
	gpIHDResultRe  = regexp.MustCompile(`(?i)Reverse lookup returns hostname\s*(\S*)\s*,\s*error\s+(-?\d+)`)
	gpGatewayCfgRe = regexp.MustCompile(`gateway (\S+)'s config is`)
)

// traceStageOf maps a "----X starts----" name onto the stage model, so the
// trace boundaries and the event-log stages line up in one sequence.
func traceStageOf(name string) GPStage {
	switch strings.ToLower(name) {
	case "portal pre-login":
		return StagePortalPrelogin
	case "portal login":
		return StagePortalAuth
	case "portal processing":
		return StagePortalConfig
	case "network discover":
		return StageDiscovery
	case "gateway pre-login":
		return StageGatewaySelect
	case "gateway login":
		return StageGatewayAuth
	case "tunnel creation":
		return StageTunnel
	}
	// "Disable" and "Tunnel User Diconnecting" (the agent's own spelling) are
	// teardown boundaries rather than steps towards a connection. They are
	// still recorded, with no stage, so the sequence shows why a run ended
	// instead of appearing to stop for no reason.
	return ""
}

// ExtractGPFacts reads the service trace out of a collection.
func ExtractGPFacts(r io.ReadSeeker) (*GPFacts, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	type namedBody struct {
		name  string
		lines []string
	}
	var files []namedBody
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := strings.ToLower(baseName(hdr.Name))
		if !strings.HasPrefix(base, "pangps") || !strings.HasSuffix(base, ".log") {
			continue
		}
		sc := bufio.NewScanner(tr)
		sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
		var body []string
		for sc.Scan() {
			body = append(body, strings.TrimRight(sc.Text(), "\r"))
		}
		files = append(files, namedBody{name: base, lines: body})
	}
	// Oldest rotation first, or a stale round overwrites the current one.
	sort.SliceStable(files, func(i, j int) bool {
		return rotationIndex(files[i].name) > rotationIndex(files[j].name)
	})

	f := newGPFactScan()
	for _, nb := range files {
		f.feed(nb.lines)
	}
	f.close()
	return f.facts, nil
}

// newGPFactScan starts a scan with the enforcer unknown rather than absent:
// "we were never told" and "it is off" are different answers.
func newGPFactScan() *gpFactScan {
	return &gpFactScan{facts: &GPFacts{}, byPortal: map[string]*GPPortalFacts{}}
}

// gpFactScan folds the trace into GPFacts, keeping one set of facts per portal
// as well as a merged one.
//
// Portal scoping is the point. The enforcer lists, the internal host detection
// result and the gateway configuration all come from whichever portal the
// agent is talking to, and a collection can hold several. Collecting them
// collection-wide made the portal selector inert and showed one portal's
// configuration under another portal's name.
//
// It is a state machine because several facts span consecutive lines: the
// host-detection IP, hostname, query and result are four separate lines, and a
// certificate check is only interpretable once you know whether a pre-login
// followed it.
type gpFactScan struct {
	facts *GPFacts

	// portal is the address of the last portal a pre-login was sent to, and it
	// scopes everything that follows until the next one.
	portal   string
	order    []string
	byPortal map[string]*GPPortalFacts

	// pendingCert indexes into the current portal's CertChecks.
	pendingCert []int
	// partial host detection being assembled
	ihdIP, ihdHost, ihdLookup string
	ihdAt                     time.Time
}

// cur returns the fact set for the portal in force. Lines logged before any
// pre-login belong to no portal; they land in a nameless bucket that is merged
// into the overall view but never offered as a selectable portal.
func (s *gpFactScan) cur() *GPPortalFacts {
	pf, ok := s.byPortal[s.portal]
	if !ok {
		pf = &GPPortalFacts{Portal: s.portal, Enforcer: GPEnforcer{State: "unknown"}}
		s.byPortal[s.portal] = pf
		s.order = append(s.order, s.portal)
	}
	return pf
}

func (s *gpFactScan) feed(lines []string) {
	for i := 0; i < len(lines); i++ {
		ts, msg, ok := gpTraceParts(lines[i])
		if !ok {
			continue
		}
		s.line(ts, msg, lines, i)
	}
}

// gpTraceParts pulls the timestamp and message out of whichever of the trace
// formats the line is in. It reuses the line patterns rather than re-deriving
// them, so a new agent format only has to be added in one place.
func gpTraceParts(line string) (time.Time, string, bool) {
	if m := gpMacLineRe.FindStringSubmatch(line); m != nil {
		if t, ok := parseGPTime(m[3], m[4]); ok {
			return t, m[8], true
		}
	}
	if m := gpTraceLineRe.FindStringSubmatch(line); m != nil {
		if t, ok := parseGPTime(m[5], m[6]); ok {
			return t, m[8], true
		}
	}
	if m := gpCpLineRe.FindStringSubmatch(line); m != nil {
		if t, ok := parseGPTime(m[4], m[5]); ok {
			return t, m[8], true
		}
	}
	if m := gpEventLineRe.FindStringSubmatch(line); m != nil {
		if t, ok := parseGPTime(m[1], m[2]); ok {
			return t, m[5], true
		}
	}
	return time.Time{}, "", false
}

func (s *gpFactScan) line(ts time.Time, msg string, all []string, idx int) {
	trimmed := strings.TrimSpace(msg)

	// The portal in force scopes everything below it, so it is established
	// first. The pre-login request line is the one unambiguous place the
	// address appears.
	if m := gpReqPortalRe.FindStringSubmatch(trimmed); m != nil && gpPreloginSentRe.MatchString(trimmed) {
		// carry any unresolved certificate check across to the named portal
		pending := s.pendingCert
		var carried []GPCertCheck
		if old := s.byPortal[s.portal]; old != nil {
			for _, i := range pending {
				carried = append(carried, old.CertChecks[i])
			}
			old.CertChecks = old.CertChecks[:len(old.CertChecks)-len(carried)]
		}
		s.portal = m[1]
		s.pendingCert = s.pendingCert[:0]
		pf := s.cur()
		for _, c := range carried {
			c.Portal = s.portal
			pf.CertChecks = append(pf.CertChecks, c)
			s.pendingCert = append(s.pendingCert, len(pf.CertChecks)-1)
		}
		s.resolvePending(true)
		return
	}

	pf := s.cur()

	// stage boundaries
	if m := gpTraceStartRe.FindStringSubmatch(trimmed); m != nil {
		name := m[1]
		st := traceStageOf(name)
		pf.Stages = append(pf.Stages, GPTraceStage{At: ts, Name: name, Stage: st})
		if st == StagePortalPrelogin {
			// a new pre-login means any earlier check never led anywhere
			s.resolvePending(false)
		}
		return
	}

	// certificate verification
	if m := gpCertCheckRe.FindStringSubmatch(trimmed); m != nil {
		c := GPCertCheck{At: ts, Code: m[1], Portal: s.portal, Detail: trimmed}
		// the "verifyportalcert=" line sits just above it
		for k := idx - 1; k >= 0 && k > idx-6; k-- {
			if v := gpVerifyRe.FindStringSubmatch(all[k]); v != nil {
				c.Verify = v[1]
				break
			}
		}
		pf.CertChecks = append(pf.CertChecks, c)
		s.pendingCert = append(s.pendingCert, len(pf.CertChecks)-1)
		return
	}
	if gpCertSkipRe.MatchString(trimmed) {
		for _, i := range s.pendingCert {
			pf.CertChecks[i].Skipped = true
		}
		return
	}
	if gpPreloginResultRe.MatchString(trimmed) {
		s.resolvePending(true)
		s.readPreloginResponse(ts, all, idx)
		return
	}

	// enforcer: state statements first, and they are the only thing that
	// decides it. The last statement while this portal was in force wins.
	if gpEnforcerOffRe.MatchString(trimmed) {
		s.setEnforcer(pf, "disabled", ts, trimmed)
		return
	}
	if gpEnforcerOnRe.MatchString(trimmed) {
		s.setEnforcer(pf, "enabled", ts, trimmed)
		return
	}
	if !gpEnforcerEmptyRe.MatchString(trimmed) {
		e := &pf.Enforcer
		switch {
		case gpEnforcerPolicyRe.MatchString(trimmed):
			e.Policy++
			if len(e.Evidence) < 6 {
				e.Evidence = append(e.Evidence, trimmed)
			}
			if m := gpEnforcerIPListRe.FindStringSubmatch(trimmed); m != nil {
				e.IPExceptions = addOnce(e.IPExceptions, m[1])
			}
			if m := gpEnforcerFQDNListRe.FindStringSubmatch(trimmed); m != nil {
				e.FQDNs = addOnce(e.FQDNs, m[1])
			}
			if m := gpEnforcerCountRe.FindStringSubmatch(trimmed); m != nil {
				e.Exceptions = atoiSafe(m[2]) - atoiSafe(m[1]) + 1
			}
			return
		case gpEnforcerDriverRe.MatchString(trimmed):
			e.Driver++
			return
		case gpEnforcerSummaryRe.MatchString(trimmed):
			// A restatement of what is already loaded, not a push from this
			// portal — see GPEnforcer.Configured. Recorded for the counts it
			// carries, but it never marks a portal as configured.
			if m := gpEnforcerDomRe.FindStringSubmatch(trimmed); m != nil && e.Policy > 0 {
				e.Domains, e.Wildcards = atoiSafe(m[1]), atoiSafe(m[2])
			}
			return
		}
	}

	// internal host detection
	switch {
	case gpIHDNoneRe.MatchString(trimmed):
		if !pf.HostDetection.Configured {
			pf.HostDetection.Detail = trimmed
			pf.HostDetection.At = ts
		}
		return
	case gpIHDNoV6Re.MatchString(trimmed):
		pf.HostDetection.IPv6 = false
		return
	}
	if m := gpIHDIPRe.FindStringSubmatch(trimmed); m != nil {
		s.ihdIP, s.ihdAt = m[1], ts
		return
	}
	if m := gpIHDHostRe.FindStringSubmatch(trimmed); m != nil {
		s.ihdHost = m[1]
		return
	}
	if m := gpIHDLookupRe.FindStringSubmatch(trimmed); m != nil {
		s.ihdLookup = m[1]
		return
	}
	if m := gpIHDResultRe.FindStringSubmatch(trimmed); m != nil {
		// error 0 is a successful detection; anything else means the agent
		// could not confirm it is inside the network
		h := &pf.HostDetection
		h.Configured = true
		h.IP, h.Host, h.Lookup = s.ihdIP, s.ihdHost, s.ihdLookup
		h.Resolved, h.Err = m[1], m[2]
		h.OK = m[2] == "0"
		h.At = s.ihdAt
		h.Detail = trimmed
		s.ihdIP, s.ihdHost, s.ihdLookup = "", "", ""
		return
	}

	// gateway configuration
	if m := gpGatewayCfgRe.FindStringSubmatch(trimmed); m != nil {
		pf.GatewayConfigs = append(pf.GatewayConfigs, parseGatewayConfig(m[1], ts, all, idx))
		return
	}
}

// setEnforcer records a state statement, counting how often the state moves.
func (s *gpFactScan) setEnforcer(pf *GPPortalFacts, state string, ts time.Time, line string) {
	e := &pf.Enforcer
	if e.State != "unknown" && e.State != state {
		e.Flips++
	}
	if state == "enabled" {
		e.EverEnabled = true
	}
	e.State, e.At, e.Deciding = state, ts, line
}

// addOnce keeps a list of distinct values in the order first seen.
func addOnce(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func (s *gpFactScan) resolvePending(proceeded bool) {
	pf := s.byPortal[s.portal]
	if pf == nil {
		s.pendingCert = s.pendingCert[:0]
		return
	}
	for _, i := range s.pendingCert {
		if i >= len(pf.CertChecks) {
			continue
		}
		c := &pf.CertChecks[i]
		c.Proceeded = proceeded
		// Only a check that was neither skipped nor followed by a pre-login is
		// a failure. See the note on GPCertCheck: the raw code is not enough.
		c.Failed = !proceeded && !c.Skipped
	}
	s.pendingCert = s.pendingCert[:0]
}

// close finishes the scan and assembles the per-portal and merged views.
func (s *gpFactScan) close() {
	s.resolvePending(false)

	for _, name := range s.order {
		pf := s.byPortal[name]
		// The nameless bucket holds lines logged before any pre-login. It is
		// merged into the overall view but is not a portal anyone can select.
		if name != "" {
			s.facts.Portals = append(s.facts.Portals, *pf)
		}
		s.mergeInto(&s.facts.All, pf)
	}
	if s.facts.All.Enforcer.State == "" {
		s.facts.All.Enforcer.State = "unknown"
	}
}

// mergeInto folds one portal's facts into the collection-wide view, which is
// what the UI shows when no portal is selected. Later statements win, exactly
// as they do within a portal.
func (s *gpFactScan) mergeInto(dst, src *GPPortalFacts) {
	dst.CertChecks = append(dst.CertChecks, src.CertChecks...)
	dst.Prelogins = append(dst.Prelogins, src.Prelogins...)
	dst.GatewayConfigs = append(dst.GatewayConfigs, src.GatewayConfigs...)
	dst.Stages = append(dst.Stages, src.Stages...)

	e, se := &dst.Enforcer, src.Enforcer
	if se.State != "unknown" && se.State != "" {
		if e.State != "unknown" && e.State != "" && e.State != se.State {
			e.Flips++
		}
		e.State, e.At, e.Deciding = se.State, se.At, se.Deciding
	}
	e.EverEnabled = e.EverEnabled || se.EverEnabled
	e.Flips += se.Flips
	e.Policy += se.Policy
	e.Driver += se.Driver
	for _, v := range se.IPExceptions {
		e.IPExceptions = addOnce(e.IPExceptions, v)
	}
	for _, v := range se.FQDNs {
		e.FQDNs = addOnce(e.FQDNs, v)
	}
	if se.Exceptions > e.Exceptions {
		e.Exceptions = se.Exceptions
	}
	if se.Domains > 0 || se.Wildcards > 0 {
		e.Domains, e.Wildcards = se.Domains, se.Wildcards
	}
	for _, ev := range se.Evidence {
		if len(e.Evidence) < 6 {
			e.Evidence = append(e.Evidence, ev)
		}
	}
	if src.HostDetection.Configured && !dst.HostDetection.Configured {
		dst.HostDetection = src.HostDetection
	} else if dst.HostDetection.Detail == "" {
		dst.HostDetection.Detail = src.HostDetection.Detail
	}
}

// readPreloginResponse collects the XML that follows the "prelogin to portal
// result is" line. The body is written as continuation lines with no trace
// prefix, and it can be cut off, so the fields are scraped one tag at a time
// rather than unmarshalled.
func (s *gpFactScan) readPreloginResponse(ts time.Time, all []string, idx int) {
	p := GPPrelogin{At: ts, Portal: s.portal}
	body := gatherBlock(all, idx, 40)
	p.Status = tagValue(body, "status")
	p.CCUsername = tagValue(body, "ccusername")
	p.ConnectedIP = tagValue(body, "connected-ip")
	p.AuthMessage = tagValue(body, "authentication-message")
	p.SAMLBrowser = tagValue(body, "saml-default-browser")
	p.PanOSVersion = tagValue(body, "panos-version")
	p.AutoSubmit = tagValue(body, "autosubmit")
	p.UsernameLabel = tagValue(body, "username-label")
	if p.Status != "" || p.ConnectedIP != "" {
		pf := s.cur()
		pf.Prelogins = append(pf.Prelogins, p)
	}
}

// parseGatewayConfig scrapes the configuration the gateway pushed.
//
// It is deliberately not an XML unmarshal. The agent writes the configuration
// into the log as continuation lines and stops at a length limit, so the
// document is routinely cut off part-way through — in the sample collections
// the <ipsec> block is clipped mid-element. encoding/xml would reject the
// whole thing and the tab would show nothing at all, when almost every field
// worth reading arrived intact before the cut.
func parseGatewayConfig(gw string, ts time.Time, all []string, idx int) GPGatewayConfig {
	c := GPGatewayConfig{Gateway: gw, At: ts}
	body := gatherBlock(all, idx, 200)
	c.ConfigName = tagValue(body, "portal")
	c.User = tagValue(body, "user")
	c.AccessRoutes = memberList(body, "access-routes")
	c.ExcludeRoutes = memberList(body, "exclude-access-routes")
	c.DNS = memberList(body, "dns")
	c.DNSSuffix = memberList(body, "dns-suffix")
	c.WINS = memberList(body, "wins")

	// Every simple element, in document order, minus the ones already lifted
	// out and the list containers.
	skip := map[string]bool{
		"access-routes": true, "exclude-access-routes": true, "dns": true,
		"dns-suffix": true, "wins": true, "member": true, "response": true,
	}
	for _, m := range simpleTagRe.FindAllStringSubmatch(body, -1) {
		name, val := m[1], strings.TrimSpace(m[2])
		if skip[name] || val == "" {
			continue
		}
		c.Fields = append(c.Fields, GPConfigField{Name: name, Value: val})
	}
	c.Truncated = !strings.Contains(body, "</response>")
	return c
}

// gatherBlock returns the continuation lines following idx — those with no
// trace prefix of their own — as one string, bounded by max lines.
func gatherBlock(all []string, idx, max int) string {
	var b strings.Builder
	b.WriteString(all[idx])
	for k := idx + 1; k < len(all) && k <= idx+max; k++ {
		if _, _, ok := gpTraceParts(all[k]); ok {
			break // a new timestamped entry ends the block
		}
		b.WriteString("\n")
		b.WriteString(all[k])
	}
	return b.String()
}

var (
	simpleTagRe = regexp.MustCompile(`<([a-zA-Z][\w:-]*)>([^<]*)</[a-zA-Z][\w:-]*>`)
	memberRe    = regexp.MustCompile(`<member>([^<]*)</member>`)
)

// tagValue reads one element's text, tolerating a document that never closes.
func tagValue(body, tag string) string {
	open := "<" + tag + ">"
	i := strings.Index(body, open)
	if i < 0 {
		return ""
	}
	rest := body[i+len(open):]
	j := strings.Index(rest, "</"+tag+">")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// memberList reads the <member> entries inside a container element.
func memberList(body, tag string) []string {
	open, shut := "<"+tag+">", "</"+tag+">"
	i := strings.Index(body, open)
	if i < 0 {
		return nil
	}
	rest := body[i+len(open):]
	if j := strings.Index(rest, shut); j >= 0 {
		rest = rest[:j]
	}
	var out []string
	for _, m := range memberRe.FindAllStringSubmatch(rest, -1) {
		if v := strings.TrimSpace(m[1]); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}
