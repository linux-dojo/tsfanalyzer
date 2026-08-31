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
	// State is "enabled", "disabled" or "unknown". Unknown is a real and
	// common answer: a collection can carry exception configuration without
	// ever stating whether enforcement is on.
	State string    `json:"state"`
	At    time.Time `json:"at,omitempty"`
	// Deciding is the line that settled it, so the answer is checkable.
	Deciding string `json:"deciding,omitempty"`
	// Configured counts exception lines seen. It says the portal pushed
	// enforcer configuration; it does not say enforcement is active.
	Configured int      `json:"configured,omitempty"`
	Exceptions int      `json:"exceptions,omitempty"`
	Domains    int      `json:"domains,omitempty"`
	Wildcards  int      `json:"wildcards,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
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

// GPFacts is everything gathered from the service trace.
type GPFacts struct {
	Enforcer       GPEnforcer        `json:"enforcer"`
	HostDetection  GPHostDetection   `json:"host_detection"`
	CertChecks     []GPCertCheck     `json:"cert_checks,omitempty"`
	Prelogins      []GPPrelogin      `json:"prelogins,omitempty"`
	GatewayConfigs []GPGatewayConfig `json:"gateway_configs,omitempty"`
	// Stages are the "----X starts----" boundaries, in order. They are the
	// authoritative stage sequence: the event log describes what happened,
	// these say which step the agent believed it was on.
	Stages []GPTraceStage `json:"stages,omitempty"`
}

// GPTraceStage is one "----X starts----" boundary from the service trace.
type GPTraceStage struct {
	At    time.Time `json:"at"`
	Name  string    `json:"name"`
	Stage GPStage   `json:"stage"`
}

// CertFailures returns only the checks that actually stopped a pre-login.
func (f GPFacts) CertFailures() []GPCertCheck {
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

	// Configuration, counted but never treated as evidence of enforcement.
	gpEnforcerCfgRe = regexp.MustCompile(`(?i)` +
		`enforcer exception|` +
		`set enforcer exclude route|` +
		`enforcer ip exception|` +
		`traffic enforcement:`)
	// ...except the lines that announce an *empty* list, which say the
	// opposite and must not be counted as configuration either.
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
	return &gpFactScan{facts: &GPFacts{Enforcer: GPEnforcer{State: "unknown"}}}
}

// gpFactScan folds the trace into GPFacts. It is a small state machine because
// several of these facts are spread over consecutive lines: the host-detection
// IP, hostname, query and result are four separate lines, and a certificate
// check is only interpretable once you know whether a pre-login followed it.
type gpFactScan struct {
	facts *GPFacts

	portal string
	// pendingCert indexes into facts.CertChecks for checks not yet resolved.
	pendingCert []int
	// partial host detection being assembled
	ihdIP, ihdHost, ihdLookup string
	ihdAt                     time.Time
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

	// stage boundaries
	if m := gpTraceStartRe.FindStringSubmatch(trimmed); m != nil {
		name := m[1]
		st := traceStageOf(name)
		s.facts.Stages = append(s.facts.Stages, GPTraceStage{At: ts, Name: name, Stage: st})
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
		s.facts.CertChecks = append(s.facts.CertChecks, c)
		s.pendingCert = append(s.pendingCert, len(s.facts.CertChecks)-1)
		return
	}
	if gpCertSkipRe.MatchString(trimmed) {
		for _, i := range s.pendingCert {
			s.facts.CertChecks[i].Skipped = true
		}
		return
	}
	if m := gpReqPortalRe.FindStringSubmatch(trimmed); m != nil && gpPreloginSentRe.MatchString(trimmed) {
		s.portal = m[1]
		for _, i := range s.pendingCert {
			s.facts.CertChecks[i].Portal = s.portal
		}
	}
	if gpPreloginResultRe.MatchString(trimmed) || gpPreloginSentRe.MatchString(trimmed) {
		s.resolvePending(true)
	}
	if gpPreloginResultRe.MatchString(trimmed) {
		s.readPreloginResponse(ts, all, idx)
		return
	}

	// enforcer: state statements first, and they are the only thing that
	// decides it. The last statement wins, since the enforcer can be turned
	// on or off during the life of the log.
	if gpEnforcerOffRe.MatchString(trimmed) {
		e := &s.facts.Enforcer
		e.State, e.At, e.Deciding = "disabled", ts, trimmed
		return
	}
	if gpEnforcerOnRe.MatchString(trimmed) {
		e := &s.facts.Enforcer
		e.State, e.At, e.Deciding = "enabled", ts, trimmed
		return
	}
	if gpEnforcerCfgRe.MatchString(trimmed) && !gpEnforcerEmptyRe.MatchString(trimmed) {
		e := &s.facts.Enforcer
		e.Configured++
		if len(e.Evidence) < 5 {
			e.Evidence = append(e.Evidence, trimmed)
		}
		if m := gpEnforcerCountRe.FindStringSubmatch(trimmed); m != nil {
			e.Exceptions = atoiSafe(m[2]) - atoiSafe(m[1]) + 1
		}
		if m := gpEnforcerDomRe.FindStringSubmatch(trimmed); m != nil {
			e.Domains, e.Wildcards = atoiSafe(m[1]), atoiSafe(m[2])
		}
		return
	}

	// internal host detection
	switch {
	case gpIHDNoneRe.MatchString(trimmed):
		if !s.facts.HostDetection.Configured {
			s.facts.HostDetection.Detail = trimmed
			s.facts.HostDetection.At = ts
		}
		return
	case gpIHDNoV6Re.MatchString(trimmed):
		s.facts.HostDetection.IPv6 = false
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
		h := &s.facts.HostDetection
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
		s.facts.GatewayConfigs = append(s.facts.GatewayConfigs,
			parseGatewayConfig(m[1], ts, all, idx))
		return
	}
}

func (s *gpFactScan) resolvePending(proceeded bool) {
	for _, i := range s.pendingCert {
		c := &s.facts.CertChecks[i]
		c.Proceeded = proceeded
		// Only a check that was neither skipped nor followed by a pre-login is
		// a failure. See the note on GPCertCheck: the raw code is not enough.
		c.Failed = !proceeded && !c.Skipped
	}
	s.pendingCert = s.pendingCert[:0]
}

func (s *gpFactScan) close() { s.resolvePending(false) }

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
		s.facts.Prelogins = append(s.facts.Prelogins, p)
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
