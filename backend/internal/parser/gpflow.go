// Package parser: gpflow.go answers the question you actually have in front of
// a GlobalProtect log — how far did the connection get, and what stopped it.
//
// A connection is a fixed sequence of stages, and each one can only be reached
// if the previous one succeeded:
//
//	portal pre-login  → is the portal reachable, is its certificate acceptable
//	portal auth       → does the user authenticate to the portal
//	portal config     → the agent config, including the gateway list, is fetched
//	network discovery → internal or external network
//	gateway select    → gateways are scored and one is chosen
//	gateway auth      → login to the chosen gateway
//	tunnel            → SSL or IPSec tunnel established
//	HIP               → the host information report is checked and submitted
//
// Recording the furthest stage reached per attempt turns a wall of log lines
// into "seven attempts, all six of the early ones stopped at gateway
// selection, the last one completed" — which is the diagnosis.
//
// # Gateway selection
//
// When a portal serves more than one gateway the app contacts all of them and
// scores each on priority and response time. Since GlobalProtect app 4.0.3 the
// highest/high/medium priorities are tried ahead of low/lowest regardless of
// response time, with the low ones appended after; in 4.0.2 and earlier a
// lower-priority gateway could win outright if a higher-priority one answered
// more slowly than the average across all gateways. A gateway whose configured
// region does not contain the client's source address is scored -2 and drops
// out of contention, which is a common and very quiet cause of "connected to
// the portal but never to a gateway".
//
// See the Palo Alto Networks documentation on gateway priority in a
// multiple-gateway configuration.
package parser

import (
	"archive/tar"
	"bufio"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

/* ---------- stages ---------- */

// GPStage names one step of a connection, in the order they must happen.
type GPStage string

const (
	StagePortalPrelogin GPStage = "portal pre-login"
	StagePortalAuth     GPStage = "portal auth"
	StagePortalConfig   GPStage = "portal config"
	StageDiscovery      GPStage = "network discovery"
	StageGatewaySelect  GPStage = "gateway select"
	StageGatewayAuth    GPStage = "gateway auth"
	StageTunnel         GPStage = "tunnel"
	StageHIP            GPStage = "HIP"
)

// GPStageOrder is the sequence, used to decide how far an attempt got.
var GPStageOrder = []GPStage{
	StagePortalPrelogin, StagePortalAuth, StagePortalConfig, StageDiscovery,
	StageGatewaySelect, StageGatewayAuth, StageTunnel, StageHIP,
}

func stageIndex(s GPStage) int {
	for i, v := range GPStageOrder {
		if v == s {
			return i
		}
	}
	return -1
}

// GPStageResult is one stage's outcome within an attempt.
type GPStageResult struct {
	Stage  GPStage   `json:"stage"`
	Status string    `json:"status"` // ok | failed | reached | not reached
	At     time.Time `json:"at,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// GPAttempt is one attempt at connecting, from portal pre-login onwards.
type GPAttempt struct {
	Start   time.Time       `json:"start"`
	End     time.Time       `json:"end"`
	Stages  []GPStageResult `json:"stages"`
	Reached GPStage         `json:"reached"`  // furthest stage touched
	StopAt  GPStage         `json:"stop_at"`  // where it stopped, if it did
	Outcome string          `json:"outcome"`  // connected | failed | incomplete
	Reason  string          `json:"reason,omitempty"`
	Portal  string          `json:"portal,omitempty"`
	Gateway string          `json:"gateway,omitempty"`
	User    string          `json:"user,omitempty"`
	Events  int             `json:"events"`

	// How the user got through the portal, and how the gateway was satisfied.
	// The point of single sign-on here is that the portal authenticates
	// interactively once, hands back a cookie, and the gateway accepts that
	// cookie instead of prompting again — so seeing "browser" at the portal and
	// "cookie" at the gateway is the configuration working, while "browser" at
	// both means the cookie was rejected or missing.
	PortalAuth  string `json:"portal_auth,omitempty"`  // browser | cookie | credentials
	GatewayAuth string `json:"gateway_auth,omitempty"` // cookie | browser
	// CookieWait is how long the interactive portion took, i.e. how long the
	// user spent in the identity provider's page.
	CookieWaitSecs float64 `json:"cookie_wait_secs,omitempty"`
	// SingleSignOn is set when the portal authenticated interactively and the
	// gateway was satisfied by the cookie alone — the intended behaviour.
	SingleSignOn bool `json:"single_sign_on,omitempty"`

	// scratch, not serialised
	gatewayPhase  bool
	browserAt     time.Time
	cookieWritten bool
	cookieMissing bool
	// awaitingAuth is set while an interactive login is outstanding. The agent
	// re-issues a portal pre-login when the browser hands control back, so a
	// pre-login arriving in this state continues the attempt rather than
	// starting a new one — without this, one user-facing login is split in two
	// and the cookie hand-off between portal and gateway is lost.
	awaitingAuth bool
}

// stageMarker maps an event-log message to a stage and what it says about it.
type stageMarker struct {
	re     *regexp.Regexp
	stage  GPStage
	status string // ok | failed | reached
	reason string // used when status is failed and the line is not self-explanatory
}

// Ordered: the first match wins, so successes and failures precede the
// general "we got here" markers for the same stage.
var gpStageMarkers = []stageMarker{
	// portal pre-login
	{regexp.MustCompile(`(?i)failed to pre ?- ?login to the portal`), StagePortalPrelogin, "failed", "the portal did not answer the pre-login request"},
	{regexp.MustCompile(`(?i)portal status is Invalid portal`), StagePortalPrelogin, "failed", "portal address rejected or unreachable"},
	{regexp.MustCompile(`(?i)portal pre-login result received`), StagePortalPrelogin, "ok", ""},
	{regexp.MustCompile(`(?i)started the portal pre ?- ?login`), StagePortalPrelogin, "reached", ""},

	// portal authentication
	{regexp.MustCompile(`(?i)auth failed for portal|portal status is User authentication failed`), StagePortalAuth, "failed", "the portal rejected the credentials"},
	{regexp.MustCompile(`(?i)portal status is Connected`), StagePortalAuth, "ok", ""},
	{regexp.MustCompile(`(?i)portal login starts|logging into portal`), StagePortalAuth, "reached", ""},

	// portal configuration (the agent config and gateway list come with it)
	{regexp.MustCompile(`(?i)portal login completed with address`), StagePortalConfig, "ok", ""},
	{regexp.MustCompile(`(?i)matching client config not found|no client configuration`), StagePortalConfig, "failed", "the portal has no agent config matching this user or device"},

	// network discovery
	{regexp.MustCompile(`(?i)network discovery started|discovering (internal|external) network`), StageDiscovery, "reached", ""},

	// gateway selection and login
	{regexp.MustCompile(`(?i)gateway pre-?login starts to|prelogin to gateway`), StageGatewaySelect, "ok", ""},
	{regexp.MustCompile(`(?i)gateway login (finished|starts) `), StageGatewayAuth, "reached", ""},
	{regexp.MustCompile(`(?i)(auto |manual )?gateway login finished with address`), StageGatewayAuth, "ok", ""},

	// tunnel
	{regexp.MustCompile(`(?i)(ipsec|ssl) tunnel creation finished`), StageTunnel, "ok", ""},
	{regexp.MustCompile(`(?i)trying to create tunnel with gateway`), StageTunnel, "reached", ""},
	{regexp.MustCompile(`(?i)tunnel creation failed|failed to create tunnel`), StageTunnel, "failed", "the tunnel could not be established"},

	// HIP
	{regexp.MustCompile(`(?i)hip report submitted to the gateway`), StageHIP, "ok", ""},
	{regexp.MustCompile(`(?i)completed hip report check with gateway`), StageHIP, "reached", ""},
}

var (
	gpAttemptStartRe = regexp.MustCompile(`(?i)^(started the portal pre ?- ?login|SSO starts)`)
	// The one error the agent emits for "no gateway could be used", whatever
	// the underlying cause. On its own it is unhelpful, so the gateway
	// analysis below supplies the reason.
	gpNoGatewayRe   = regexp.MustCompile(`(?i)network connection is unreachable or the gateway is unresponsive`)
	gpNoNetworkRe   = regexp.MustCompile(`(?i)no network connectivity`)
	gpFlowPortalRe  = regexp.MustCompile(`(?i)(?:portal|to the portal) ([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z0-9.\-]+)`)
	gpFlowGatewayRe = regexp.MustCompile(`(?i)(?:gateway|with Gateway|to gateway) ([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z0-9.\-]+)`)
	gpFlowUserRe    = regexp.MustCompile(`(?i)and user (\S+?)\.?$`)

	// The cookie is the whole mechanism behind not authenticating twice.
	// PanPUAC is the portal user auth cookie: the portal issues it after an
	// interactive login, the agent stores it encrypted, and the gateway accepts
	// it in place of a second prompt.
	gpBrowserRe      = regexp.MustCompile(`(?i)Load the SAML Browser|ShowPage - using (embedded|default) browser|SAMLDlg`)
	gpCookieOKRe     = regexp.MustCompile(`(?i)Unserialized non-empty cookie for portal (\S+) and user (\S+)`)
	gpCookieMissRe   = regexp.MustCompile(`(?i)Failed to open file .*PanPUAC_|Failed to UnserializePortalPrelogonAuthCookie`)
	gpCookieWriteRe  = regexp.MustCompile(`(?i)Serialize non-empty cookie for portal (\S+) and user (\S+)|Serialized portal user auth cookie to file`)
	gpCredPromptRe   = regexp.MustCompile(`(?i)Enter login credentials|authentication-message`)
	gpGatewayLoginRe = regexp.MustCompile(`(?i)Gateway (pre-?Login Starts|Login starts)`)
	// the portal has ruled one way or the other, so nothing interactive is
	// outstanding any more
	gpPortalSettledRe = regexp.MustCompile(
		`(?i)portal status is (Connected|User authentication failed|Invalid portal)|Auth failed for portal`)
)

// ExtractGPAttempts segments the event log into attempts and works out how far
// each one got. Every attempt begins with a portal pre-login or an SSO start;
// anything before the first of those is ignored, since it cannot be attributed.
func ExtractGPAttempts(r io.ReadSeeker) ([]GPAttempt, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	var lines []gpFlowLine
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
		if strings.ToLower(baseName(hdr.Name)) != "pan_gp_event.log" {
			continue
		}
		sc := bufio.NewScanner(tr)
		sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
		for sc.Scan() {
			m := gpEventLineRe.FindStringSubmatch(strings.TrimRight(sc.Text(), "\r"))
			if m == nil {
				continue
			}
			if t, ok := parseGPTime(m[1], m[2]); ok {
				lines = append(lines, gpFlowLine{ts: t, sev: strings.TrimSpace(m[4]), msg: m[5]})
			}
		}
	}
	return attemptsFromLines(lines), nil
}

type gpFlowLine struct {
	ts  time.Time
	sev string
	msg string
}

func attemptsFromLines(lines []gpFlowLine) []GPAttempt {
	var out []GPAttempt
	var cur *GPAttempt
	best := map[GPStage]GPStageResult{}

	flush := func() {
		if cur == nil {
			return
		}
		cur.Stages = nil
		for _, s := range GPStageOrder {
			if r, ok := best[s]; ok {
				cur.Stages = append(cur.Stages, r)
			} else {
				cur.Stages = append(cur.Stages, GPStageResult{Stage: s, Status: "not reached"})
			}
		}
		finishAttempt(cur)
		out = append(out, *cur)
		cur = nil
		best = map[GPStage]GPStageResult{}
	}

	for _, l := range lines {
		if gpAttemptStartRe.MatchString(l.msg) {
			// A pre-login immediately after an SSO start is the same attempt,
			// not a new one: SSO is how the attempt begins. Nor is it a new
			// attempt while an interactive login is still outstanding — the
			// browser round-trip re-issues the pre-login when it returns.
			waiting := cur != nil && cur.awaitingAuth
			if cur == nil || (!waiting && l.ts.Sub(cur.Start) > 2*time.Second) {
				flush()
				cur = &GPAttempt{Start: l.ts}
			}
		}
		if cur == nil {
			continue
		}
		cur.End = l.ts
		cur.Events++

		if cur.Portal == "" {
			if m := gpFlowPortalRe.FindStringSubmatch(l.msg); m != nil {
				cur.Portal = m[1]
			}
		}
		if m := gpFlowUserRe.FindStringSubmatch(l.msg); m != nil &&
			!strings.EqualFold(m[1], "pre-logon") && cur.User == "" {
			cur.User = strings.TrimSuffix(m[1], ".")
		}

		// Track how each half was authenticated. "atGateway" flips once the
		// gateway phase starts, so the same cookie and browser markers can be
		// attributed to the right side of the exchange.
		atGateway := gpGatewayLoginRe.MatchString(l.msg) || cur.gatewayPhase
		if atGateway {
			cur.gatewayPhase = true
		}
		switch {
		case gpBrowserRe.MatchString(l.msg):
			if atGateway {
				cur.GatewayAuth = "browser"
			} else {
				cur.PortalAuth = "browser"
				if cur.browserAt.IsZero() {
					cur.browserAt = l.ts
				}
				cur.awaitingAuth = true
			}
		case gpCookieOKRe.MatchString(l.msg):
			if atGateway {
				if cur.GatewayAuth == "" {
					cur.GatewayAuth = "cookie"
				}
			} else if cur.PortalAuth == "" {
				cur.PortalAuth = "cookie"
			}
		case gpCredPromptRe.MatchString(l.msg):
			if !atGateway && cur.PortalAuth == "" {
				cur.PortalAuth = "credentials"
			}
		case gpCookieWriteRe.MatchString(l.msg):
			cur.cookieWritten = true
		case gpCookieMissRe.MatchString(l.msg):
			cur.cookieMissing = true
		}
		// the interactive login is over once the portal has ruled either way
		if gpPortalSettledRe.MatchString(l.msg) {
			cur.awaitingAuth = false
		}
		if !cur.browserAt.IsZero() && cur.PortalAuth == "browser" && cur.CookieWaitSecs == 0 {
			if strings.Contains(strings.ToLower(l.msg), "logging into portal") {
				cur.CookieWaitSecs = l.ts.Sub(cur.browserAt).Seconds()
			}
		}

		matched := false
		for _, mk := range gpStageMarkers {
			if !mk.re.MatchString(l.msg) {
				continue
			}
			matched = true
			res := GPStageResult{Stage: mk.stage, Status: mk.status, At: l.ts, Detail: l.msg}
			if mk.status == "failed" && mk.reason != "" {
				res.Detail = mk.reason
			}
			// keep the strongest statement about a stage: a failure or a
			// success beats a bare "reached", and a later failure beats an
			// earlier success within the same attempt
			if prev, ok := best[mk.stage]; !ok || rank(mk.status) >= rank(prev.Status) {
				best[mk.stage] = res
			}
			if mk.stage == StageGatewayAuth || mk.stage == StageTunnel || mk.stage == StageHIP {
				if g := gpFlowGatewayRe.FindStringSubmatch(l.msg); g != nil {
					cur.Gateway = g[1]
				}
			}
			break
		}

		if !matched && gpNoGatewayRe.MatchString(l.msg) {
			// This is the "no usable gateway" error. It arrives after
			// discovery, so it belongs to gateway selection.
			if prev, ok := best[StageGatewaySelect]; !ok || prev.Status != "ok" {
				best[StageGatewaySelect] = GPStageResult{
					Stage: StageGatewaySelect, Status: "failed", At: l.ts,
					Detail: "no gateway could be used — see the gateway table for priority and region scoring",
				}
			}
		}
		if !matched && gpNoNetworkRe.MatchString(l.msg) {
			if prev, ok := best[StagePortalPrelogin]; !ok || prev.Status != "ok" {
				best[StagePortalPrelogin] = GPStageResult{
					Stage: StagePortalPrelogin, Status: "failed", At: l.ts,
					Detail: "no network connectivity to the portal",
				}
			}
		}
	}
	flush()
	return out
}

func rank(status string) int {
	switch status {
	case "failed":
		return 3
	case "ok":
		return 2
	case "reached":
		return 1
	}
	return 0
}

// finishAttempt derives the verdict from the stages that were recorded.
func finishAttempt(a *GPAttempt) {
	furthest := -1
	firstFail := -1
	for _, s := range a.Stages {
		i := stageIndex(s.Stage)
		if s.Status == "not reached" {
			continue
		}
		if i > furthest {
			furthest = i
		}
		if s.Status == "failed" && (firstFail < 0 || i < firstFail) {
			firstFail = i
			a.Reason = s.Detail
		}
	}
	if furthest >= 0 {
		a.Reached = GPStageOrder[furthest]
	}
	// The portal prompted, the gateway did not: the cookie did its job.
	a.SingleSignOn = (a.PortalAuth == "browser" || a.PortalAuth == "credentials") &&
		a.GatewayAuth == "cookie"
	switch {
	case firstFail >= 0:
		a.Outcome, a.StopAt = "failed", GPStageOrder[firstFail]
	case tunnelUp(a):
		a.Outcome = "connected"
	default:
		a.Outcome = "incomplete"
		if furthest >= 0 {
			a.StopAt = GPStageOrder[furthest]
			a.Reason = "the attempt stopped after " + string(a.StopAt) + " with no further activity"
		}
	}
}

func tunnelUp(a *GPAttempt) bool {
	for _, s := range a.Stages {
		if s.Stage == StageTunnel && s.Status == "ok" {
			return true
		}
	}
	return false
}

/* ---------- authentication ---------- */

// GPAuthEvent is one authentication, at one target. A single connection
// normally produces two: the portal, which prompts, and the gateway, which
// should be satisfied by the cookie the portal issued.
type GPAuthEvent struct {
	Ts      time.Time `json:"ts"`
	User    string    `json:"user,omitempty"`
	Target  string    `json:"target"`  // portal | gateway
	Address string    `json:"address,omitempty"`
	Method  string    `json:"method,omitempty"`  // browser | cookie | credentials
	Outcome string    `json:"outcome"`           // success | failed | not reached
	Detail  string    `json:"detail,omitempty"`
	// WaitSecs is how long an interactive login took — the time the user spent
	// in the identity provider's page.
	WaitSecs float64 `json:"wait_secs,omitempty"`
	// SingleSignOn is set on a gateway row that was satisfied by the cookie
	// after the portal had prompted: the configuration working as intended.
	SingleSignOn bool `json:"single_sign_on,omitempty"`
}

// methodLabel spells out what the agent actually did, since "browser" alone
// does not say it was interactive.
func methodLabel(m string) string {
	switch m {
	case "browser":
		return "SAML (browser)"
	case "cookie":
		return "cookie reuse"
	case "credentials":
		return "credentials"
	}
	return ""
}

// GPAuthEvents flattens the attempts into one row per authentication, which is
// what you want to scan when the question is "who authenticated, where, how,
// and did it work". It is derived from the attempts rather than re-scanned, so
// the Authentication and Connection views can never disagree.
func GPAuthEvents(attempts []GPAttempt) []GPAuthEvent {
	out := []GPAuthEvent{}
	for _, a := range attempts {
		stage := func(s GPStage) (string, time.Time, string) {
			for _, x := range a.Stages {
				if x.Stage == s {
					return x.Status, x.At, x.Detail
				}
			}
			return "not reached", time.Time{}, ""
		}

		// the portal half
		st, at, detail := stage(StagePortalAuth)
		if at.IsZero() {
			at = a.Start
		}
		if st != "not reached" || a.PortalAuth != "" {
			out = append(out, GPAuthEvent{
				Ts: at, User: a.User, Target: "portal", Address: a.Portal,
				Method: methodLabel(a.PortalAuth), Outcome: outcomeWord(st),
				Detail: detail, WaitSecs: a.CookieWaitSecs,
			})
		}

		// the gateway half, only when it was actually attempted
		gst, gat, gdetail := stage(StageGatewayAuth)
		if gst != "not reached" || a.GatewayAuth != "" {
			if gat.IsZero() {
				gat = at
			}
			out = append(out, GPAuthEvent{
				Ts: gat, User: a.User, Target: "gateway", Address: a.Gateway,
				Method: methodLabel(a.GatewayAuth), Outcome: outcomeWord(gst),
				Detail: gdetail, SingleSignOn: a.SingleSignOn,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Ts.Before(out[j].Ts) })
	return out
}

func outcomeWord(status string) string {
	switch status {
	case "ok":
		return "success"
	case "failed":
		return "failed"
	case "reached":
		// the stage started but nothing said how it ended
		return "incomplete"
	}
	return "not reached"
}

/* ---------- gateway selection ---------- */

// GPGateway is one gateway the portal offered, with everything the agent
// recorded about scoring it.
type GPGateway struct {
	FQDN     string `json:"fqdn"`
	Name     string `json:"name,omitempty"` // the configured display name
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	Priority *int   `json:"priority,omitempty"`
	Manual   *bool  `json:"manual,omitempty"`
	// RegionMatch is false when the client's source address falls outside the
	// gateway's configured region, which scores it -2 and takes it out of
	// contention.
	RegionMatch *bool  `json:"region_match,omitempty"`
	Region      string `json:"region,omitempty"`
	// TCPMillis is the connection time the agent measured, the "response time"
	// half of the selection rule.
	TCPMillis *int `json:"tcp_ms,omitempty"`
	// SSLMillis and Weight come from the compact scoring line a
	// multiple-gateway deployment emits. Weight is the composite score the
	// agent ranks on, and lower wins.
	SSLMillis *int `json:"ssl_ms,omitempty"`
	Weight    *int `json:"weight,omitempty"`
	Selected  bool `json:"selected"`
	Internal  bool `json:"internal"`
}

// GPGatewaySelection is the whole picture: the candidates, how they were
// scored, and which one won.
type GPGatewaySelection struct {
	Type        string      `json:"type,omitempty"` // auto | manual
	Gateways    []GPGateway `json:"gateways"`
	Best        string      `json:"best,omitempty"`
	CutoffSecs  *int        `json:"cutoff_secs,omitempty"`
	ExternalCnt *int        `json:"external_count,omitempty"`
	InternalCnt *int        `json:"internal_count,omitempty"`
	// Notes explains what the scoring implies, including the region-mismatch
	// case that silently removes every candidate.
	Notes []string `json:"notes,omitempty"`
}

var (
	gwListRe      = regexp.MustCompile(`(?i)Parse gateway list for user (\S+)`)
	gwEntryRe     = regexp.MustCompile(`Gateway (\S+?)\(([^)]*)\): ipv4 (\S*), ipv6 (\S*), FQDN (\w+)`)
	gwPriorityRe  = regexp.MustCompile(`(?i)One (external|internal) gateway (\S+?), priority=(-?\d+), manual is (\d)`)
	gwRegionBadRe = regexp.MustCompile(`(?i)One (?:external|internal) gateway and the priority is (-?\d+), region does not match`)
	gwRegionPrioRe = regexp.MustCompile(
		`REGION-PRIO, gateway \d+\(([^)]*)\).*?region = (\S+), priority = (-?\d+), portalRegion=(\S+)`)
	gwTCPRe    = regexp.MustCompile(`(?i)tcp connection time is (\d+)`)
	gwSelTypeRe = regexp.MustCompile(`(?i)Gateway selection type is (\w+)`)
	gwBestRe    = regexp.MustCompile(`(?i)m_pBestGateway=\w+ \(gateway=([^)]+)\)`)
	gwCountRe   = regexp.MustCompile(`(?i)gateway count is (\d+), cutoff time is (\d+)`)
	gwIntCntRe  = regexp.MustCompile(`(?i)Gateway count is (\d+) for internal network`)
	gwEmptyRe   = regexp.MustCompile(`(?i)gateway list is empty`)

	// A deployment with several gateways summarises the whole comparison on one
	// line, by display name rather than FQDN:
	//   Gateway selection(Priority-TCP-SSL-Weight): US Northwest(5-419-349-300),
	//   India West(1-210-206-20), Netherlands Central(5-373-295-262).
	// This is the authoritative record of how the choice was made, and the
	// per-gateway priority lines are not emitted in this case.
	gwScoreLineRe  = regexp.MustCompile(`(?i)Gateway selection\(Priority-TCP-SSL-Weight\):\s*(.+)`)
	gwScoreEntryRe = regexp.MustCompile(`([^(,]+?)\s*\((\d+)-(\d+)-(\d+)-(\d+)\)`)
)

// gwScore is one gateway's entry on the compact scoring line.
type gwScore struct {
	name                        string
	priority, tcp, ssl, weight int
}

// parseGatewayScoreLine reads the comma-separated Name(P-TCP-SSL-Weight) list.
func parseGatewayScoreLine(rest string) []gwScore {
	var out []gwScore
	for _, m := range gwScoreEntryRe.FindAllStringSubmatch(rest, -1) {
		name := strings.TrimSpace(m[1])
		if name == "" {
			continue
		}
		p, _ := strconv.Atoi(m[2])
		tcp, _ := strconv.Atoi(m[3])
		ssl, _ := strconv.Atoi(m[4])
		w, _ := strconv.Atoi(m[5])
		out = append(out, gwScore{name: name, priority: p, tcp: tcp, ssl: ssl, weight: w})
	}
	return out
}

// rotationIndex returns how old a log file is: 0 for the live file,
// 1 for PanGPS.1.log, 2 for PanGPS.2.log and so on. Higher is older.
func rotationIndex(base string) int {
	// PanGPS.log -> 0, PanGPS.1.log -> 1
	parts := strings.Split(strings.TrimSuffix(base, ".log"), ".")
	if len(parts) < 2 {
		return 0
	}
	if n, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
		return n
	}
	return 0
}

// ExtractGPGateways reads the gateway list and its scoring out of the PanGPS
// logs.
//
// Two things this has to get right, both found by running it over real
// collections. Rotated files must be read oldest first — a tar lists members
// in arbitrary order, and reading PanGPS.1.log after PanGPS.log let a stale
// round overwrite the current one. And the agent re-scores every gateway on
// each attempt, so observations are grouped into rounds delimited by "Parse
// gateway list", and only the last round is reported: earlier rounds can
// belong to a different portal entirely and their gateways no longer apply.
func ExtractGPGateways(r io.ReadSeeker) (*GPGatewaySelection, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}

	// Collect only the lines that matter, keyed by how old the file is, so
	// memory stays proportional to the gateway activity rather than the logs.
	interesting := []*regexp.Regexp{
		gwListRe, gwEntryRe, gwPriorityRe, gwRegionBadRe, gwRegionPrioRe,
		gwTCPRe, gwSelTypeRe, gwBestRe, gwCountRe, gwIntCntRe, gwEmptyRe,
		gwScoreLineRe,
	}
	byAge := map[int][]string{}
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
		// The scoring line also appears in the event log, which is not rotated;
		// treat it as the newest source so it never loses to an older PanGPS.
		isGPS := strings.HasPrefix(base, "pangps") && strings.HasSuffix(base, ".log")
		if !isGPS && base != "pan_gp_event.log" {
			continue
		}
		age := 0
		if isGPS {
			age = rotationIndex(base)
		}
		sc := bufio.NewScanner(tr)
		sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			for _, re := range interesting {
				if re.MatchString(line) {
					byAge[age] = append(byAge[age], line)
					break
				}
			}
		}
	}

	ages := make([]int, 0, len(byAge))
	for a := range byAge {
		ages = append(ages, a)
	}
	// oldest first: a higher rotation number is an older file
	for i := 0; i < len(ages); i++ {
		for j := i + 1; j < len(ages); j++ {
			if ages[j] > ages[i] {
				ages[i], ages[j] = ages[j], ages[i]
			}
		}
	}

	sel := &GPGatewaySelection{Gateways: []GPGateway{}}
	sawEmpty := false
	regionByName := map[string]string{}

	// per-round state, reset whenever a new gateway list is parsed
	byFQDN := map[string]*GPGateway{}
	var order []string
	var lastTCP *int
	resetRound := func() {
		byFQDN = map[string]*GPGateway{}
		order = nil
		lastTCP = nil
	}
	get := func(fqdn string) *GPGateway {
		if g, ok := byFQDN[fqdn]; ok {
			return g
		}
		g := &GPGateway{FQDN: fqdn}
		byFQDN[fqdn] = g
		order = append(order, fqdn)
		return g
	}

	for _, age := range ages {
		for _, line := range byAge[age] {
			switch {
			case gwListRe.MatchString(line):
				resetRound()

			case gwEntryRe.MatchString(line):
				m := gwEntryRe.FindStringSubmatch(line)
				g := get(m[1])
				g.Name, g.IPv4, g.IPv6 = m[2], m[3], m[4]

			case gwPriorityRe.MatchString(line):
				m := gwPriorityRe.FindStringSubmatch(line)
				g := get(m[2])
				if p, err := strconv.Atoi(m[3]); err == nil {
					g.Priority = &p
				}
				man := m[4] == "1"
				g.Manual = &man
				g.Internal = strings.EqualFold(m[1], "internal")
				yes := true
				g.RegionMatch = &yes // until a mismatch line says otherwise
				if lastTCP != nil {
					g.TCPMillis = lastTCP
					lastTCP = nil
				}

			case gwRegionBadRe.MatchString(line):
				// applies to the gateway named on the preceding priority line
				m := gwRegionBadRe.FindStringSubmatch(line)
				if len(order) > 0 {
					g := byFQDN[order[len(order)-1]]
					no := false
					g.RegionMatch = &no
					if p, err := strconv.Atoi(m[1]); err == nil {
						g.Priority = &p
					}
				}

			case gwRegionPrioRe.MatchString(line):
				m := gwRegionPrioRe.FindStringSubmatch(line)
				regionByName[m[1]] = m[2]

			case gwTCPRe.MatchString(line):
				m := gwTCPRe.FindStringSubmatch(line)
				if v, err := strconv.Atoi(m[1]); err == nil {
					lastTCP = &v
				}

			case gwSelTypeRe.MatchString(line):
				sel.Type = strings.ToLower(gwSelTypeRe.FindStringSubmatch(line)[1])

			case gwBestRe.MatchString(line):
				sel.Best = gwBestRe.FindStringSubmatch(line)[1]

			case gwCountRe.MatchString(line):
				m := gwCountRe.FindStringSubmatch(line)
				if v, err := strconv.Atoi(m[1]); err == nil {
					sel.ExternalCnt = &v
				}
				if v, err := strconv.Atoi(m[2]); err == nil {
					sel.CutoffSecs = &v
				}

			case gwIntCntRe.MatchString(line):
				m := gwIntCntRe.FindStringSubmatch(line)
				if v, err := strconv.Atoi(m[1]); err == nil {
					sel.InternalCnt = &v
				}

			case gwScoreLineRe.MatchString(line):
				// The compact line is the whole comparison, so it replaces
				// whatever the round had gathered by name.
				scores := parseGatewayScoreLine(gwScoreLineRe.FindStringSubmatch(line)[1])
				if len(scores) == 0 {
					break
				}
				byName := map[string]*GPGateway{}
				for _, f := range order {
					if n := byFQDN[f].Name; n != "" {
						byName[strings.ToLower(n)] = byFQDN[f]
					}
				}
				bestWeight := 0
				bestName := ""
				for i, s := range scores {
					g, ok := byName[strings.ToLower(s.name)]
					if !ok {
						// scored but never listed by FQDN: keep it under its
						// display name rather than lose it
						g = get(s.name)
						g.Name = s.name
					}
					p, tcp, ssl, w := s.priority, s.tcp, s.ssl, s.weight
					g.Priority, g.TCPMillis, g.SSLMillis, g.Weight = &p, &tcp, &ssl, &w
					if i == 0 || w < bestWeight {
						bestWeight, bestName = w, g.FQDN
					}
				}
				// lower weight wins; only fill Best if nothing more explicit said so
				if sel.Best == "" && bestName != "" {
					sel.Best = bestName
				}

			case gwEmptyRe.MatchString(line):
				sawEmpty = true
			}
		}
	}

	for _, f := range order {
		g := byFQDN[f]
		if reg, ok := regionByName[g.Name]; ok {
			g.Region = reg
		}
		g.Selected = sel.Best != "" && strings.EqualFold(sel.Best, g.FQDN)
		sel.Gateways = append(sel.Gateways, *g)
	}
	sel.Notes = gatewayNotes(sel, sawEmpty)
	return sel, nil
}

// gatewayNotes explains what the numbers mean, because the agent's own error
// for all of these cases is the same unhelpful sentence about the network
// being unreachable.
func gatewayNotes(sel *GPGatewaySelection, sawEmpty bool) []string {
	var notes []string
	mismatch := 0
	negative := 0
	for _, g := range sel.Gateways {
		if g.RegionMatch != nil && !*g.RegionMatch {
			mismatch++
		}
		if g.Priority != nil && *g.Priority < 0 {
			negative++
		}
	}
	if mismatch > 0 {
		notes = append(notes, "The client's source address falls outside the configured region on "+
			plural(mismatch, "gateway", "gateways")+", which scores it -2 and removes it from "+
			"contention. This is a common cause of connecting to the portal but never to a gateway.")
	}
	if negative > 0 && negative == len(sel.Gateways) {
		notes = append(notes, "Every gateway scored below zero, so no gateway was eligible — "+
			"the agent reports this only as the network being unreachable.")
	}
	if sawEmpty {
		notes = append(notes, "The agent logged an empty gateway list at least once: the portal "+
			"returned no gateway for this user, which points at the agent configuration on the portal "+
			"rather than at the network.")
	}
	if len(sel.Gateways) > 1 {
		notes = append(notes, "With more than one gateway, priority and response time both count. "+
			"Since app 4.0.3 the highest, high and medium priorities are tried ahead of low and lowest "+
			"regardless of response time; before 4.0.3 a slower high-priority gateway could lose to a "+
			"faster low-priority one.")
	}
	if scored := countScored(sel); scored > 1 {
		notes = append(notes, "Weight is the composite score the agent ranks on, combining priority "+
			"with the measured TCP and SSL response times — the lowest weight wins.")
	}
	return notes
}

func countScored(sel *GPGatewaySelection) int {
	n := 0
	for _, g := range sel.Gateways {
		if g.Weight != nil {
			n++
		}
	}
	return n
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
