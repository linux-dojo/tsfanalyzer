// Package parser: gpportal.go groups everything a GlobalProtect collection
// knows by the portal it belongs to.
//
// An endpoint often talks to more than one portal — a lab firewall and a
// Prisma Access tenant, say — and each portal has its own gateway list, its own
// user, its own authentication method and its own region. Reporting a single
// flat gateway list mixes them, and the count comes out wrong: the lab portal
// serves one gateway, the Prisma tenant six. Everything here is therefore keyed
// on the portal address.
//
// # How a portal round is read
//
// The agent brackets its phases with distinctive markers, which makes the
// grouping reliable rather than heuristic:
//
//	----Portal Pre-login starts----      a new attempt at some portal
//	<region>IN</region>                  the region the portal placed us in
//	<saml-auth-method>POST</…>           how the portal wants us to authenticate
//	----Portal Login starts----
//	--Set state to Retrieving configuration...
//	Discover external gateway: gateway count is 6, cutoff time is 5
//	gateway <fqdn> priority is 5         one line per configured gateway
//	leave low and lowest priority for last selection
//	gateway 2 of <fqdn> is manual select only, will not be in rediscover list
//	REGION-PRIO, gateway 4 is not selectable base on region
//	Process gateway: host <fqdn>, description US Northwest
//	gateway US Northwest (<fqdn>), priority=5, duration=349 ms, assign 300 as its weight
//	PickGatewayBaseOnWeight, … chose prefered gateway index =1, gateway is India West
//	----Gateway Pre-login starts----
//	----Tunnel Creation starts----
//
// The exclusion lines refer to gateways by their index in the discovery round,
// so the order of the "priority is" lines has to be preserved to attribute them.
//
// A gateway excluded as manual-only or out of region never gets measured, so it
// has no weight — which is exactly why counting only the measured ones
// understated the list.
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

/* ---------- model ---------- */

// GPPortalGateway is one gateway as a specific portal offered it.
type GPPortalGateway struct {
	FQDN string `json:"fqdn"`
	Name string `json:"name,omitempty"` // the portal's description for it
	IPv4 string `json:"ipv4,omitempty"`

	Priority   *int `json:"priority,omitempty"`
	DurationMS *int `json:"duration_ms,omitempty"`
	Weight     *int `json:"weight,omitempty"`

	// Excluded says why a gateway was never in contention: "region" when the
	// client's location does not match, "manual-only" when it is configured
	// for manual selection. Empty means it was a candidate.
	Excluded string `json:"excluded,omitempty"`
	Selected bool   `json:"selected"`
}

// GPPortal is one portal and everything associated with it.
type GPPortal struct {
	Address string `json:"address"`
	Region  string `json:"region,omitempty"`
	User    string `json:"user,omitempty"`

	// AuthMethod is what the portal asked for, and Browser how the interactive
	// part was presented, when it was SAML.
	AuthMethod string `json:"auth_method,omitempty"`
	Browser    string `json:"browser,omitempty"`
	CloudAuth  bool   `json:"cloud_auth,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`

	Gateways        []GPPortalGateway `json:"gateways"`
	GatewayCount    int               `json:"gateway_count"`
	CutoffSecs      *int              `json:"cutoff_secs,omitempty"`
	SelectedGateway string            `json:"selected_gateway,omitempty"`

	// evidence that this portal actually worked
	AuthSuccess  bool      `json:"auth_success"`
	Tunnels      int       `json:"tunnels"`
	HIPSubmitted int       `json:"hip_submitted"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`

	// PanOSVersion and AssignedIP come from the gateway's own config reply.
	PanOSVersion string `json:"panos_version,omitempty"`
	AssignedIP   string `json:"assigned_ip,omitempty"`
}

var (
	pPreloginRe   = regexp.MustCompile(`----Portal Pre-login starts----`)
	pRegionRe     = regexp.MustCompile(`REGION-PRIO, region code is (\S+)`)
	pRegionTagRe  = regexp.MustCompile(`<region>([^<]+)</region>`)
	pSamlMethodRe = regexp.MustCompile(`<saml-auth-method>([^<]+)</saml-auth-method>`)
	pCasAuthRe    = regexp.MustCompile(`<cas-auth>yes</cas-auth>`)
	pTenantRe     = regexp.MustCompile(`<tenant-id>([^<]+)</tenant-id>`)
	pEmbeddedRe   = regexp.MustCompile(`<cas-embedded-browser>yes</cas-embedded-browser>`)
	pDefBrowserRe = regexp.MustCompile(`<default-browser>(yes|no)</default-browser>`)
	pAuthMsgRe    = regexp.MustCompile(`(?i)authentication-message>([^<]*)`)

	// these name the portal explicitly
	// Only lines that name the portal unambiguously are allowed to bind the
	// round. A looser "…portal <host>" pattern also matched identity-provider
	// addresses and invented portals that do not exist.
	pCookiePortalRe = regexp.MustCompile(`(?i)(?:Serialize|Unserialize)d? non-empty cookie for portal (\S+) and user (\S+)`)
	pCookieAnyRe    = regexp.MustCompile(`(?i)(?:Serialize|Unserialize)d? (?:non-)?empty cookie for portal (\S+) and`)
	pPortalDoneRe   = regexp.MustCompile(`(?i)Portal login completed with address (\S+)`)

	// gateway discovery within a portal round
	pDiscoverRe   = regexp.MustCompile(`(?i)Discover (external|internal) gateway: gateway count is (\d+), cutoff time is (\d+)`)
	pGwPriorityRe = regexp.MustCompile(`(?i)^.*?gateway (\S+) priority is (-?\d+)`)
	pGwManualRe   = regexp.MustCompile(`(?i)gateway (\d+) of (\S+) is manual select only`)
	pGwRegionRe   = regexp.MustCompile(`(?i)REGION-PRIO, gateway (\d+) is not selectable base on region`)
	pGwDescRe     = regexp.MustCompile(`(?i)Process gateway: host (\S+), description (.+?)\s*$`)
	pGwAddrRe     = regexp.MustCompile(`Gateway (\S+?)\(([^)]*)\): ipv4 (\S*), ipv6`)
	pGwWeightRe   = regexp.MustCompile(
		`(?i)gateway (.+?) \((\S+?)\), priority=(-?\d+), duration=(\d+) ms, assign (-?\d+) as its weight`)
	pGwChosenRe = regexp.MustCompile(`(?i)chose prefered gateway index =(-?\d+), gateway is (.+?)\s*$`)

	pTunnelOKRe = regexp.MustCompile(`(?i)(ipsec|ssl) tunnel creation finished`)
	pHipSentRe  = regexp.MustCompile(`(?i)HIP Report submitted to the Gateway`)
	pPanOSRe    = regexp.MustCompile(`<panos-version>([^<]+)</panos-version>`)
	pAssignedRe = regexp.MustCompile(`<ip-address>([0-9.]+)</ip-address>`)
	pGwUserRe   = regexp.MustCompile(`<user>([^<]+)</user>`)
)

// ExtractGPPortals builds one record per portal the endpoint talked to.
//
// Rounds are attributed to whichever portal was most recently named, because a
// gateway discovery block does not repeat the portal address. Rotated logs are
// read oldest first so later rounds win, and both PanGPS and the event log are
// consulted since the two carry different halves of the picture.
func ExtractGPPortals(r io.ReadSeeker) ([]GPPortal, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
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
		isGPS := strings.HasPrefix(base, "pangps") && strings.HasSuffix(base, ".log")
		if !isGPS && base != "pan_gp_event.log" {
			continue
		}
		age := 0
		if isGPS {
			age = rotationIndex(base)
		}
		sc := bufio.NewScanner(tr)
		sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
		for sc.Scan() {
			byAge[age] = append(byAge[age], strings.TrimRight(sc.Text(), "\r"))
		}
	}

	ages := make([]int, 0, len(byAge))
	for a := range byAge {
		ages = append(ages, a)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(ages))) // oldest (highest rotation) first

	pf := &portalFold{portals: map[string]*GPPortal{}}
	for _, age := range ages {
		for _, line := range byAge[age] {
			pf.feed(line)
		}
	}
	return pf.result(), nil
}

// portalFold accumulates portal records as the log is read.
type portalFold struct {
	portals map[string]*GPPortal
	order   []string

	current string // the portal most recently named
	// pending holds facts seen before the portal was named in this round —
	// the pre-login response arrives before any line mentions the address.
	pending GPPortal
	// the gateway discovery round in progress, in log order so the
	// index-based exclusion lines can be attributed
	round      []*GPPortalGateway
	roundByFQ  map[string]*GPPortalGateway
	roundCnt   int
	roundCut   *int
	roundOwner string // the portal this round belongs to
	roundOpen  bool   // a discovery block is in progress
	lastTs     time.Time
}

func (p *portalFold) portal(addr string) *GPPortal {
	if g, ok := p.portals[addr]; ok {
		return g
	}
	g := &GPPortal{Address: addr, Gateways: []GPPortalGateway{}}
	p.portals[addr] = g
	p.order = append(p.order, addr)
	return g
}

// nameCurrent binds the facts gathered so far to a portal address.
func (p *portalFold) nameCurrent(addr string) {
	if addr == "" {
		return
	}
	p.current = addr
	g := p.portal(addr)
	if p.pending.Region != "" {
		g.Region = p.pending.Region
	}
	if p.pending.AuthMethod != "" {
		g.AuthMethod = p.pending.AuthMethod
	}
	if p.pending.Browser != "" {
		g.Browser = p.pending.Browser
	}
	if p.pending.TenantID != "" {
		g.TenantID = p.pending.TenantID
	}
	if p.pending.CloudAuth {
		g.CloudAuth = true
	}
	p.pending = GPPortal{}
	if !p.lastTs.IsZero() {
		if g.FirstSeen.IsZero() {
			g.FirstSeen = p.lastTs
		}
		g.LastSeen = p.lastTs
	}
}

func (p *portalFold) feed(line string) {
	if m := gpTraceLineRe.FindStringSubmatch(line); m != nil {
		if t, ok := parseGPTime(m[5], m[6]); ok {
			p.lastTs = t
		}
	} else if m := gpEventLineRe.FindStringSubmatch(line); m != nil {
		if t, ok := parseGPTime(m[1], m[2]); ok {
			p.lastTs = t
		}
	}

	// A new round. The pre-login response that follows describes *this* portal
	// but does not name it, so the facts are held until something does — and
	// the previous portal is forgotten, or a Prisma pre-login would be
	// attributed to the lab portal that happened to be current before it.
	if pPreloginRe.MatchString(line) {
		p.pending = GPPortal{}
		p.current = ""
		p.round = nil
		p.roundByFQ = nil
		p.roundOpen = false
	}

	// pre-login response facts
	if m := pRegionRe.FindStringSubmatch(line); m != nil {
		p.setRegion(m[1])
	} else if m := pRegionTagRe.FindStringSubmatch(line); m != nil {
		p.setRegion(m[1])
	}
	if m := pSamlMethodRe.FindStringSubmatch(line); m != nil {
		p.setAuth("SAML (" + m[1] + ")")
	}
	if pCasAuthRe.MatchString(line) {
		p.setCloudAuth()
	}
	if m := pTenantRe.FindStringSubmatch(line); m != nil {
		p.setTenant(m[1])
	}
	if pEmbeddedRe.MatchString(line) {
		p.setBrowser("embedded")
	} else if m := pDefBrowserRe.FindStringSubmatch(line); m != nil && m[1] == "yes" {
		p.setBrowser("OS default")
	}
	if m := pAuthMsgRe.FindStringSubmatch(line); m != nil && strings.TrimSpace(m[1]) != "" {
		// a credential prompt string only appears for local authentication
		p.setAuth("credentials")
	}

	// lines that name the portal
	if m := pCookiePortalRe.FindStringSubmatch(line); m != nil {
		p.nameCurrent(m[1])
		if u := strings.TrimSuffix(m[2], "."); u != "" && !strings.EqualFold(u, "pre-logon") {
			p.portal(m[1]).User = u
		}
	} else if m := pPortalDoneRe.FindStringSubmatch(line); m != nil {
		addr := strings.TrimSuffix(m[1], ".")
		p.nameCurrent(addr)
		p.portal(addr).AuthSuccess = true
	} else if m := pCookieAnyRe.FindStringSubmatch(line); m != nil {
		p.nameCurrent(m[1])
	}

	// Gateway discovery. The round belongs to the portal that is current when
	// discovery *starts*: by the time a choice is logged, other lines may have
	// moved the current portal on.
	if m := pDiscoverRe.FindStringSubmatch(line); m != nil {
		p.commitRound("") // whatever was pending belongs to the previous round
		p.round = nil
		p.roundByFQ = map[string]*GPPortalGateway{}
		p.roundOwner = p.current
		p.roundOpen = true
		if n, err := strconv.Atoi(m[2]); err == nil {
			p.roundCnt = n
		}
		if n, err := strconv.Atoi(m[3]); err == nil {
			p.roundCut = &n
		}
		return
	}
	// Gateway lines only count inside an open discovery round. The measuring
	// threads keep logging after a choice is made, and those trailing lines
	// were starting a phantom round that then attached to the next portal.
	if !p.roundOpen {
		p.portalOutcome(line)
		return
	}
	if p.roundByFQ == nil {
		p.roundByFQ = map[string]*GPPortalGateway{}
	}

	if m := pGwPriorityRe.FindStringSubmatch(line); m != nil && !strings.Contains(line, "priority=") {
		g := p.roundGateway(m[1])
		if n, err := strconv.Atoi(m[2]); err == nil {
			g.Priority = &n
		}
	}
	if m := pGwManualRe.FindStringSubmatch(line); m != nil {
		p.roundGateway(m[2]).Excluded = "manual-only"
	}
	if m := pGwRegionRe.FindStringSubmatch(line); m != nil {
		if i, err := strconv.Atoi(m[1]); err == nil && i >= 0 && i < len(p.round) {
			p.round[i].Excluded = "region"
		}
	}
	if m := pGwDescRe.FindStringSubmatch(line); m != nil {
		p.roundGateway(m[1]).Name = strings.TrimSpace(m[2])
	}
	if m := pGwAddrRe.FindStringSubmatch(line); m != nil {
		g := p.roundGateway(m[1])
		if g.Name == "" {
			g.Name = m[2]
		}
		g.IPv4 = m[3]
	}
	if m := pGwWeightRe.FindStringSubmatch(line); m != nil {
		g := p.roundGateway(m[2])
		g.Name = strings.TrimSpace(m[1])
		if n, err := strconv.Atoi(m[3]); err == nil {
			g.Priority = &n
		}
		if n, err := strconv.Atoi(m[4]); err == nil {
			g.DurationMS = &n
		}
		if n, err := strconv.Atoi(m[5]); err == nil {
			g.Weight = &n
		}
	}
	if m := pGwChosenRe.FindStringSubmatch(line); m != nil {
		name := strings.TrimSpace(m[2])
		for _, g := range p.round {
			g.Selected = strings.EqualFold(g.Name, name)
		}
		p.commitRound(name)
	}
	p.portalOutcome(line)
}

// portalOutcome records what happened, against the current portal.
func (p *portalFold) portalOutcome(line string) {
	if p.current == "" {
		return
	}
	g := p.portal(p.current)
	if pTunnelOKRe.MatchString(line) {
		g.Tunnels++
	}
	if pHipSentRe.MatchString(line) {
		g.HIPSubmitted++
	}
	if m := pPanOSRe.FindStringSubmatch(line); m != nil {
		g.PanOSVersion = m[1]
	}
	if m := pAssignedRe.FindStringSubmatch(line); m != nil {
		g.AssignedIP = m[1]
	}
	if m := pGwUserRe.FindStringSubmatch(line); m != nil && g.User == "" {
		g.User = m[1]
	}
}

func (p *portalFold) setRegion(v string) {
	if p.current != "" {
		p.portal(p.current).Region = v
	} else {
		p.pending.Region = v
	}
}

func (p *portalFold) setAuth(v string) {
	if p.current != "" {
		// a SAML method should not be downgraded to "credentials" by a later
		// generic prompt string
		if g := p.portal(p.current); g.AuthMethod == "" || strings.HasPrefix(v, "SAML") {
			g.AuthMethod = v
		}
	} else if p.pending.AuthMethod == "" || strings.HasPrefix(v, "SAML") {
		p.pending.AuthMethod = v
	}
}

func (p *portalFold) setBrowser(v string) {
	if p.current != "" {
		p.portal(p.current).Browser = v
	} else {
		p.pending.Browser = v
	}
}

func (p *portalFold) setTenant(v string) {
	if p.current != "" {
		p.portal(p.current).TenantID = v
	} else {
		p.pending.TenantID = v
	}
}

func (p *portalFold) setCloudAuth() {
	if p.current != "" {
		p.portal(p.current).CloudAuth = true
	} else {
		p.pending.CloudAuth = true
	}
}

func (p *portalFold) roundGateway(fqdn string) *GPPortalGateway {
	if g, ok := p.roundByFQ[fqdn]; ok {
		return g
	}
	g := &GPPortalGateway{FQDN: fqdn}
	p.roundByFQ[fqdn] = g
	p.round = append(p.round, g)
	return g
}

// commitRound attaches the discovery round to the portal that owns it,
// replacing whatever that portal held: the newest round is its current truth.
// The round is cleared afterwards so it can never be attributed twice.
func (p *portalFold) commitRound(chosen string) {
	owner := p.roundOwner
	if owner == "" {
		owner = p.current
	}
	if owner == "" || len(p.round) == 0 {
		return
	}
	defer func() { p.round = nil; p.roundByFQ = nil; p.roundOpen = false }()
	g := p.portal(owner)
	g.Gateways = g.Gateways[:0]
	for _, x := range p.round {
		g.Gateways = append(g.Gateways, *x)
	}
	if p.roundCnt > 0 {
		g.GatewayCount = p.roundCnt
	}
	if p.roundCut != nil {
		g.CutoffSecs = p.roundCut
	}
	if chosen != "" {
		for _, x := range p.round {
			if strings.EqualFold(x.Name, chosen) {
				g.SelectedGateway = x.FQDN
			}
		}
	}
}

func (p *portalFold) result() []GPPortal {
	out := make([]GPPortal, 0, len(p.order))
	for _, addr := range p.order {
		g := p.portals[addr]
		if g.Gateways == nil {
			g.Gateways = []GPPortalGateway{}
		}
		if g.GatewayCount == 0 {
			g.GatewayCount = len(g.Gateways)
		}
		out = append(out, *g)
	}
	// portals that actually authenticated first, then by most recent activity
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].AuthSuccess != out[j].AuthSuccess {
			return out[i].AuthSuccess
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}
