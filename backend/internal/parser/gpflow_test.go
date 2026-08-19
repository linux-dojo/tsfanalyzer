package parser

import (
	"bytes"
	"strings"
	"testing"
)

// The event sequence of a connection that completed, copied from a real
// collection where the lab portal and gateway were finally working.
const gpGoodAttempt = `08/19/2026 03:21:15:002 [Info ]: Started the Portal pre-login
08/19/2026 03:21:15:175 [Info ]: CPanMSService::PreloginPortal CheckServerCert return 0x1002
08/19/2026 03:21:15:763 [Info ]: Portal pre-login result received
08/19/2026 03:21:15:763 [Info ]: Portal Login starts
08/19/2026 03:21:15:778 [Info ]: Unserialized non-empty cookie for portal gp.tpmlab.local and user abdul
08/19/2026 03:21:15:778 [Info ]: Logging into portal
08/19/2026 03:21:17:333 [Info ]: portal status is Connected.
08/19/2026 03:21:17:411 [Info ]: Connect method is user-logon
08/19/2026 03:21:17:730 [Info ]: Portal login completed with address gp.tpmlab.local and conect method of user-logon.
08/19/2026 03:21:17:746 [Info ]: Network discovery started.
08/19/2026 03:21:17:746 [Info ]: Discovering internal network.
08/19/2026 03:21:17:746 [Info ]: Gateway pre-Login Starts to gp.tpmlab.local
08/19/2026 03:21:17:994 [Info ]: Gateway Login starts to gp.tpmlab.local
08/19/2026 03:21:19:042 [Info ]: Auto Gateway login finished with address gp.tpmlab.local and user abdul.
08/19/2026 03:21:19:042 [Info ]: Trying to create tunnel with gateway gp.tpmlab.local
08/19/2026 03:21:26:217 [Info ]: IPSec tunnel creation finished with Gateway gp.tpmlab.local.
08/19/2026 03:21:29:905 [Info ]: Completed HIP Report check with Gateway gp.tpmlab.local.
08/19/2026 03:21:33:694 [Info ]: HIP Report submitted to the Gateway gp.tpmlab.local.`

// The far more common shape: the portal is fine but no gateway is usable. The
// agent reports only that the network is unreachable.
const gpNoGatewayAttempt = `08/19/2026 03:13:11:000 [Info ]: Started the Portal pre-login
08/19/2026 03:13:11:200 [Info ]: Portal pre-login result received
08/19/2026 03:13:22:598 [Info ]: Logging into portal
08/19/2026 03:13:24:130 [Info ]: portal status is Connected.
08/19/2026 03:13:25:065 [Info ]: Portal login completed with address gp.tpmlab.local and conect method of user-logon.
08/19/2026 03:13:25:095 [Info ]: Network discovery started.
08/19/2026 03:13:25:095 [Info ]: Discovering external network.
08/19/2026 03:13:25:095 [Error]: The network connection is unreachable or the gateway is unresponsive. Check the network connection and reconnect.`

const gpAuthFailAttempt = `08/18/2026 13:31:14:843 [Info ]: Started the Portal pre-login
08/18/2026 13:31:16:473 [Info ]: Portal pre-login result received
08/18/2026 13:31:16:473 [Info ]: Portal Login starts
08/18/2026 13:31:16:567 [Info ]: Logging into portal
08/18/2026 13:31:17:897 [Info ]: Auth failed for portal
08/18/2026 13:31:17:897 [Info ]: portal status is User authentication failed.`

func gpTgz(t *testing.T, eventLog string, extra map[string]string) []byte {
	t.Helper()
	files := map[string]string{"pan_gp_event.log": eventLog}
	for k, v := range extra {
		files[k] = v
	}
	return buildMultiTgz(t, files)
}

func TestGPAttemptConnected(t *testing.T) {
	at, err := ExtractGPAttempts(bytes.NewReader(gpTgz(t, gpGoodAttempt, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if len(at) != 1 {
		t.Fatalf("got %d attempts, want 1", len(at))
	}
	a := at[0]
	if a.Outcome != "connected" {
		t.Errorf("outcome = %q, want connected (reason %q)", a.Outcome, a.Reason)
	}
	if a.Reached != StageHIP {
		t.Errorf("reached = %q, want %q", a.Reached, StageHIP)
	}
	if a.Portal != "gp.tpmlab.local" {
		t.Errorf("portal = %q", a.Portal)
	}
	if a.Gateway != "gp.tpmlab.local" {
		t.Errorf("gateway = %q", a.Gateway)
	}
	if a.User != "abdul" {
		t.Errorf("user = %q, want abdul", a.User)
	}
	// every stage should have a verdict, none left "not reached"
	for _, s := range a.Stages {
		if s.Status == "not reached" {
			t.Errorf("stage %q was not reached in a completed connection", s.Stage)
		}
	}
}

// The whole point of the stage model: the portal succeeded, so the failure is
// at gateway selection, not "the network".
func TestGPAttemptStopsAtGatewaySelect(t *testing.T) {
	at, err := ExtractGPAttempts(bytes.NewReader(gpTgz(t, gpNoGatewayAttempt, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if len(at) != 1 {
		t.Fatalf("got %d attempts, want 1", len(at))
	}
	a := at[0]
	if a.Outcome != "failed" {
		t.Errorf("outcome = %q, want failed", a.Outcome)
	}
	if a.StopAt != StageGatewaySelect {
		t.Errorf("stop_at = %q, want %q", a.StopAt, StageGatewaySelect)
	}
	// the portal stages must still read as successful
	for _, s := range a.Stages {
		if s.Stage == StagePortalAuth && s.Status != "ok" {
			t.Errorf("portal auth = %q, want ok — the portal did connect", s.Status)
		}
		if s.Stage == StageTunnel && s.Status != "not reached" {
			t.Errorf("tunnel = %q, want not reached", s.Status)
		}
	}
	if !strings.Contains(a.Reason, "gateway") {
		t.Errorf("reason should name the gateway stage: %q", a.Reason)
	}
}

func TestGPAttemptStopsAtPortalAuth(t *testing.T) {
	at, err := ExtractGPAttempts(bytes.NewReader(gpTgz(t, gpAuthFailAttempt, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if len(at) != 1 {
		t.Fatalf("got %d attempts, want 1", len(at))
	}
	if at[0].StopAt != StagePortalAuth {
		t.Errorf("stop_at = %q, want %q", at[0].StopAt, StagePortalAuth)
	}
	if at[0].Outcome != "failed" {
		t.Errorf("outcome = %q, want failed", at[0].Outcome)
	}
}

// Several attempts in one log must be segmented, not merged.
func TestGPAttemptsSegmented(t *testing.T) {
	log := gpAuthFailAttempt + "\n" + gpNoGatewayAttempt + "\n" + gpGoodAttempt
	at, err := ExtractGPAttempts(bytes.NewReader(gpTgz(t, log, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if len(at) != 3 {
		t.Fatalf("got %d attempts, want 3", len(at))
	}
	want := []string{"failed", "failed", "connected"}
	for i, w := range want {
		if at[i].Outcome != w {
			t.Errorf("attempt %d outcome = %q, want %q", i, at[i].Outcome, w)
		}
	}
	// they must come out in time order
	for i := 1; i < len(at); i++ {
		if at[i].Start.Before(at[i-1].Start) {
			t.Errorf("attempts out of order at %d", i)
		}
	}
}

// Single sign-on with SAML, verbatim from a collection taken after deleting the
// cached cookies and signing out. The shape that matters: the portal prompts
// through the browser, issues a cookie, and the gateway accepts that cookie
// instead of prompting again. Note the second "Started the Portal pre-login" —
// the agent re-issues it when the browser hands control back, and treating that
// as a new attempt would split one login in two and lose the hand-off.
const gpSamlSingleSignOn = `08/19/2026 05:55:49:136 [Info ]: Started the Portal pre-login
08/19/2026 05:55:50:572 [Info ]: Portal pre-login result received
08/19/2026 05:55:50:573 [Info ]: Portal Login starts
08/19/2026 05:55:50:573 [Info ]: Failed to open file C:\Users\administrator\AppData\Local\Palo Alto Networks\GlobalProtect\PanPUAC_9cbfb063c3861b6e249d57c7ea96d78.dat
08/19/2026 05:55:50:684 [Info ]: Load the SAML Browser
08/19/2026 05:55:58:407 [Info ]: Started the Portal pre-login
08/19/2026 05:55:58:409 [Info ]: Unserialized empty cookie for portal tpm.gpcloudservice.com and pre-logon user.
08/19/2026 05:55:58:410 [Info ]: Logging into portal
08/19/2026 05:55:59:445 [Info ]: portal status is Connected.
08/19/2026 05:56:00:425 [Info ]: Serialize non-empty cookie for portal tpm.gpcloudservice.com and user abandey%40paloaltonetworks.com
08/19/2026 05:56:01:503 [Info ]: Portal login completed with address tpm.gpcloudservice.com and conect method of user-logon.
08/19/2026 05:56:02:436 [Info ]: Gateway pre-Login Starts to india-west-paloalto.gpocnggconco.gw.gpcloudservice.com
08/19/2026 05:56:03:373 [Info ]: File is successfully decrypted. File: C:\Users\administrator\AppData\Local\Palo Alto Networks\GlobalProtect\PanPUAC_9cbfb063c3861b6e249d57c7ea96d78.dat
08/19/2026 05:56:03:373 [Info ]: Unserialized non-empty cookie for portal tpm.gpcloudservice.com and user abandey%40paloaltonetworks.com
08/19/2026 05:56:03:373 [Info ]: Gateway Login starts to india-west-paloalto.gpocnggconco.gw.gpcloudservice.com
08/19/2026 05:56:03:949 [Info ]: Auto Gateway login finished with address india-west-paloalto.gpocnggconco.gw.gpcloudservice.com and user abandey@paloaltonetworks.com.
08/19/2026 05:56:04:088 [Info ]: Trying to create tunnel with gateway india-west-paloalto.gpocnggconco.gw.gpcloudservice.com
08/19/2026 05:56:10:163 [Info ]: IPSec tunnel creation finished with Gateway india-west-paloalto.gpocnggconco.gw.gpcloudservice.com.`

func TestGPSamlSingleSignOn(t *testing.T) {
	at, err := ExtractGPAttempts(bytes.NewReader(gpTgz(t, gpSamlSingleSignOn, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if len(at) != 1 {
		t.Fatalf("got %d attempts, want 1 — the browser round-trip must not split the login: %+v",
			len(at), at)
	}
	a := at[0]
	if a.PortalAuth != "browser" {
		t.Errorf("portal_auth = %q, want browser", a.PortalAuth)
	}
	if a.GatewayAuth != "cookie" {
		t.Errorf("gateway_auth = %q, want cookie — the gateway must not prompt again", a.GatewayAuth)
	}
	if !a.SingleSignOn {
		t.Error("this is the configuration working: one prompt at the portal, cookie at the gateway")
	}
	if a.Outcome != "connected" {
		t.Errorf("outcome = %q, want connected", a.Outcome)
	}
	// the interactive wait is the time the user spent with the identity provider
	if a.CookieWaitSecs < 7 || a.CookieWaitSecs > 9 {
		t.Errorf("cookie_wait_secs = %v, want about 8", a.CookieWaitSecs)
	}
}

// The contrast: the gateway's cookie was missing too, so it prompted as well.
// That is the same deployment failing to deliver single sign-on.
func TestGPSamlGatewayPromptsAgain(t *testing.T) {
	log := strings.Replace(gpSamlSingleSignOn,
		"08/19/2026 05:56:03:373 [Info ]: Unserialized non-empty cookie for portal tpm.gpcloudservice.com and user abandey%40paloaltonetworks.com",
		"08/19/2026 05:56:03:373 [Info ]: Load the SAML Browser", 1)
	at, err := ExtractGPAttempts(bytes.NewReader(gpTgz(t, log, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if len(at) != 1 {
		t.Fatalf("got %d attempts, want 1", len(at))
	}
	if at[0].GatewayAuth != "browser" {
		t.Errorf("gateway_auth = %q, want browser", at[0].GatewayAuth)
	}
	if at[0].SingleSignOn {
		t.Error("a second browser prompt at the gateway is not single sign-on")
	}
}

/* ---------- gateway selection ---------- */

// Real PanGPS lines. The region mismatch is the quiet cause of "portal fine,
// gateway never": the gateway is reachable in 20 ms but scores -2.
const gpsRegionMismatch = `(P11496-T12424)Debug( 349): 08/19/26 03:13:25:095 Parse gateway list for user abdul
(P11496-T12424)Debug(6587): 08/19/26 03:13:25:095 Gateway 10.10.10.1(gp_gateway): ipv4 10.10.10.1, ipv6 , FQDN yes
(P11496-T12424)Debug(1024): 08/19/26 03:13:25:095 tcp connection time is 20
(P11496-T12424)Debug( 609): 08/19/26 03:13:25:095 One external gateway 10.10.10.1, priority=1, manual is 0
(P11496-T12424)Debug( 645): 08/19/26 03:13:25:095 One external gateway and the priority is -2, region does not match
(P11496-T6520)Dump ( 899): 08/19/26 03:13:25:095 REGION-PRIO, gateway 0(gp_gateway), 0, region = 0.0.0.0-0.255.255.255, priority = 1, portalRegion=10.0.0.0-10.255.255.255
(P11496-T12424)Info ( 419): 08/19/26 03:13:25:095 gateway count is 1, cutoff time is 5, bJustResumed=0
(P11496-T12424)Info ( 400): 08/19/26 03:13:25:095 Gateway count is 0 for internal network.`

const gpsGoodRound = `(P11496-T12424)Debug( 349): 08/19/26 03:21:17:746 Parse gateway list for user abdul
(P11496-T12424)Debug(6587): 08/19/26 03:21:17:746 Gateway gp.tpmlab.local(gp_gateway): ipv4 192.168.31.78, ipv6 , FQDN yes
(P11496-T12424)Debug(1024): 08/19/26 03:21:17:746 tcp connection time is 17
(P11496-T12424)Debug( 609): 08/19/26 03:21:17:746 One external gateway gp.tpmlab.local, priority=1, manual is 1
(P11496-T12424)Debug(4729): 08/19/26 03:21:18:025 Gateway selection type is auto
(P11496-T12424)Debug(2020): 08/19/26 03:21:26:201 Calling AddGatewayEntryToResponse on m_pBestGateway=00000240D3965DB8 (gateway=gp.tpmlab.local)`

func TestGPGatewayRegionMismatchExplained(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{"PanGPS.log": gpsRegionMismatch})
	sel, err := ExtractGPGateways(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Gateways) != 1 {
		t.Fatalf("got %d gateways, want 1: %+v", len(sel.Gateways), sel.Gateways)
	}
	g := sel.Gateways[0]
	if g.Priority == nil || *g.Priority != -2 {
		t.Errorf("priority = %v, want -2 after the region mismatch", g.Priority)
	}
	if g.RegionMatch == nil || *g.RegionMatch {
		t.Errorf("region_match = %v, want false", g.RegionMatch)
	}
	if g.TCPMillis == nil || *g.TCPMillis != 20 {
		t.Errorf("tcp_ms = %v, want 20 — the gateway was reachable", g.TCPMillis)
	}
	if g.Region != "0.0.0.0-0.255.255.255" {
		t.Errorf("region = %q", g.Region)
	}
	var explained bool
	for _, n := range sel.Notes {
		if strings.Contains(n, "region") {
			explained = true
		}
	}
	if !explained {
		t.Errorf("the region mismatch should be explained in the notes: %v", sel.Notes)
	}
}

// Each "Parse gateway list" starts a new scoring round, and only the last one
// is reported: earlier rounds can belong to a different portal whose gateways
// no longer apply.
func TestGPGatewayLastRoundWins(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"PanGPS.log": gpsRegionMismatch + "\n" + gpsGoodRound,
	})
	sel, err := ExtractGPGateways(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Gateways) != 1 || sel.Gateways[0].FQDN != "gp.tpmlab.local" {
		t.Fatalf("want only the last round's gateway, got %+v", sel.Gateways)
	}
	g := sel.Gateways[0]
	if g.Priority == nil || *g.Priority != 1 {
		t.Errorf("priority = %v, want 1", g.Priority)
	}
	if g.RegionMatch == nil || !*g.RegionMatch {
		t.Errorf("region_match = %v, want true — the stale mismatch must not carry over", g.RegionMatch)
	}
	if !g.Selected {
		t.Error("the best gateway should be marked selected")
	}
	if sel.Type != "auto" {
		t.Errorf("selection type = %q, want auto", sel.Type)
	}
}

// A tar lists members in arbitrary order, so rotation has to be sorted:
// PanGPS.1.log is older than PanGPS.log and must be read first, or its stale
// round overwrites the current one.
func TestGPGatewayRotationReadOldestFirst(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"PanGPS.log":   gpsGoodRound,       // newer
		"PanGPS.1.log": gpsRegionMismatch,  // older
	})
	sel, err := ExtractGPGateways(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Gateways) != 1 || sel.Gateways[0].FQDN != "gp.tpmlab.local" {
		t.Fatalf("the newer rotation must win, got %+v", sel.Gateways)
	}
	if p := sel.Gateways[0].Priority; p == nil || *p != 1 {
		t.Errorf("priority = %v, want 1 from the newer file", p)
	}
}

func TestRotationIndex(t *testing.T) {
	for base, want := range map[string]int{
		"pangps.log":   0,
		"pangps.1.log": 1,
		"pangps.9.log": 9,
		"pangpa.log":   0,
		"weird":        0,
	} {
		if got := rotationIndex(base); got != want {
			t.Errorf("rotationIndex(%q) = %d, want %d", base, got, want)
		}
	}
}

// A multiple-gateway deployment does not emit the per-gateway priority lines
// at all: it summarises the whole comparison on one line, by display name.
// This is verbatim from a Prisma Access collection with three gateways.
const gpsScoreLine = `(P1-T1)Debug( 349): 08/19/26 05:31:09:349 Parse gateway list for user abandey
(P1-T1)Debug(6587): 08/19/26 05:31:09:349 Gateway us-northwest-g-paloalto.gpocnggconco.gw.gpcloudservice.com(US Northwest): ipv4 130.41.64.138, ipv6 , FQDN yes
(P1-T1)Debug(6587): 08/19/26 05:31:09:349 Gateway india-west-paloalto.gpocnggconco.gw.gpcloudservice.com(India West): ipv4 130.41.204.188, ipv6 , FQDN yes
(P1-T1)Debug(6587): 08/19/26 05:31:09:349 Gateway netherlands-central-paloalto.gpocnggconco.gw.gpcloudservice.com(Netherlands Central): ipv4 134.238.141.55, ipv6 , FQDN yes
(P1-T1)Info (1234): 08/19/26 05:31:09:349 Gateway selection(Priority-TCP-SSL-Weight): US Northwest(5-419-349-300), India West(1-210-206-20), Netherlands Central(5-373-295-262). `

func TestGPGatewayScoreLine(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{"PanGPS.log": gpsScoreLine})
	sel, err := ExtractGPGateways(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Gateways) != 3 {
		t.Fatalf("got %d gateways, want 3: %+v", len(sel.Gateways), sel.Gateways)
	}
	want := map[string][4]int{ // priority, tcp, ssl, weight
		"US Northwest":        {5, 419, 349, 300},
		"India West":          {1, 210, 206, 20},
		"Netherlands Central": {5, 373, 295, 262},
	}
	for _, g := range sel.Gateways {
		w, ok := want[g.Name]
		if !ok {
			t.Errorf("unexpected gateway %q", g.Name)
			continue
		}
		if g.Priority == nil || *g.Priority != w[0] {
			t.Errorf("%s priority = %v, want %d", g.Name, g.Priority, w[0])
		}
		if g.TCPMillis == nil || *g.TCPMillis != w[1] {
			t.Errorf("%s tcp = %v, want %d", g.Name, g.TCPMillis, w[1])
		}
		if g.SSLMillis == nil || *g.SSLMillis != w[2] {
			t.Errorf("%s ssl = %v, want %d", g.Name, g.SSLMillis, w[2])
		}
		if g.Weight == nil || *g.Weight != w[3] {
			t.Errorf("%s weight = %v, want %d", g.Name, g.Weight, w[3])
		}
	}
	// the lowest weight wins, and it is the gateway that was actually used
	if !strings.HasPrefix(sel.Best, "india-west") {
		t.Errorf("best = %q, want the lowest-weight gateway (India West)", sel.Best)
	}
	for _, g := range sel.Gateways {
		if g.Name == "India West" && !g.Selected {
			t.Error("India West had the lowest weight and should be marked selected")
		}
		if g.Name == "US Northwest" && g.Selected {
			t.Error("US Northwest had the highest weight and must not be selected")
		}
	}
	var explained bool
	for _, n := range sel.Notes {
		if strings.Contains(n, "lowest weight wins") {
			explained = true
		}
	}
	if !explained {
		t.Errorf("the weight column should be explained: %v", sel.Notes)
	}
}

// The name in the scoring line is the display name and may contain spaces; a
// gateway scored but never listed by FQDN must still appear.
func TestParseGatewayScoreLine(t *testing.T) {
	got := parseGatewayScoreLine(
		"US Northwest(5-419-349-300), India West(1-210-206-20), Netherlands Central(5-373-295-262). ")
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(got), got)
	}
	if got[0].name != "US Northwest" || got[2].name != "Netherlands Central" {
		t.Errorf("names not parsed: %+v", got)
	}
	if got[1].priority != 1 || got[1].tcp != 210 || got[1].ssl != 206 || got[1].weight != 20 {
		t.Errorf("India West parsed as %+v", got[1])
	}
	if len(parseGatewayScoreLine("")) != 0 {
		t.Error("an empty list should yield nothing")
	}
}

func TestGPGatewayEmptyListNoted(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"PanGPS.log": `(P1-T1)Debug( 349): 08/19/26 03:21:17:746 Parse gateway list for user abdul
(P1-T1)Debug( 417): 08/19/26 03:21:17:746 gateway list is empty.`,
	})
	sel, err := ExtractGPGateways(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	var noted bool
	for _, n := range sel.Notes {
		if strings.Contains(n, "empty gateway list") {
			noted = true
		}
	}
	if !noted {
		t.Errorf("an empty gateway list should point at the portal config: %v", sel.Notes)
	}
}
