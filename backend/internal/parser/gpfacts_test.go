package parser

import (
	"strings"
	"testing"
)

// scanTrace runs the fact scanner over trace lines without needing an archive.
func scanTrace(body string) *GPFacts {
	s := &gpFactScan{facts: &GPFacts{}}
	s.feed(strings.Split(strings.TrimPrefix(body, "\n"), "\n"))
	s.close()
	return s.facts
}

func tl(clock, msg string) string {
	return "P 823-T13059 08/24/2026 " + clock + ":000 Debug(1234): " + msg
}

// The central judgement of this parser, and the one place the spec and the
// logs disagree.
//
// CheckServerCert returning 0x1002 reads like a failed certificate check, and
// treating it as one is the obvious implementation. But across the sample
// collections it appeared 63 times and in all 63 the pre-login was issued
// immediately afterwards and the connection went on to succeed — it
// accompanies a local trust-store miss while the hostname still matches the
// certificate's subject alternative name. Flagging on the code alone would put
// 63 certificate alarms on a connection that worked.
//
// So the flow decides, not the code.
func TestCertCheckThatProceededIsNotAFailure(t *testing.T) {
	f := scanTrace(`
` + tl("11:47:18", "----Portal Pre-login starts----") + `
` + tl("11:47:18", "Pre-login...,verifyportalcert=yes") + `
` + tl("11:47:18", "CPanMSService::PreloginPortal CheckServerCert return 0x1002 ") + `
` + tl("11:47:18", "REQID=1,IPADDR=portal.example.com,PORT=443,URL=/global-protect/prelogin.esp,POST=1") + `
`)
	if len(f.CertChecks) != 1 {
		t.Fatalf("got %d cert checks, want 1", len(f.CertChecks))
	}
	c := f.CertChecks[0]
	if c.Code != "0x1002" {
		t.Errorf("code = %q, want 0x1002", c.Code)
	}
	if !c.Proceeded {
		t.Error("the pre-login was issued straight after, so the check did not stop anything")
	}
	if c.Failed {
		t.Error("0x1002 followed by a pre-login is not a failure; flagging it " +
			"would raise an alarm on every working connection")
	}
	if c.Verify != "yes" {
		t.Errorf("verifyportalcert = %q, want yes", c.Verify)
	}
	if c.Portal != "portal.example.com" {
		t.Errorf("portal = %q, want it named from the pre-login request", c.Portal)
	}
	if len(f.CertFailures()) != 0 {
		t.Error("CertFailures should be empty")
	}
}

// "Skip CheckServerCert result" is the agent saying it is ignoring the code.
func TestSkippedCertCheckIsNotAFailure(t *testing.T) {
	f := scanTrace(`
` + tl("11:47:18", "----Portal Pre-login starts----") + `
` + tl("11:47:18", "CPanMSService::PreloginPortal CheckServerCert return 0x2000 ") + `
` + tl("11:47:18", "Skip CheckServerCert result") + `
`)
	if !f.CertChecks[0].Skipped {
		t.Error("the skip line should be recorded")
	}
	if f.CertChecks[0].Failed {
		t.Error("a skipped check cannot be a failure")
	}
}

// The case that *is* a failure: nothing followed it.
func TestCertCheckThatStoppedTheFlowIsAFailure(t *testing.T) {
	f := scanTrace(`
` + tl("11:47:18", "----Portal Pre-login starts----") + `
` + tl("11:47:18", "CPanMSService::PreloginPortal CheckServerCert return 0x1002 ") + `
` + tl("11:48:20", "----Portal Pre-login starts----") + `
` + tl("11:48:20", "CPanMSService::PreloginPortal CheckServerCert return 0x0 ") + `
` + tl("11:48:20", "REQID=2,IPADDR=portal.example.com,PORT=443,URL=/global-protect/prelogin.esp,POST=1") + `
`)
	if len(f.CertChecks) != 2 {
		t.Fatalf("got %d checks, want 2", len(f.CertChecks))
	}
	if !f.CertChecks[0].Failed {
		t.Error("a check with no pre-login after it, cut off by a retry, is a failure")
	}
	if f.CertChecks[1].Failed {
		t.Error("the retry proceeded and is not a failure")
	}
	if len(f.CertFailures()) != 1 {
		t.Errorf("CertFailures gave %d, want 1", len(f.CertFailures()))
	}
}

func TestPreloginResponseFields(t *testing.T) {
	f := scanTrace(`
` + tl("11:47:19", "prelogin to portal result is <?xml version=\"1.0\" encoding=\"UTF-8\" ?>") + `
<prelogin-response>
<status>Success</status>
<ccusername></ccusername>
<autosubmit>false</autosubmit>
<authentication-message>Enter login credentials</authentication-message>
<panos-version>1</panos-version>
<saml-default-browser>yes</saml-default-browser>
<connected-ip>137.83.218.155</connected-ip>
</prelogin-response>
`)
	if len(f.Prelogins) != 1 {
		t.Fatalf("got %d prelogin responses, want 1", len(f.Prelogins))
	}
	p := f.Prelogins[0]
	if p.Status != "Success" {
		t.Errorf("status = %q", p.Status)
	}
	if p.ConnectedIP != "137.83.218.155" {
		t.Errorf("connected-ip = %q", p.ConnectedIP)
	}
	if p.SAMLBrowser != "yes" {
		t.Errorf("saml-default-browser = %q", p.SAMLBrowser)
	}
	if p.ClientCert() {
		t.Error("an empty <ccusername> means no client certificate was used")
	}
}

// A populated <ccusername> is the portal having accepted a client certificate
// and read the username out of it.
func TestPreloginClientCertificateUsername(t *testing.T) {
	f := scanTrace(`
` + tl("11:47:19", "prelogin to portal result is <?xml version=\"1.0\" ?>") + `
<prelogin-response>
<status>Success</status>
<ccusername>DRHOTEN@example.com</ccusername>
</prelogin-response>
`)
	p := f.Prelogins[0]
	if !p.ClientCert() {
		t.Fatal("a non-empty <ccusername> means certificate authentication")
	}
	if p.CCUsername != "DRHOTEN@example.com" {
		t.Errorf("cc_username = %q", p.CCUsername)
	}
}

func TestEnforcerDetectedFromAnyOfItsLines(t *testing.T) {
	for name, line := range map[string]string{
		"already loaded": "Enforcer already loaded.",
		"exception":      "enforcer exception IPv4 255.255.192.0 - 255.255.255.255",
		"set exceptions": "Enforcer set exceptions 8-388",
		"domain parse":   "enforcer exception: parsed 14 single and 26 wildcard domain entries for enforcer exception",
	} {
		if !scanTrace("\n" + tl("11:47:18", line)).Enforcer.Present {
			t.Errorf("%s: the enforcer should have been detected", name)
		}
	}
	if scanTrace("\n" + tl("11:47:18", "nothing to see here")).Enforcer.Present {
		t.Error("the enforcer should not be claimed without evidence")
	}
}

func TestEnforcerCounts(t *testing.T) {
	f := scanTrace(`
` + tl("11:47:18", "Enforcer set exceptions 8-388") + `
` + tl("11:47:18", "enforcer exception: parsed 14 single and 26 wildcard domain entries for enforcer exception") + `
`)
	if got := f.Enforcer.Exceptions; got != 381 {
		t.Errorf("exceptions = %d, want 381 (8..388 inclusive)", got)
	}
	if f.Enforcer.Domains != 14 || f.Enforcer.Wildcards != 26 {
		t.Errorf("domains/wildcards = %d/%d, want 14/26", f.Enforcer.Domains, f.Enforcer.Wildcards)
	}
}

// Internal host detection is assembled from four consecutive lines, and the
// error code decides it. This is the failing case from the macOS collection.
func TestInternalHostDetectionFailure(t *testing.T) {
	f := scanTrace(`
` + tl("11:51:38", "IP 10.6.56.139 ") + `
` + tl("11:51:38", "host any-internal-fqdn.local ") + `
` + tl("11:51:38", "Reverse DNS lookup: 139.56.6.10.in-addr.arpa") + `
` + tl("11:51:38", "Reverse lookup returns hostname , error -65554") + `
`)
	h := f.HostDetection
	if !h.Configured {
		t.Fatal("internal host detection was configured; the portal supplied an IP and a host")
	}
	if h.IP != "10.6.56.139" || h.Host != "any-internal-fqdn.local" {
		t.Errorf("ip/host = %q/%q", h.IP, h.Host)
	}
	if h.Lookup != "139.56.6.10.in-addr.arpa" {
		t.Errorf("lookup = %q", h.Lookup)
	}
	if h.OK {
		t.Error("error -65554 is not a successful detection")
	}
}

func TestInternalHostDetectionSuccess(t *testing.T) {
	f := scanTrace(`
` + tl("11:51:38", "IP 10.6.56.139 ") + `
` + tl("11:51:38", "host any-internal-fqdn.local ") + `
` + tl("11:51:38", "Reverse DNS lookup: 139.56.6.10.in-addr.arpa") + `
` + tl("11:51:38", "Reverse lookup returns hostname any-internal-fqdn.local, error 0") + `
`)
	if !f.HostDetection.OK {
		t.Error("error 0 is a successful internal host detection")
	}
}

func TestInternalHostDetectionNotConfigured(t *testing.T) {
	f := scanTrace("\n" + tl("11:51:38", "No internal host detection defined"))
	if f.HostDetection.Configured {
		t.Error("nothing was configured, so nothing should be claimed")
	}
}

// The gateway config arrives as XML that the agent cuts off at a log-line
// limit, so it must be scraped rather than unmarshalled — encoding/xml would
// reject the document and the tab would show nothing at all.
func TestGatewayConfigSurvivesTruncation(t *testing.T) {
	f := scanTrace(`
` + tl("03:21:19", "gateway gw.example.com's config is <?xml version=\"1.0\" ?>") + `
	<response status="success">
		<portal>GP-Gateway-N</portal>
		<user>abdul</user>
		<gw-address>192.168.31.78</gw-address>
		<dns>
			<member>8.8.8.8</member>
		</dns>
		<dns-suffix>
			<member>example.local</member>
		</dns-suffix>
		<access-routes>
			<member>10.0.0.0/8</member>
			<member>8.8.8.8/32</member>
		</access-routes>
		<exclude-access-routes>
			<member>13.107.6.152/31</member>
		</exclude-access-routes>
		<ipsec>
			<udp-port>4501</udp-port>
			<hmac-algo>sha1
`)
	if len(f.GatewayConfigs) != 1 {
		t.Fatalf("got %d gateway configs, want 1", len(f.GatewayConfigs))
	}
	c := f.GatewayConfigs[0]
	if c.Gateway != "gw.example.com" {
		t.Errorf("gateway = %q", c.Gateway)
	}
	if !c.Truncated {
		t.Error("the document never closed; the view must be able to say so")
	}
	if got := strings.Join(c.AccessRoutes, ","); got != "10.0.0.0/8,8.8.8.8/32" {
		t.Errorf("access routes = %q", got)
	}
	if got := strings.Join(c.ExcludeRoutes, ","); got != "13.107.6.152/31" {
		t.Errorf("exclude routes = %q", got)
	}
	if got := strings.Join(c.DNS, ","); got != "8.8.8.8" {
		t.Errorf("dns = %q", got)
	}
	if c.User != "abdul" {
		t.Errorf("user = %q", c.User)
	}
	if len(c.Fields) == 0 {
		t.Error("the remaining simple elements should be listed")
	}
}

// <portal> inside the gateway config is the name of the agent config profile
// the gateway matched, not a portal address. Reading it as an address would
// invent portals like "GP-Gateway-N" and corrupt the portal grouping.
func TestGatewayConfigPortalElementIsAProfileName(t *testing.T) {
	f := scanTrace(`
` + tl("03:21:19", "gateway gw.example.com's config is <?xml version=\"1.0\" ?>") + `
	<response status="success">
		<portal>GP-Gateway-N</portal>
	</response>
`)
	c := f.GatewayConfigs[0]
	if c.ConfigName != "GP-Gateway-N" {
		t.Errorf("config_name = %q, want the profile name", c.ConfigName)
	}
}

func TestSplitTunnelReading(t *testing.T) {
	full := GPGatewayConfig{AccessRoutes: []string{"0.0.0.0/0"}}
	if full.SplitTunnel() {
		t.Error("a lone default route is a full tunnel")
	}
	split := GPGatewayConfig{AccessRoutes: []string{"10.0.0.0/8"}}
	if !split.SplitTunnel() {
		t.Error("named routes only is a split tunnel")
	}
	excl := GPGatewayConfig{AccessRoutes: []string{"0.0.0.0/0"}, ExcludeRoutes: []string{"13.107.6.152/31"}}
	if !excl.SplitTunnel() {
		t.Error("a default route with exclusions is still split")
	}
}

// The stage boundaries are the spine of the Connection tab.
func TestTraceStageSequence(t *testing.T) {
	f := scanTrace(`
` + tl("11:47:18", "----Portal Pre-login starts----") + `
` + tl("11:47:19", "----Portal Login starts----") + `
` + tl("11:47:20", "----Portal Processing starts----") + `
` + tl("11:47:21", "----Network Discover starts----") + `
` + tl("11:47:22", "----Gateway Pre-login starts----") + `
` + tl("11:47:23", "----Gateway Login starts----") + `
` + tl("11:47:24", "----Tunnel Creation starts----") + `
`)
	want := []GPStage{
		StagePortalPrelogin, StagePortalAuth, StagePortalConfig,
		StageDiscovery, StageGatewaySelect, StageGatewayAuth, StageTunnel,
	}
	if len(f.Stages) != len(want) {
		t.Fatalf("got %d stages, want %d", len(f.Stages), len(want))
	}
	for i, w := range want {
		if f.Stages[i].Stage != w {
			t.Errorf("stage %d = %q, want %q", i, f.Stages[i].Stage, w)
		}
	}
}

// Teardown boundaries are real and appear in the collections ("Disable",
// "Tunnel User Diconnecting" — the agent's own spelling). They are recorded
// with no stage rather than dropped, so a run that ends does not look like a
// run that simply stopped.
func TestTeardownBoundariesAreKeptWithoutAStage(t *testing.T) {
	f := scanTrace(`
` + tl("11:47:18", "----Tunnel User Diconnecting starts----") + `
` + tl("11:47:19", "----Disable starts----") + `
`)
	if len(f.Stages) != 2 {
		t.Fatalf("got %d boundaries, want 2", len(f.Stages))
	}
	for _, s := range f.Stages {
		if s.Stage != "" {
			t.Errorf("%q mapped to stage %q; teardown is not a connection step", s.Name, s.Stage)
		}
		if s.Name == "" {
			t.Error("the boundary should still be named")
		}
	}
}
