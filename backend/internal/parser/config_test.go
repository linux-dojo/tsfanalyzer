package parser

import (
	"bytes"
	"strings"
	"testing"
)

const sampleConfigXML = `<?xml version="1.0"?>
<config version="10.2.0">
  <shared>
    <address>
      <entry name="web-server-1">
        <ip-netmask>10.1.1.5/32</ip-netmask>
      </entry>
    </address>
  </shared>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <zone>
          <entry name="trust">
            <network><layer3><member>ethernet1/1</member></layer3></network>
          </entry>
        </zone>
      </network>
      <vsys>
        <entry name="vsys1">
          <rulebase>
            <security>
              <rules>
                <entry name="allow-web">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <action>allow</action>
                </entry>
              </rules>
            </security>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
`

// A Panorama-managed device: pushed policy lives in pre-/post-rulebase and
// device-group metadata comes with it.
const samplePanoramaConfigXML = `<?xml version="1.0"?>
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <device-group>
        <entry name="branch-dg"/>
      </device-group>
      <vsys>
        <entry name="vsys1">
          <pre-rulebase>
            <security>
              <rules>
                <entry name="pano-allow-dns">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <application><member>dns</member></application>
                  <action>allow</action>
                </entry>
              </rules>
            </security>
          </pre-rulebase>
          <rulebase>
            <security>
              <rules>
                <entry name="local-rule">
                  <action>deny</action>
                </entry>
              </rules>
            </security>
          </rulebase>
          <post-rulebase>
            <security>
              <rules>
                <entry name="pano-deny-all">
                  <action>deny</action>
                </entry>
              </rules>
            </security>
          </post-rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
`

const decoyLicenseXML = `<?xml version="1.0"?><License><Feature>Threat Prevention</Feature></License>`

func TestExtractConfigPrefersLargestUnderMgmtDir(t *testing.T) {
	big := samplePanoramaConfigXML + strings.Repeat("<!-- padding -->\n", 500)
	tgz := buildMultiTgz(t, map[string]string{
		// a small local config outside the mgmt dir
		"tmp/cli/running-config.xml": sampleConfigXML,
		// two configs under the mgmt dir: the bigger one must win
		"opt/pancfg/mgmt/saved-configs/snapshot.xml": sampleConfigXML,
		"opt/pancfg/mgmt/mergesp.xml":                big,
		"license/license.xml":                        decoyLicenseXML,
	})
	doc, err := ExtractConfig(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Path != "opt/pancfg/mgmt/mergesp.xml" {
		t.Fatalf("picked %q, want the largest XML under opt/pancfg/mgmt", doc.Path)
	}
	if doc.Root == nil || doc.Root.Tag != "config" {
		t.Fatalf("root = %+v", doc.Root)
	}
	// the pick must be recorded, and other candidates reported
	var picked int
	for _, c := range doc.Candidates {
		if c.Picked {
			picked++
		}
	}
	if picked != 1 {
		t.Errorf("expected exactly one picked candidate, got %d", picked)
	}
	if len(doc.Candidates) < 3 {
		t.Errorf("candidates should list the files considered: %+v", doc.Candidates)
	}
}

func TestExtractConfigDetectsPanoramaManaged(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"opt/pancfg/mgmt/mergesp.xml": samplePanoramaConfigXML,
	})
	doc, err := ExtractConfig(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if !doc.PanoramaManaged {
		t.Fatalf("expected Panorama-managed, markers=%v", doc.Markers)
	}
	want := map[string]bool{"pre-rulebase": false, "post-rulebase": false, "device-group": false}
	for _, m := range doc.Markers {
		if _, ok := want[m]; ok {
			want[m] = true
		}
	}
	for m, seen := range want {
		if !seen {
			t.Errorf("marker %q not detected (got %v)", m, doc.Markers)
		}
	}
}

func TestExtractConfigLocalOnlyIsNotPanorama(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"opt/pancfg/mgmt/running-config.xml": sampleConfigXML,
	})
	doc, err := ExtractConfig(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if doc.PanoramaManaged {
		t.Errorf("a local-only config must not be flagged Panorama-managed: %v", doc.Markers)
	}
}

// A non-config XML that happens to be the biggest file must be skipped
// rather than accepted and rendered as an empty Config tab.
func TestExtractConfigSkipsNonConfigXML(t *testing.T) {
	huge := decoyLicenseXML + strings.Repeat("<!-- pad -->\n", 2000)
	tgz := buildMultiTgz(t, map[string]string{
		"opt/pancfg/mgmt/licenses/big-license.xml": huge,
		"opt/pancfg/mgmt/running-config.xml":       sampleConfigXML,
	})
	doc, err := ExtractConfig(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Path != "opt/pancfg/mgmt/running-config.xml" {
		t.Fatalf("picked %q, want the real config", doc.Path)
	}
	var rejected bool
	for _, c := range doc.Candidates {
		if strings.Contains(c.Path, "big-license") && strings.Contains(c.Reason, "not <config>") {
			rejected = true
		}
	}
	if !rejected {
		t.Errorf("the non-config XML should be reported as rejected: %+v", doc.Candidates)
	}
}

func TestExtractConfigFallbackOutsideMgmtDir(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"misc/dump.xml":       sampleConfigXML,
		"license/license.xml": decoyLicenseXML,
	})
	doc, err := ExtractConfig(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Root == nil || doc.Root.Tag != "config" {
		t.Fatalf("config outside the mgmt dir should still be found: %+v", doc)
	}
}

func TestExtractConfigMissing(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{"license/license.xml": decoyLicenseXML})
	if _, err := ExtractConfig(bytes.NewReader(tgz)); err != ErrNoConfig {
		t.Fatalf("got %v, want ErrNoConfig", err)
	}
}

func TestExtractConfigNoXMLAtAll(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{"var/log/pan/ms.log": "nothing"})
	if _, err := ExtractConfig(bytes.NewReader(tgz)); err != ErrNoConfig {
		t.Fatalf("got %v, want ErrNoConfig", err)
	}
}

func TestRankConfigCandidatesOrdering(t *testing.T) {
	in := []ConfigCandidate{
		{Path: "misc/other.xml", Size: 9999},
		{Path: "opt/pancfg/mgmt/small.xml", Size: 10},
		{Path: "tmp/cli/running-config.xml", Size: 50},
		{Path: "opt/pancfg/mgmt/saved/big.xml", Size: 5000},
	}
	got := rankConfigCandidates(in)
	if got[0].Path != "opt/pancfg/mgmt/saved/big.xml" {
		t.Errorf("first = %q, want the largest under the mgmt dir", got[0].Path)
	}
	if got[1].Path != "opt/pancfg/mgmt/small.xml" {
		t.Errorf("second = %q, want the other mgmt-dir file", got[1].Path)
	}
	if got[2].Path != "tmp/cli/running-config.xml" {
		t.Errorf("third = %q, want the name-matched config", got[2].Path)
	}
	if got[3].Path != "misc/other.xml" {
		t.Errorf("last = %q, want the unrecognized file", got[3].Path)
	}
}

func TestExtractConfigTreeShape(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{"opt/pancfg/mgmt/running-config.xml": sampleConfigXML})
	doc, err := ExtractConfig(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	cfg := doc.Root
	if cfg.Attrs["version"] != "10.2.0" {
		t.Fatalf("root attrs = %+v", cfg.Attrs)
	}
	shared := findChild(cfg, "shared")
	addr := findChild(shared, "address")
	if addr == nil || len(addr.Children) != 1 || addr.Children[0].Attrs["name"] != "web-server-1" {
		t.Fatalf("shared/address = %+v", addr)
	}
	if ip := findChild(addr.Children[0], "ip-netmask"); ip == nil || ip.Text != "10.1.1.5/32" {
		t.Fatalf("ip-netmask = %+v", ip)
	}
}

func findChild(n *ConfigNode, tag string) *ConfigNode {
	if n == nil {
		return nil
	}
	for _, c := range n.Children {
		if c.Tag == tag {
			return c
		}
	}
	return nil
}
