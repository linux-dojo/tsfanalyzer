package parser

import (
	"bytes"
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
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>web-browsing</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <tag><member>prod</member></tag>
                </entry>
              </rules>
            </security>
          </rulebase>
          <tag>
            <entry name="prod">
              <color>color3</color>
            </entry>
          </tag>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
`

const decoyLicenseXML = `<?xml version="1.0"?><License><Feature>Threat Prevention</Feature></License>`

func TestExtractConfigByName(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"configs/running-config.xml": sampleConfigXML,
		"license/license.xml":        decoyLicenseXML,
	})
	cfg, err := ExtractConfig(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tag != "config" {
		t.Fatalf("root tag = %q, want config", cfg.Tag)
	}
	if cfg.Attrs["version"] != "10.2.0" {
		t.Fatalf("root attrs = %+v", cfg.Attrs)
	}
}

func TestExtractConfigRootFallback(t *testing.T) {
	// no file is named like a config, but one has a <config> root — must
	// still be found.
	tgz := buildMultiTgz(t, map[string]string{
		"misc/dump.xml":       sampleConfigXML,
		"license/license.xml": decoyLicenseXML,
	})
	cfg, err := ExtractConfig(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tag != "config" {
		t.Fatalf("root tag = %q, want config", cfg.Tag)
	}
}

func TestExtractConfigMissing(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"license/license.xml": decoyLicenseXML,
	})
	if _, err := ExtractConfig(bytes.NewReader(tgz)); err != ErrNoConfig {
		t.Fatalf("got %v, want ErrNoConfig", err)
	}
}

func TestExtractConfigTreeShape(t *testing.T) {
	tgz := buildMultiTgz(t, map[string]string{
		"configs/running-config.xml": sampleConfigXML,
	})
	cfg, err := ExtractConfig(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}

	// find shared > address > entry
	shared := findChild(cfg, "shared")
	if shared == nil {
		t.Fatal("missing <shared>")
	}
	addr := findChild(shared, "address")
	if addr == nil || len(addr.Children) != 1 || addr.Children[0].Tag != "entry" {
		t.Fatalf("shared/address = %+v", addr)
	}
	if addr.Children[0].Attrs["name"] != "web-server-1" {
		t.Fatalf("address entry attrs = %+v", addr.Children[0].Attrs)
	}
	ipNetmask := findChild(addr.Children[0], "ip-netmask")
	if ipNetmask == nil || ipNetmask.Text != "10.1.1.5/32" {
		t.Fatalf("ip-netmask = %+v", ipNetmask)
	}

	// find the security rule several levels down and check its action text
	devices := findChild(cfg, "devices")
	device := findChild(devices, "entry")
	vsys := findChild(device, "vsys")
	vsysEntry := findChild(vsys, "entry")
	rulebase := findChild(vsysEntry, "rulebase")
	security := findChild(rulebase, "security")
	rules := findChild(security, "rules")
	if rules == nil || len(rules.Children) != 1 {
		t.Fatalf("security rules = %+v", rules)
	}
	rule := rules.Children[0]
	if rule.Attrs["name"] != "allow-web" {
		t.Fatalf("rule attrs = %+v", rule.Attrs)
	}
	action := findChild(rule, "action")
	if action == nil || action.Text != "allow" {
		t.Fatalf("action = %+v", action)
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
