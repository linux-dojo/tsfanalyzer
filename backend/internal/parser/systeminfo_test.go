package parser

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

const sampleCLI = `
==========================
 > show clock

Tue Jun  9 10:15:02 PST 2026

==========================
 > show system info

hostname: PA-FW-LAB01
ip-address: 192.168.1.1
public-ip-address: unknown
netmask: 255.255.255.0
default-gateway: 192.168.1.254
mac-address: 00:1b:17:00:01:10
time: Tue Jun  9 10:15:02 2026
uptime: 45 days, 3:22:10
family: vm
model: PA-VM
serial: 0070000001234
sw-version: 10.2.4
global-protect-client-package-version: 0.0.0
app-version: 8700-7900
app-release-date: 2026/06/01 18:01:02 PDT
threat-version: 8700-7900
wildfire-version: 0
logdb-version: 10.2.0
platform-family: vm
vpn-disable-mode: off
multi-vsys: off
operational-mode: normal
device-certificate-status: None

==========================
 > show interface all
...
`

func buildTgz(t *testing.T, path, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: path, Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte(content))
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestExtractSystemInfo(t *testing.T) {
	tgz := buildTgz(t, "tmp/cli/techsupport_20260609.txt", sampleCLI)
	kv, err := ExtractSystemInfo(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	if len(kv) != 23 {
		t.Fatalf("got %d pairs, want 23", len(kv))
	}
	if kv[0].Key != "hostname" || kv[0].Value != "PA-FW-LAB01" {
		t.Fatalf("first pair = %+v", kv[0])
	}
	last := kv[len(kv)-1]
	if last.Key != "device-certificate-status" || last.Value != "None" {
		t.Fatalf("last pair = %+v", last)
	}
	got := map[string]string{}
	for _, p := range kv {
		got[p.Key] = p.Value
	}
	if got["sw-version"] != "10.2.4" || got["serial"] != "0070000001234" {
		t.Fatalf("unexpected values: %v", got)
	}
}

func TestExtractSystemInfoMissing(t *testing.T) {
	tgz := buildTgz(t, "tmp/cli/other.txt", "> show clock\nTue Jun 9\n")
	if _, err := ExtractSystemInfo(bytes.NewReader(tgz)); err == nil {
		t.Fatal("expected error for archive without system info")
	}
}

func TestExtractSystemInfoIgnoresOtherPaths(t *testing.T) {
	tgz := buildTgz(t, "var/log/system.log", sampleCLI)
	if _, err := ExtractSystemInfo(bytes.NewReader(tgz)); err == nil {
		t.Fatal("expected error: file is outside tmp/cli/")
	}
}
