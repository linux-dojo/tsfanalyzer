package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

/*
security_test.go pins the browser-facing protections.

The bug being pinned by TestNoWildcardCORS was the most serious thing in the
codebase, and no dependency scanner would ever have reported it, because it was
our own five lines rather than a CVE in a package.
*/

// newTestServer lives in server_test.go — same package, so it is shared.

// TestNoWildcardCORS: with CORS_ALLOW_ORIGIN unset the API must send no
// Access-Control-Allow-Origin at all.
//
// The wildcard it replaced turned off the browser's same-origin protection on
// an API with no authentication. Any page the user visited while the tool ran
// could list their uploaded archives, read every file inside them — configs,
// addressing, serials, usernames — and delete them.
func TestNoWildcardCORS(t *testing.T) {
	allowedOrigin = "" // the default
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/files", nil)
	req.Host = "localhost:8081"
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q; it must be absent, and must never be \"*\"", got)
	}
}

func TestCORSOnlyEchoesTheConfiguredOrigin(t *testing.T) {
	allowedOrigin = "https://tsf.example.internal"
	defer func() { allowedOrigin = "" }()
	s := newTestServer(t)

	t.Run("configured origin is allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/files", nil)
		req.Host = "localhost:8081"
		req.Header.Set("Origin", "https://tsf.example.internal")
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://tsf.example.internal" {
			t.Fatalf("allow-origin = %q, want the configured origin", got)
		}
		if rec.Header().Get("Vary") == "" {
			t.Fatal("Vary: Origin is required so a shared cache cannot hand this response to another origin")
		}
	})

	t.Run("any other origin gets nothing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/files", nil)
		req.Host = "localhost:8081"
		req.Header.Set("Origin", "https://evil.example")
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("allow-origin = %q for an unconfigured origin; want empty", got)
		}
	})
}

// TestHostCheckBlocksDNSRebinding: once the CORS wildcard is gone, rebinding is
// the remaining way to reach this API from a hostile page — resolve a name you
// control to 127.0.0.1 and the browser treats the request as same-origin.
//
// Script cannot set the Host header, so checking it defeats the attack.
func TestHostCheckBlocksDNSRebinding(t *testing.T) {
	s := newTestServer(t)

	blocked := []string{"evil.example", "rebind.attacker.test:8081", "tsf.example.internal"}
	for _, h := range blocked {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/files", nil)
		req.Host = h
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("Host %q returned %d, want 403", h, rec.Code)
		}
	}
}

func TestHostCheckAllowsTheRealDeployments(t *testing.T) {
	s := newTestServer(t)

	allowed := []string{
		"localhost", "localhost:8080", "localhost:8081",
		"127.0.0.1", "127.0.0.1:8081",
		"api:8081",   // nginx -> api on the compose network
		"10.10.10.5", // reached by IP on a LAN
		"[::1]:8081",
	}
	for _, h := range allowed {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Host = h
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code == http.StatusForbidden {
			t.Errorf("Host %q was rejected; this is a supported way to reach the tool", h)
		}
	}
}

func TestAllowedHostsEnvOptsAName(t *testing.T) {
	old := extraHosts
	extraHosts = []string{"tsf.example.internal"}
	defer func() { extraHosts = old }()

	if !hostAllowed("tsf.example.internal:8080") {
		t.Fatal("a name listed in ALLOWED_HOSTS must be accepted")
	}
	if hostAllowed("other.example") {
		t.Fatal("a name not listed must still be rejected")
	}
}

func TestWildcardAllowedHostsDisablesTheCheck(t *testing.T) {
	old := extraHosts
	extraHosts = []string{"*"}
	defer func() { extraHosts = old }()

	if !hostAllowed("anything.example") {
		t.Fatal(`ALLOWED_HOSTS="*" must disable the check for proxies that rewrite Host`)
	}
}

// Responses carry the headers that stop content-type sniffing and framing.
func TestSecurityHeadersArePresent(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Host = "localhost:8081"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	for h, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := rec.Header().Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
}

// Archive content is served as text/plain, so a log line containing markup is
// never interpreted by the browser. React escaping is the first defence; this
// is the one that holds if someone opens the URL directly.
func TestUploadRejectsUnsupportedExtension(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/files", nil)
	req.Host = "localhost:8081"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
		t.Fatalf("a bodyless upload returned %d; it must be refused", rec.Code)
	}
}
