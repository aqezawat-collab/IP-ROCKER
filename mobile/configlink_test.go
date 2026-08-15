package mobile

import "testing"

// A VLESS-over-WebSocket link is the standard Cloudflare-fronted config, so its
// SNI, Host, path and port must all be recovered exactly.
func TestParseVLESSWebSocket(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@edge.example.com:443" +
		"?encryption=none&security=tls&sni=panel.example.com&type=ws" +
		"&host=panel.example.com&path=%2F%3Fed%3D2560#MyNode"

	cfg, err := ParseConfigLink(link)
	if err != nil {
		t.Fatalf("ParseConfigLink returned error: %v", err)
	}
	if cfg.SNI != "panel.example.com" {
		t.Errorf("SNI = %q, want panel.example.com", cfg.SNI)
	}
	if cfg.Host != "panel.example.com" {
		t.Errorf("Host = %q, want panel.example.com", cfg.Host)
	}
	if cfg.Path != "/?ed=2560" {
		t.Errorf("Path = %q, want /?ed=2560 (double URL-encoding must be undone)", cfg.Path)
	}
	if cfg.Port != 443 {
		t.Errorf("Port = %d, want 443", cfg.Port)
	}
	if cfg.Transport != "ws" {
		t.Errorf("Transport = %q, want ws", cfg.Transport)
	}
}

// A REALITY link cannot work behind a Cloudflare proxy, so it must be rejected
// with an explanation rather than silently producing a useless scan.
func TestParseRealityIsRejected(t *testing.T) {
	link := "vless://uuid@1.2.3.4:443?security=reality&sni=www.microsoft.com" +
		"&pbk=abcdef&fp=chrome&type=tcp#Reality"

	_, err := ParseConfigLink(link)
	if err == nil {
		t.Fatal("expected REALITY link to be rejected")
	}
	if !contains(err.Error(), "REALITY") || !contains(err.Error(), "terminates TLS") {
		t.Errorf("error should explain why REALITY cannot be fronted, got: %v", err)
	}
}

func TestParseTrojan(t *testing.T) {
	link := "trojan://password@edge.example.com:2053?security=tls&type=ws&path=/tj&sni=cdn.example.com"
	cfg, err := ParseConfigLink(link)
	if err != nil {
		t.Fatalf("ParseConfigLink returned error: %v", err)
	}
	if cfg.Port != 2053 {
		t.Errorf("Port = %d, want 2053", cfg.Port)
	}
	if cfg.Path != "/tj" {
		t.Errorf("Path = %q, want /tj", cfg.Path)
	}
	if cfg.SNI != "cdn.example.com" {
		t.Errorf("SNI = %q, want cdn.example.com", cfg.SNI)
	}
}

func TestParseVMessBase64(t *testing.T) {
	// {"v":"2","add":"104.16.0.1","port":"443","host":"panel.example.com",
	//  "path":"/ws","net":"ws","tls":"tls","sni":"panel.example.com"}
	link := "vmess://eyJ2IjoiMiIsImFkZCI6IjEwNC4xNi4wLjEiLCJwb3J0IjoiNDQzIiwiaG9zdCI6InBhbmVsLmV4YW1wbGUuY29tIiwicGF0aCI6Ii93cyIsIm5ldCI6IndzIiwidGxzIjoidGxzIiwic25pIjoicGFuZWwuZXhhbXBsZS5jb20ifQ"

	cfg, err := ParseConfigLink(link)
	if err != nil {
		t.Fatalf("ParseConfigLink returned error: %v", err)
	}
	if cfg.SNI != "panel.example.com" {
		t.Errorf("SNI = %q, want panel.example.com", cfg.SNI)
	}
	if cfg.Path != "/ws" {
		t.Errorf("Path = %q, want /ws", cfg.Path)
	}
	if cfg.Port != 443 {
		t.Errorf("Port = %d, want 443", cfg.Port)
	}
}

// A literal IP is useless as a TLS server name, so it must not be promoted into
// the SNI when the link omits one.
func TestLiteralIPIsNotUsedAsSNI(t *testing.T) {
	link := "vless://uuid@104.16.0.1:443?type=ws&security=tls&path=/x"
	_, err := ParseConfigLink(link)
	if err == nil {
		t.Fatal("expected rejection: link has no hostname to derive an SNI from")
	}
}

func TestApplyConfigURLUpdatesRequest(t *testing.T) {
	req := NewScanRequest()
	summary, err := req.ApplyConfigURL(
		"vless://uuid@edge.example.com:2087?security=tls&type=ws&sni=cdn.example.com&path=/vl")
	if err != nil {
		t.Fatalf("ApplyConfigURL returned error: %v", err)
	}
	if req.sni != "cdn.example.com" {
		t.Errorf("request SNI = %q, want cdn.example.com", req.sni)
	}
	if req.wsPath != "/vl" {
		t.Errorf("request ws path = %q, want /vl", req.wsPath)
	}
	if req.port != 2087 {
		t.Errorf("request port = %d, want 2087", req.port)
	}
	// A WebSocket path is recorded (wsPath) but must NOT auto-arm
	// RequireWebSocket: the upgrade is answered by the origin (e.g. a
	// Cloudflare Worker panel), not the edge, so forcing it would reject
	// every edge for Worker-fronted configs. requireWS stays opt-in.
	if req.requireWS {
		t.Error("ApplyConfigURL must not auto-enable requireWS from a path; it stays opt-in")
	}
	if summary == "" {
		t.Error("expected a human-readable summary of what was applied")
	}
}

func TestRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "   ", "http://example.com", "ss://abc@1.2.3.4:443"} {
		if _, err := ParseConfigLink(in); err == nil {
			t.Errorf("ParseConfigLink(%q) should have failed", in)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
