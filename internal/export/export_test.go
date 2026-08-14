package export

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

var sampleEndpoints = []Endpoint{
	{IP: "1.2.3.4", Port: 443},
	{IP: "5.6.7.8", Port: 8443},
}

func testTemplate() Template {
	return Template{
		Name:      "test",
		UUID:      "11111111-2222-3333-4444-555555555555",
		SNI:       "edge.example.com",
		Host:      "front.example.com",
		Path:      "/?ed=2048",
		Transport: "ws",
		TLS:       true,
	}
}

func TestRawEndpoints(t *testing.T) {
	got := RawEndpoints(sampleEndpoints)
	want := "1.2.3.4:443\n5.6.7.8:8443"
	if got != want {
		t.Fatalf("RawEndpoints = %q, want %q", got, want)
	}
}

func TestV2RayLinks(t *testing.T) {
	links := V2RayLinks(testTemplate(), sampleEndpoints)
	lines := strings.Split(links, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 links, got %d: %q", len(lines), links)
	}
	first := lines[0]
	for _, want := range []string{
		"vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443",
		"type=ws",
		"security=tls",
		"sni=edge.example.com",
		"host=front.example.com",
		"path=%2F%3Fed%3D2048",
		"#test-1-1.2.3.4",
	} {
		if !strings.Contains(first, want) {
			t.Errorf("vless link missing %q\n got: %s", want, first)
		}
	}
}

func TestBase64SubscriptionRoundTrips(t *testing.T) {
	sub := Base64Subscription(testTemplate(), sampleEndpoints)
	decoded, err := base64.StdEncoding.DecodeString(sub)
	if err != nil {
		t.Fatalf("subscription is not valid base64: %v", err)
	}
	links := string(decoded)
	if !strings.Contains(links, "vless://") {
		t.Errorf("decoded subscription missing vless links: %s", links)
	}
	if strings.Count(links, "\n") != 1 {
		t.Errorf("expected 2 links separated by one newline, got %q", links)
	}
}

func TestClashYAML(t *testing.T) {
	out := ClashYAML(testTemplate(), sampleEndpoints)
	for _, want := range []string{
		"proxies:",
		"  - name: \"test-1-1.2.3.4\"",
		"    type: vless",
		"    server: 1.2.3.4",
		"    port: 443",
		"    network: ws",
		"    ws-opts:",
		"      path: \"/?ed=2048\"",
		"        Host: front.example.com",
		"    servername: edge.example.com",
		"    tls: true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Clash YAML missing %q\n got:\n%s", want, out)
		}
	}
}

func TestSingboxJSON(t *testing.T) {
	out := SingboxJSON(testTemplate(), sampleEndpoints)
	var doc struct {
		Outbounds []struct {
			Type  string `json:"type"`
			Tag   string `json:"tag"`
			Server string `json:"server"`
			Port  int    `json:"server_port"`
			UUID  string `json:"uuid"`
			TLS   struct {
				Enabled bool   `json:"enabled"`
				SNI     string `json:"server_name"`
			} `json:"tls"`
			Transport struct {
				Type    string `json:"type"`
				Path    string `json:"path"`
				Headers struct {
					Host string `json:"Host"`
				} `json:"headers"`
			} `json:"transport"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("SingboxJSON is not valid JSON: %v\n got:\n%s", err, out)
	}
	if len(doc.Outbounds) != 2 {
		t.Fatalf("expected 2 outbounds, got %d", len(doc.Outbounds))
	}
	o := doc.Outbounds[0]
	if o.Type != "vless" || o.Server != "1.2.3.4" || o.Port != 443 {
		t.Errorf("unexpected first outbound: %+v", o)
	}
	if o.TLS.Enabled != true || o.TLS.SNI != "edge.example.com" {
		t.Errorf("unexpected TLS block: %+v", o.TLS)
	}
	if o.Transport.Type != "ws" || o.Transport.Path != "/?ed=2048" || o.Transport.Headers.Host != "front.example.com" {
		t.Errorf("unexpected transport block: %+v", o.Transport)
	}
}

func TestRenderFallback(t *testing.T) {
	if got := Render("bogus", testTemplate(), sampleEndpoints); got != RawEndpoints(sampleEndpoints) {
		t.Errorf("unknown format should fall back to raw, got %q", got)
	}
	if got := Render("clash", testTemplate(), sampleEndpoints); got != ClashYAML(testTemplate(), sampleEndpoints) {
		t.Errorf("Render(clash) mismatch")
	}
}
