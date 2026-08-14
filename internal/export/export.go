// Package export turns discovered Cloudflare edge addresses into the portable
// subscription formats other scanners (e.g. SenPaiScanner) emit. IP-ROCKER
// finds clean edges; it does not own the user's proxy credentials, so the node
// template carries the connection parameters it does know (SNI, host, path,
// transport) and a placeholder UUID the user fills in their client.
package export

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// Endpoint is a discovered Cloudflare edge address.
type Endpoint struct {
	IP   string
	Port int
}

// Template carries the connection parameters shared by every exported node.
type Template struct {
	Name      string
	UUID      string
	SNI       string
	Host      string
	Path      string
	Transport string // "tcp" or "ws"; empty defaults to "tcp"
	TLS       bool
}

func (t Template) network() string {
	if t.Transport == "" {
		return "tcp"
	}
	return t.Transport
}

func (t Template) hostOrSNI() string {
	if t.Host != "" {
		return t.Host
	}
	return t.SNI
}

func (t Template) uuid() string {
	if t.UUID == "" {
		return "00000000-0000-0000-0000-000000000000"
	}
	return t.UUID
}

func (t Template) nodeName(ip string, idx int) string {
	name := t.Name
	if name == "" {
		name = "iprocker"
	}
	return fmt.Sprintf("%s-%d-%s", name, idx+1, ip)
}

// RawEndpoints returns one ip:port per line — the portable form any client
// can paste.
func RawEndpoints(eps []Endpoint) string {
	var b strings.Builder
	for _, e := range eps {
		fmt.Fprintf(&b, "%s:%d\n", e.IP, e.Port)
	}
	return strings.TrimRight(b.String(), "\n")
}

// V2RayLinks builds standard v2rayN vless:// URIs, one per endpoint.
func V2RayLinks(t Template, eps []Endpoint) string {
	var b strings.Builder
	net := t.network()
	for i, e := range eps {
		q := url.Values{}
		q.Set("type", net)
		if t.TLS {
			q.Set("security", "tls")
		} else {
			q.Set("security", "none")
		}
		if t.SNI != "" {
			q.Set("sni", t.SNI)
		}
		if t.hostOrSNI() != "" {
			q.Set("host", t.hostOrSNI())
		}
		if net == "ws" && t.Path != "" {
			q.Set("path", t.Path)
		}
		u := url.URL{
			Scheme:   "vless",
			User:     url.User(t.uuid()),
			Host:     fmt.Sprintf("%s:%d", e.IP, e.Port),
			RawQuery: q.Encode(),
			Fragment: t.nodeName(e.IP, i),
		}
		fmt.Fprintln(&b, u.String())
	}
	return strings.TrimRight(b.String(), "\n")
}

// Base64Subscription returns the v2rayN subscription form: base64 of the
// joined vless links.
func Base64Subscription(t Template, eps []Endpoint) string {
	return base64.StdEncoding.EncodeToString([]byte(V2RayLinks(t, eps)))
}

// ClashYAML renders a minimal Clash config whose proxies are the discovered
// edges, using the shared connection template.
func ClashYAML(t Template, eps []Endpoint) string {
	var b strings.Builder
	fmt.Fprintf(&b, "port: 7890\n")
	fmt.Fprintf(&b, "socks-port: 7891\n")
	fmt.Fprintf(&b, "allow-lan: false\n")
	fmt.Fprintf(&b, "mode: rule\n")
	fmt.Fprintf(&b, "log-level: info\n")
	fmt.Fprintf(&b, "proxies:\n")
	net := t.network()
	for i, e := range eps {
		name := t.nodeName(e.IP, i)
		fmt.Fprintf(&b, "  - name: %q\n", name)
		fmt.Fprintf(&b, "    type: vless\n")
		fmt.Fprintf(&b, "    server: %s\n", e.IP)
		fmt.Fprintf(&b, "    port: %d\n", e.Port)
		fmt.Fprintf(&b, "    uuid: %s\n", t.uuid())
		fmt.Fprintf(&b, "    network: %s\n", net)
		if net == "ws" {
			fmt.Fprintf(&b, "    ws-opts:\n")
			fmt.Fprintf(&b, "      path: %q\n", t.Path)
			fmt.Fprintf(&b, "      headers:\n")
			fmt.Fprintf(&b, "        Host: %s\n", t.hostOrSNI())
		}
		fmt.Fprintf(&b, "    servername: %s\n", t.SNI)
		fmt.Fprintf(&b, "    tls: %v\n", t.TLS)
		fmt.Fprintf(&b, "    udp: true\n")
	}
	return b.String()
}

// SingboxJSON renders a sing-box outbounds list for the discovered edges.
func SingboxJSON(t Template, eps []Endpoint) string {
	net := t.network()
	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString("  \"outbounds\": [\n")
	for i, e := range eps {
		name := t.nodeName(e.IP, i)
		fmt.Fprintf(&b, "    {\n")
		fmt.Fprintf(&b, "      \"type\": \"vless\",\n")
		fmt.Fprintf(&b, "      \"tag\": %q,\n", name)
		fmt.Fprintf(&b, "      \"server\": %q,\n", e.IP)
		fmt.Fprintf(&b, "      \"server_port\": %d,\n", e.Port)
		fmt.Fprintf(&b, "      \"uuid\": %q,\n", t.uuid())
		fmt.Fprintf(&b, "      \"tls\": { \"enabled\": %v, \"server_name\": %q },\n", t.TLS, t.SNI)
		fmt.Fprintf(&b, "      \"transport\": { \"type\": %q", net)
		if net == "ws" {
			fmt.Fprintf(&b, ", \"path\": %q, \"headers\": { \"Host\": %q }", t.Path, t.hostOrSNI())
		}
		fmt.Fprintf(&b, " }\n")
		if i < len(eps)-1 {
			fmt.Fprintf(&b, "    },\n")
		} else {
			fmt.Fprintf(&b, "    }\n")
		}
	}
	b.WriteString("  ]\n")
	b.WriteString("}\n")
	return b.String()
}

// Render returns the export in the requested format. Unknown formats fall back
// to raw endpoints.
func Render(format string, t Template, eps []Endpoint) string {
	switch format {
	case "clash":
		return ClashYAML(t, eps)
	case "singbox":
		return SingboxJSON(t, eps)
	case "base64":
		return Base64Subscription(t, eps)
	default:
		return RawEndpoints(eps)
	}
}
