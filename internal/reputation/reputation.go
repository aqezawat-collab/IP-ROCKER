// Package reputation looks up the IP reputation of a scanned address so the
// user can tell a legitimate Cloudflare edge from an abused or proxied host.
//
// Every Cloudflare edge is a datacenter, so a datacenter flag is expected
// rather than a fault; what matters is whether the address is associated with
// proxy/VPN/Tor or other abusive infrastructure. Lookups are best-effort: a
// provider outage returns an Info with Err set instead of failing the scan.
package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Verdict is the reputation conclusion for an address.
type Verdict int

const (
	// VerdictUnknown means no conclusion could be drawn (e.g. lookup failed).
	VerdictUnknown Verdict = iota
	// VerdictClean means the address shows no abuse association.
	VerdictClean
	// VerdictCaution means some risk signal was present but not conclusive.
	VerdictCaution
	// VerdictBad means the address is associated with proxy/VPN/Tor abuse.
	VerdictBad
)

func (v Verdict) String() string {
	switch v {
	case VerdictClean:
		return "clean"
	case VerdictCaution:
		return "caution"
	case VerdictBad:
		return "bad"
	default:
		return "unknown"
	}
}

// Info is the reputation of a single address.
type Info struct {
	// Err is non-empty when the lookup failed. A failed lookup must never be
	// reported as clean, only as "not verified".
	Err string `json:"error,omitempty"`

	Verdict Verdict `json:"verdict"`

	// RiskPercent is the estimated (0-100) chance this address is associated
	// with abusive infrastructure. A datacenter flag alone is not treated as
	// risk, because every Cloudflare edge is one.
	RiskPercent int `json:"risk_percent"`

	IsDatacenter bool `json:"is_datacenter"`

	CompanyName string `json:"company_name,omitempty"`
	Org         string `json:"org,omitempty"`
	Route       string `json:"route,omitempty"`
	ASN         string `json:"asn,omitempty"`
	Country     string `json:"country,omitempty"`
	City        string `json:"city,omitempty"`
}

// ipwhoResponse is the subset of the ipwho.is response we consume. The service
// needs no API key and returns connection type and abuse flags.
type ipwhoResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Country string `json:"country"`
	City    string `json:"city"`
	Connection struct {
		ASN  int    `json:"asn"`
		Org  string `json:"org"`
		ISP  string `json:"isp"`
		Type string `json:"type"`
	} `json:"connection"`
	Security struct {
		VPN   bool `json:"vpn"`
		Proxy bool `json:"proxy"`
		Tor   bool `json:"tor"`
	} `json:"security"`
}

var client = &http.Client{Timeout: 5 * time.Second}

// Lookup returns the reputation of ip. It is best-effort: network or parsing
// failures return an Info with Err set rather than nil, because a single
// provider outage must never make a working edge look malicious.
func Lookup(ctx context.Context, ip string) *Info {
	url := "https://ipwho.is/" + ip
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return &Info{Err: "provider request failed: " + err.Error()}
	}
	resp, err := client.Do(req)
	if err != nil {
		return &Info{Err: "reputation provider unreachable: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Info{Err: fmt.Sprintf("reputation provider returned HTTP %d", resp.StatusCode)}
	}
	var r ipwhoResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return &Info{Err: "reputation response unreadable: " + err.Error()}
	}
	if !r.Success {
		msg := r.Message
		if msg == "" {
			msg = "provider reported failure"
		}
		return &Info{Err: msg}
	}

	info := &Info{
		Country:      r.Country,
		City:         r.City,
		Org:          r.Connection.Org,
		CompanyName:  r.Connection.Org,
		ASN:          fmt.Sprintf("AS%d", r.Connection.ASN),
	}
	orgISP := strings.ToLower(r.Connection.Org + " " + r.Connection.ISP)
	t := strings.ToLower(r.Connection.Type)
	info.IsDatacenter = t == "hosting" || t == "datacenter" ||
		strings.Contains(orgISP, "hosting") ||
		strings.Contains(orgISP, "data center") ||
		strings.Contains(orgISP, "colocation") ||
		strings.Contains(orgISP, "colo")

	abusive := r.Security.VPN || r.Security.Proxy || r.Security.Tor
	switch {
	case abusive:
		info.Verdict = VerdictBad
		info.RiskPercent = 90
	case info.IsDatacenter:
		// A datacenter is expected for a Cloudflare edge; not risky by itself.
		info.Verdict = VerdictClean
		info.RiskPercent = 10
	default:
		info.Verdict = VerdictClean
		info.RiskPercent = 5
	}
	return info
}
