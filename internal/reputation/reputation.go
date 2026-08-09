// Package reputation scores Cloudflare edge addresses for "cleanliness".
//
// The primary provider is ipapi.is, which accepts up to 100 addresses per POST
// with no API key and returns per-address proxy/VPN/Tor/abuser flags plus
// company and ASN abuser scores. That bulk endpoint is what makes reputation
// filtering practical inside a scanner: a full scan's worth of hits can be
// rated in a handful of requests.
package reputation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	bulkEndpoint = "https://api.ipapi.is/"
	// bulkMax is the provider's documented per-request address limit.
	bulkMax = 100
)

// Verdict is a traffic-light summary of an address's reputation.
type Verdict int

const (
	VerdictUnknown Verdict = iota
	VerdictClean           // green: safe to hand to a config
	VerdictCaution         // yellow: usable but flagged
	VerdictDirty           // red: proxy/abuser flagged, avoid
)

func (v Verdict) String() string {
	switch v {
	case VerdictClean:
		return "clean"
	case VerdictCaution:
		return "caution"
	case VerdictDirty:
		return "dirty"
	default:
		return "unknown"
	}
}

// Emoji renders the verdict for terminal and mobile UIs.
func (v Verdict) Emoji() string {
	switch v {
	case VerdictClean:
		return "🟢"
	case VerdictCaution:
		return "🟡"
	case VerdictDirty:
		return "🔴"
	default:
		return "⚪"
	}
}

// Info is the reputation record for a single address.
type Info struct {
	IP string `json:"ip"`

	IsDatacenter bool `json:"is_datacenter"`
	IsProxy      bool `json:"is_proxy"`
	IsVPN        bool `json:"is_vpn"`
	IsTor        bool `json:"is_tor"`
	IsAbuser     bool `json:"is_abuser"`
	IsMobile     bool `json:"is_mobile"`
	IsSatellite  bool `json:"is_satellite"`
	IsBogon      bool `json:"is_bogon"`
	IsCrawler    bool `json:"is_crawler"`

	// CompanyAbuse and ASNAbuse are the provider's 0..1 abuse ratios for the
	// owning organisation and ASN.
	CompanyName  string  `json:"company_name"`
	CompanyAbuse float64 `json:"company_abuse"`
	ASN          int     `json:"asn"`
	ASNName      string  `json:"asn_name"`
	ASNAbuse     float64 `json:"asn_abuse"`
	Route        string  `json:"route"`

	Country string `json:"country"`
	City    string `json:"city"`
	Region  string `json:"region"`

	// RiskPercent is a 0..100 composite risk figure.
	RiskPercent float64 `json:"risk_percent"`
	Verdict     Verdict `json:"-"`
	VerdictName string  `json:"verdict"`

	// Reasons lists the specific flags that pushed risk up.
	Reasons []string `json:"reasons,omitempty"`

	// Err is set when this address could not be rated. An unrated address is
	// never reported as clean.
	Err string `json:"error,omitempty"`
}

// CleanEnough reports whether the address passes the given strictness.
func (i *Info) CleanEnough(strict bool) bool {
	if i == nil || i.Err != "" {
		return false
	}
	if strict {
		return i.Verdict == VerdictClean
	}
	return i.Verdict == VerdictClean || i.Verdict == VerdictCaution
}

// score fills RiskPercent, Verdict and Reasons from the raw flags.
//
// Being a datacenter address is deliberately not penalised: every Cloudflare
// edge address is a datacenter address, so penalising it would rank all
// candidates equally badly and destroy the signal.
func (i *Info) score() {
	risk := 0.0
	i.Reasons = nil

	switch {
	case i.IsBogon:
		risk += 100
		i.Reasons = append(i.Reasons, "bogon address")
	case i.IsTor:
		risk += 60
		i.Reasons = append(i.Reasons, "Tor exit node")
	}
	if i.IsAbuser {
		risk += 45
		i.Reasons = append(i.Reasons, "listed as abuse source")
	}
	if i.IsProxy {
		risk += 30
		i.Reasons = append(i.Reasons, "flagged as open proxy")
	}
	if i.IsVPN {
		risk += 12
		i.Reasons = append(i.Reasons, "flagged as VPN endpoint")
	}
	if i.IsCrawler {
		risk += 5
		i.Reasons = append(i.Reasons, "flagged as crawler")
	}

	// Organisation and ASN abuse ratios are small numbers (0.0076 = low,
	// 0.13 = high), so amplify them into percentage points.
	risk += clamp(i.CompanyAbuse*250, 0, 25)
	risk += clamp(i.ASNAbuse*250, 0, 15)
	if i.CompanyAbuse >= 0.05 {
		i.Reasons = append(i.Reasons,
			fmt.Sprintf("owner abuse ratio %.4f", i.CompanyAbuse))
	}

	i.RiskPercent = clamp(risk, 0, 100)

	switch {
	case i.RiskPercent < 12:
		i.Verdict = VerdictClean
	case i.RiskPercent < 35:
		i.Verdict = VerdictCaution
	default:
		i.Verdict = VerdictDirty
	}
	i.VerdictName = i.Verdict.String()
}

// Client fetches and caches reputation records.
type Client struct {
	HTTP    *http.Client
	Timeout time.Duration
	// Disabled short-circuits every lookup, used for offline scans.
	Disabled bool

	mu    sync.RWMutex
	cache map[string]*Info
}

// NewClient returns a Client with sane defaults for mobile networks. The
// lookup timeout is deliberately short: a provider that has not answered within
// a few seconds on a mobile link is usually not reachable at all (censorship
// blocks the endpoint), and stinting here means the scan stalls for minutes in
// its reputation phase instead of finishing with measurement-only results.
func NewClient() *Client {
	return &Client{
		HTTP: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				MaxIdleConns:        8,
				IdleConnTimeout:     60 * time.Second,
				TLSHandshakeTimeout: 5 * time.Second,
			},
		},
		Timeout: 8 * time.Second,
		cache:   make(map[string]*Info),
	}
}

// Cached returns a previously fetched record without touching the network.
func (c *Client) Cached(ip string) (*Info, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	i, ok := c.cache[ip]
	return i, ok
}

// Lookup rates a single address.
func (c *Client) Lookup(ctx context.Context, ip net.IP) (*Info, error) {
	m, err := c.LookupBulk(ctx, []net.IP{ip})
	if err != nil {
		return nil, err
	}
	if info, ok := m[ip.String()]; ok {
		return info, nil
	}
	return nil, fmt.Errorf("no reputation record for %s", ip)
}

// LookupBulk rates every address in ips, chunking to the provider's limit and
// serving repeats from cache. The returned map is keyed by address string and
// always contains an entry per input, with Err set on failures.
func (c *Client) LookupBulk(ctx context.Context, ips []net.IP) (map[string]*Info, error) {
	out := make(map[string]*Info, len(ips))
	if len(ips) == 0 {
		return out, nil
	}

	var pending []string
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		s := ip.String()
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		if cached, ok := c.Cached(s); ok {
			out[s] = cached
			continue
		}
		pending = append(pending, s)
	}

	if c.Disabled {
		for _, s := range pending {
			out[s] = &Info{IP: s, Err: "reputation lookups disabled"}
		}
		return out, nil
	}

	var firstErr error
	for start := 0; start < len(pending); start += bulkMax {
		end := min(start+bulkMax, len(pending))
		chunk := pending[start:end]

		batch, err := c.fetchChunk(ctx, chunk)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// Record the failure per address so callers never mistake an
			// unreachable provider for a clean result.
			for _, s := range chunk {
				out[s] = &Info{IP: s, Err: err.Error()}
			}
			// An unreachable provider fails every chunk identically, so waiting
			// out the timeout on each one only stalls the scan in its reputation
			// phase. Mark the rest failed and stop; the one failure a later chunk
			// could dodge is a rate limit, which is not a connection error.
			if isUnreachable(err) {
				for _, s := range pending[start+len(chunk):] {
					out[s] = &Info{IP: s, Err: err.Error()}
				}
				return out, firstErr
			}
			continue
		}
		for _, s := range chunk {
			info, ok := batch[s]
			if !ok || info == nil {
				info = &Info{IP: s, Err: "address missing from provider response"}
			}
			out[s] = info
			if info.Err == "" {
				c.mu.Lock()
				c.cache[s] = info
				c.mu.Unlock()
			}
		}
	}
	return out, firstErr
}

func (c *Client) fetchChunk(ctx context.Context, ips []string) (map[string]*Info, error) {
	body, err := json.Marshal(map[string][]string{"ips": ips})
	if err != nil {
		return nil, err
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, bulkEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "IP-ROCKER")

	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reputation request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("reading reputation response: %w", err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("reputation provider rate limit reached (HTTP 429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reputation provider returned HTTP %d: %s",
			resp.StatusCode, snippet(raw))
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("decoding reputation response: %w", err)
	}

	out := make(map[string]*Info, len(ips))
	for key, val := range envelope {
		if key == "" || !isAddressKey(key) {
			continue
		}
		info := parseRecord(key, val)
		out[key] = info
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("reputation response contained no address records: %s", snippet(raw))
	}
	return out, nil
}

// rawRecord mirrors the provider's per-address object. is_crawler is typed as
// json.RawMessage because the provider returns either a bool or a bot name.
type rawRecord struct {
	IP           string          `json:"ip"`
	IsBogon      bool            `json:"is_bogon"`
	IsMobile     bool            `json:"is_mobile"`
	IsSatellite  bool            `json:"is_satellite"`
	IsDatacenter bool            `json:"is_datacenter"`
	IsTor        bool            `json:"is_tor"`
	IsProxy      bool            `json:"is_proxy"`
	IsVPN        bool            `json:"is_vpn"`
	IsAbuser     bool            `json:"is_abuser"`
	IsCrawler    json.RawMessage `json:"is_crawler"`

	Company struct {
		Name        string `json:"name"`
		AbuserScore string `json:"abuser_score"`
	} `json:"company"`
	ASN struct {
		ASN         int    `json:"asn"`
		Org         string `json:"org"`
		Descr       string `json:"descr"`
		Route       string `json:"route"`
		AbuserScore string `json:"abuser_score"`
	} `json:"asn"`
	Location struct {
		Country string `json:"country"`
		State   string `json:"state"`
		City    string `json:"city"`
	} `json:"location"`
}

func parseRecord(key string, val json.RawMessage) *Info {
	var rr rawRecord
	if err := json.Unmarshal(val, &rr); err != nil {
		return &Info{IP: key, Err: "unparseable provider record"}
	}
	ipStr := rr.IP
	if ipStr == "" {
		ipStr = key
	}
	info := &Info{
		IP:           ipStr,
		IsDatacenter: rr.IsDatacenter,
		IsProxy:      rr.IsProxy,
		IsVPN:        rr.IsVPN,
		IsTor:        rr.IsTor,
		IsAbuser:     rr.IsAbuser,
		IsMobile:     rr.IsMobile,
		IsSatellite:  rr.IsSatellite,
		IsBogon:      rr.IsBogon,
		IsCrawler:    crawlerFlag(rr.IsCrawler),
		CompanyName:  rr.Company.Name,
		CompanyAbuse: parseAbuserScore(rr.Company.AbuserScore),
		ASN:          rr.ASN.ASN,
		ASNName:      firstNonEmpty(rr.ASN.Org, rr.ASN.Descr),
		ASNAbuse:     parseAbuserScore(rr.ASN.AbuserScore),
		Route:        rr.ASN.Route,
		Country:      rr.Location.Country,
		Region:       rr.Location.State,
		City:         rr.Location.City,
	}
	info.score()
	return info
}

// crawlerFlag handles is_crawler arriving as either false or "CloudflareBot".
//
// Cloudflare's own edge addresses are routinely labelled "CloudflareBot", which
// is expected rather than suspicious, so that specific value is not treated as
// a crawler flag.
func crawlerFlag(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" || strings.EqualFold(s, "CloudflareBot") {
			return false
		}
		return true
	}
	return false
}

// isUnreachable reports whether a chunk failure means the provider itself is out
// of reach rather than the request being rejected. Dial and TLS failures and
// timeouts indicate censorship or a dead endpoint, and will repeat for every
// chunk; an HTTP status like 429 is per-request and a later chunk might dodge it.
func isUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	// TLS handshake failures surface as tls errors rather than a *net.OpError
	// on some Go versions and transports.
	if strings.Contains(err.Error(), "handshake") {
		return true
	}
	return false
}

// parseAbuserScore extracts the float from strings like "0.0076 (Low)".
func parseAbuserScore(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if idx := strings.IndexByte(s, ' '); idx > 0 {
		s = s[:idx]
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return f
}

func isAddressKey(k string) bool {
	return net.ParseIP(k) != nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func snippet(b []byte) string {
	const maxLen = 180
	s := strings.TrimSpace(string(b))
	if len(s) > maxLen {
		return s[:maxLen] + "…"
	}
	return s
}
