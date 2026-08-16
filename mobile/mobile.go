// Package mobile is the gomobile-facing API for the Android app.
//
// gomobile can only bind a restricted subset of Go: exported functions may use
// string, numeric types, bool, byte slices, error and pointers to bound structs.
// Slices of structs and maps cannot cross the boundary, so results are handed
// over as JSON strings and decoded on the Kotlin side. Keeping that translation
// in one package means the scanner core stays idiomatic Go.
//
// Integer parameters are declared as int32 rather than int on purpose: gomobile
// maps Go int to Java long, which would force every Kotlin call site to widen
// its literals. int32 binds to a plain Java int.
package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Qezawat/IP-ROCKER/internal/cfranges"
	"github.com/Qezawat/IP-ROCKER/internal/netports"
	"github.com/Qezawat/IP-ROCKER/internal/probe"
	"github.com/Qezawat/IP-ROCKER/internal/scanner"
	"github.com/Qezawat/IP-ROCKER/internal/score"
)

// Version is stamped at build time via -ldflags.
var Version = "dev"

// ProgressListener receives scan updates. Kotlin implements this interface and
// marshals the callbacks onto the main thread itself.
type ProgressListener interface {
	// OnProgress reports counters and the current phase.
	OnProgress(phase string, tested, total, hits, inFlight int32)
	// OnHit delivers a single candidate as JSON as soon as it passes probing.
	OnHit(candidateJSON string)
	// OnFinished delivers the full report as JSON. err is empty on success.
	OnFinished(reportJSON string, err string)
	// OnLog carries a human-readable note, such as a provider error.
	OnLog(message string)
}

// ScanRequest is built field by field from Kotlin, because gomobile cannot pass
// a struct literal across the boundary.
type ScanRequest struct {
	count          int32
	concurrency    int32
	port           int32
	mode           string
	tries          int32
	timeoutMs      int32
	holdMs         int32
	downloadBytes  int64
	uploadBytes    int64
	sni            string
	host           string
	wsPath         string
	ports          string
	minSpeedKBps   float64
	requireWS bool
	strict    bool
	extraCIDRs     string
	onlyExtra      bool
	topN           int32
	exportMode     string
	importMode     string // "comma" or "lines"
}

// NewScanRequest returns a request preloaded with defaults tuned for a phone on
// a mobile network: a moderate address count, conservative concurrency to avoid
// exhausting sockets, and the reset-detecting idle hold enabled.
func NewScanRequest() *ScanRequest {
	return &ScanRequest{
		count:       400,
		concurrency: 48,
		port:        443,
		mode:        "http",
		tries:       3,
		timeoutMs:   6000,
		holdMs:      3000,
		// A megabyte is the smallest sample that reliably separates a slow
		// middlebox from a real edge; a 256 KB fetch finishes inside the noise
		// on either.
		downloadBytes: 1024 * 1024,
		uploadBytes:   0,
	}
}

// Setters. gomobile exposes each of these as a Java method.

func (r *ScanRequest) SetCount(v int32)          { r.count = v }
func (r *ScanRequest) SetConcurrency(v int32)    { r.concurrency = v }
func (r *ScanRequest) SetPort(v int32)           { r.port = v }
func (r *ScanRequest) SetMode(v string)          { r.mode = v }
func (r *ScanRequest) SetTries(v int32)          { r.tries = v }
func (r *ScanRequest) SetTimeoutMs(v int32)      { r.timeoutMs = v }
func (r *ScanRequest) SetHoldMs(v int32)         { r.holdMs = v }
func (r *ScanRequest) SetDownloadBytes(v int64)  { r.downloadBytes = v }
func (r *ScanRequest) SetUploadBytes(v int64)    { r.uploadBytes = v }
func (r *ScanRequest) SetSNI(v string)           { r.sni = v }
func (r *ScanRequest) SetHost(v string)          { r.host = v }
func (r *ScanRequest) SetWebSocketPath(v string) { r.wsPath = v }

// SetPorts takes a comma-separated port list, for example "443,2053,8443".
// Empty means probe only the single port set by SetPort. Selecting several
// ports multiplies the number of probes.
func (r *ScanRequest) SetPorts(v string) { r.ports = v }

// SetMinSpeedKBps rejects addresses whose download sample is slower than this.
// Zero disables the filter.
func (r *ScanRequest) SetMinSpeedKBps(v float64) { r.minSpeedKBps = v }

func (r *ScanRequest) SetRequireWebSocket(v bool) { r.requireWS = v }
func (r *ScanRequest) SetStrict(v bool)           { r.strict = v }
func (r *ScanRequest) SetTopN(v int32)            { r.topN = v }
func (r *ScanRequest) SetExportMode(v string)     { r.exportMode = v }
func (r *ScanRequest) SetImportMode(v string)     { r.importMode = v }
func (r *ScanRequest) SetExtraCIDRs(v string)     { r.extraCIDRs = v }
func (r *ScanRequest) SetOnlyExtra(v bool)        { r.onlyExtra = v }

// ApplyConfigURL parses a VLESS, Trojan or VMess link and derives the SNI, Host,
// WebSocket path and port from it, so the scan probes the exact front the user's
// config will use rather than a generic Cloudflare hostname. It returns a short
// description of what was applied, or an error explaining why the link is not
// usable.
func (r *ScanRequest) ApplyConfigURL(raw string) (string, error) {
	cfg, err := ParseConfigLink(raw)
	if err != nil {
		return "", err
	}
	if cfg.SNI != "" {
		r.sni = cfg.SNI
	}
	if cfg.Host != "" {
		r.host = cfg.Host
	}
	if cfg.Path != "" {
		r.wsPath = cfg.Path
		// NOTE: we do NOT force RequireWebSocket from a path alone. The WS
		// upgrade is answered by the origin (e.g. a Cloudflare Worker panel),
		// not the edge, so a failed upgrade reflects the origin's capability —
		// not the edge's health. Force-arming it disqualified every edge for
		// Worker-fronted configs ("no usable edges"). WS stays a soft signal
		// used for scoring/sorting; opt in explicitly via SetRequireWebSocket
		// / -require-ws when the origin is a real ws proxy.
	}
	if cfg.Port > 0 {
		r.port = int32(cfg.Port)
		// A config link names one port, so probing a wider set would test
		// endpoints the config cannot use.
		r.ports = ""
	}

	var parts []string
	// Surface the detected transport/security up front so the user can see the
	// config was recognised as "WS + TLS" (or TLS, or REALITY) rather than
	// leaving it ambiguous whether a WebSocket config was treated as plain SNI.
	if label := configTransportLabel(cfg); label != "" {
		parts = append(parts, label)
	}
	if cfg.SNI != "" {
		parts = append(parts, "SNI "+cfg.SNI)
	}
	if cfg.Host != "" && cfg.Host != cfg.SNI {
		parts = append(parts, "Host "+cfg.Host)
	}
	if cfg.Path != "" {
		parts = append(parts, "path "+cfg.Path)
	}
	if cfg.Port > 0 {
		parts = append(parts, fmt.Sprintf("port %d", cfg.Port))
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("config link contained no usable TLS or transport settings")
	}
	return strings.Join(parts, ", "), nil
}

// configTransportLabel describes the detected transport and security layer so
// the UI can show exactly what a pasted link was recognised as — for example
// "WS + TLS" for a vless://…?type=ws&security=tls link, instead of leaving it
// ambiguous whether the config was treated as plain SNI/TLS. The scanner always
// uses SNI/Host/path regardless of this label; it is display-only.
func configTransportLabel(cfg *ConfigLink) string {
	var parts []string
	switch strings.ToLower(strings.TrimSpace(cfg.Transport)) {
	case "ws", "websocket", "httpupgrade":
		parts = append(parts, "WS")
	case "xhttp":
		parts = append(parts, "XHTTP")
	case "tcp", "":
		// default transport; no prefix needed
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Security)) {
	case "tls":
		parts = append(parts, "TLS")
	case "reality":
		parts = append(parts, "REALITY")
	case "none", "":
		// no explicit security layer named
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " + ")
}

// Scanner is the handle Kotlin holds for a running or finished scan.
type Scanner struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
}

// NewScanner creates a scanner handle.
func NewScanner() *Scanner { return &Scanner{} }

// IsRunning reports whether a scan is in flight.
func (s *Scanner) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Stop cancels a running scan. Results gathered so far are still delivered.
func (s *Scanner) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Start launches a scan on a background goroutine and streams updates to the
// listener. It returns immediately; the caller must not block on it.
func (s *Scanner) Start(req *ScanRequest, listener ProgressListener) error {
	if req == nil {
		return fmt.Errorf("scan request was nil")
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("a scan is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.running = true
	s.mu.Unlock()

	opts, err := req.toOptions(listener)
	if err != nil {
		s.finish(cancel)
		return err
	}

	go func() {
		defer s.finish(cancel)

		sc := scanner.New(opts)
		report, err := sc.Run(ctx)
		if listener == nil {
			return
		}
		if err != nil {
			listener.OnFinished("", err.Error())
			return
		}
		payload, jerr := json.Marshal(reportPayload(report))
		if jerr != nil {
			listener.OnFinished("", "encoding report: "+jerr.Error())
			return
		}
		listener.OnFinished(string(payload), "")
	}()
	return nil
}

func (s *Scanner) finish(cancel context.CancelFunc) {
	cancel()
	s.mu.Lock()
	s.running = false
	s.cancel = nil
	s.mu.Unlock()
}

func (r *ScanRequest) toOptions(listener ProgressListener) (scanner.Options, error) {
	mode, err := probe.ParseMode(r.mode)
	if err != nil {
		return scanner.Options{}, err
	}

	crit := score.DefaultCriteria()
	if r.strict {
		crit = score.StrictCriteria()
	}
	if r.requireWS {
		crit.RequireWebSocket = true
	}
	if r.minSpeedKBps > 0 {
		crit.MinDownloadKBps = r.minSpeedKBps
	}

	ports, err := netports.Parse(r.ports, int(r.port))
	if err != nil {
		return scanner.Options{}, err
	}

	var extra []string
	// Import mode selects how the custom ranges text is split. "lines" accepts a
	// file pasted line-by-line (one CIDR or IP per line), which is what most
	// exported lists actually look like; "comma" keeps the old single-line
	// comma-separated form. Blank lines and comments are ignored either way.
	raw := r.extraCIDRs
	if r.importMode == "lines" {
		raw = strings.ReplaceAll(raw, "\n", ",")
	}
	for _, c := range strings.Split(raw, ",") {
		c = strings.TrimSpace(c)
		if c == "" || strings.HasPrefix(c, "#") {
			continue
		}
		// A bare IP is treated as a /32 so a pasted ip list still scans.
		if net.ParseIP(c) != nil {
			c += "/32"
		}
		extra = append(extra, c)
	}

	opts := scanner.Options{
		Count:       int(r.count),
		Concurrency: int(r.concurrency),
		Ports:       ports,
		Probe: probe.Config{
			Port:             ports[0],
			Mode:             mode,
			Tries:            int(r.tries),
			Timeout:          time.Duration(r.timeoutMs) * time.Millisecond,
			SNI:              r.sni,
			Host:             r.host,
			HoldDuration:     time.Duration(r.holdMs) * time.Millisecond,
			DownloadBytes:    r.downloadBytes,
			UploadBytes:      r.uploadBytes,
			WebSocketPath:    r.wsPath,
			RequireWebSocket: r.requireWS,
		},
		Criteria: crit,
		Ranges: cfranges.Options{
			IPv4:       true,
			ExtraCIDRs: extra,
			OnlyExtra:  r.onlyExtra,
			SkipDirty:  true,
		},
		TopN:       int(r.topN),
		ExportMode: r.exportMode,
	}

	if listener != nil {
		// Progress arrives from many goroutines at once; throttle it so the UI
		// thread is not flooded with hundreds of updates per second.
		var mu sync.Mutex
		var last time.Time
		opts.Report = func(p scanner.Progress) {
			if p.Message != "" {
				listener.OnLog(p.Message)
				return
			}
			mu.Lock()
			if p.Phase != scanner.PhaseDone && time.Since(last) < 120*time.Millisecond {
				mu.Unlock()
				return
			}
			last = time.Now()
			mu.Unlock()
			listener.OnProgress(p.Phase.String(),
				int32(p.Tested), int32(p.Total), int32(p.Hits), int32(p.InFlight))
		}
		opts.OnHit = func(c *score.Candidate) {
			if b, err := json.Marshal(c); err == nil {
				listener.OnHit(string(b))
			}
		}
	}
	return opts, nil
}

func reportPayload(r *scanner.Report) map[string]any {
	return map[string]any{
		"tested":      r.Tested,
		"hits":        r.Hits,
		"duration_ms": r.Duration.Milliseconds(),
		"candidates":  r.Candidates,
		"clean_count": len(r.Clean()),
	}
}

// BlockProfileJSON returns the built-in Cloudflare ranges with their measured
// cleanliness weights, so the app can explain why it prefers some blocks.
func BlockProfileJSON() string {
	type entry struct {
		CIDR   string  `json:"cidr"`
		Weight float64 `json:"weight"`
		Note   string  `json:"note"`
	}
	out := make([]entry, 0, len(cfranges.V4Blocks))
	for _, b := range cfranges.V4Blocks {
		out = append(out, entry{CIDR: b.CIDR, Weight: b.Weight, Note: b.Note})
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// CloudflareTLSPortsCSV lets the app populate its port chips without hardcoding
// the list on the Kotlin side.
func CloudflareTLSPortsCSV() string { return netports.CloudflareTLSCSV() }
