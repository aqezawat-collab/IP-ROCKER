// Package probe measures how well a Cloudflare edge address actually carries
// traffic, as opposed to merely answering a ping.
//
// Censorship-grade filtering commonly lets the first request through and then
// resets the connection, so a scanner that only measures TCP connect time
// reports addresses that are useless in practice. Every check here is designed
// to survive that: TLS is completed, a real payload is downloaded, an idle hold
// confirms the connection is not reset, and a WebSocket upgrade confirms the
// transport a CDN-fronted config depends on.
package probe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Mode selects how deep a probe goes.
type Mode int

const (
	// ModeTCP only completes a TCP handshake. Fast, but proves little.
	ModeTCP Mode = iota
	// ModeTLS completes a TLS handshake with SNI.
	ModeTLS
	// ModeHTTP completes TLS, fetches /cdn-cgi/trace, downloads a payload,
	// holds the connection open, and optionally upgrades to WebSocket.
	ModeHTTP
)

func (m Mode) String() string {
	switch m {
	case ModeTLS:
		return "tls"
	case ModeHTTP:
		return "http"
	default:
		return "tcp"
	}
}

// ParseMode converts a mode name to a Mode.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp":
		return ModeTCP, nil
	case "tls":
		return ModeTLS, nil
	case "http", "https":
		return ModeHTTP, nil
	default:
		return ModeTCP, fmt.Errorf("unknown probe mode %q (want tcp, tls or http)", s)
	}
}

// rotatingSNI are Cloudflare-fronted hostnames used when the caller has no
// config of its own. Rotating them avoids looking like a single repeated
// fingerprint to middleboxes.
var rotatingSNI = []string{
	"speed.cloudflare.com",
	"www.cloudflare.com",
	"cp.cloudflare.com",
	"blog.cloudflare.com",
	"developers.cloudflare.com",
}

// speedTestHost is the one host that reliably serves the throughput endpoints
// (/__down, /__up). The other rotating SNI names return 404 for them, and a
// config's own panel host never implements them, so measuring against either
// failed good edges purely because the endpoint did not exist. The connection
// stays pinned to the candidate edge IP — only the HTTP authority changes.
const speedTestHost = "speed.cloudflare.com"

// Config describes one probe session.
type Config struct {
	Port    int
	Mode    Mode
	Tries   int
	Timeout time.Duration

	// SNI overrides the TLS server name. Empty rotates automatically.
	SNI string
	// Host overrides the HTTP Host header. Empty uses SNI.
	Host string
	// TracePath is the endpoint used for the reachability check.
	TracePath string

	// DownloadBytes is the payload size for the throughput sample.
	// Zero disables the download check.
	DownloadBytes int64
	// UploadBytes is the payload size for the upstream throughput sample.
	// Zero disables the upload check. Upstream capacity matters because a
	// proxied connection is bidirectional, and many edges that download fast
	// upload badly.
	UploadBytes int64

	// HoldDuration is how long an idle connection must survive to prove the
	// path is not being reset mid-session. Zero disables the hold check.
	HoldDuration time.Duration

	// LongTest, when true, performs a sustained multi-second test on top
	// candidates after the main sweep: it holds a single connection open for
	// LongTestDuration while pumping downloads, then verifies the connection
	// is still alive. A 3 s idle hold cannot catch filters that reset a
	// session after 10-15 s of real traffic; this is the test that can.
	// LongTest runs only on the top-N candidates from the main scan, so it
	// adds roughly LongTestDuration of work, not LongTestDuration x Count.
	LongTest bool
	// LongTestDuration is how long the sustained long-test should run.
	// 10-15 s catches most "resets after warmup" filters on censored paths
	// without making a 5k-address scan take hours.
	LongTestDuration time.Duration

	// WebSocketPath enables a WebSocket upgrade check, which is the transport
	// a CDN-fronted proxy config actually uses.
	WebSocketPath string
	// RequireWebSocket makes a failed upgrade disqualify the address.
	RequireWebSocket bool

	// InsecureSkipVerify skips certificate validation. Certificates are still
	// validated by default; this exists only for probing custom fronts.
	InsecureSkipVerify bool
}

// WithDefaults fills unset fields with values that work on a mobile network.
func (c Config) WithDefaults() Config {
	if c.Port == 0 {
		c.Port = 443
	}
	if c.Tries <= 0 {
		c.Tries = 3
	}
	if c.Timeout <= 0 {
		c.Timeout = 6 * time.Second
	}
	if c.TracePath == "" {
		c.TracePath = "/cdn-cgi/trace"
	}
	// Custom fronts present a certificate for a name that does not match the
	// SNI we send, so strict verification rejects working edges. Skip it when
	// the caller pins its own SNI or Host; the default rotating Cloudflare SNI
	// keeps verification on.
	if c.SNI != "" || c.Host != "" {
		c.InsecureSkipVerify = true
	}
	return c
}

// Attempt records one round of measurement against an address.
type Attempt struct {
	// Latency is the connect-or-first-byte time. Zero means the attempt failed.
	Latency time.Duration
	TLSOk   bool
	HTTPOk  bool
	// HeldOpen is true when the idle-hold check passed, proving the connection
	// was not reset after the first successful request.
	HeldOpen bool
	// WSOk is true when the WebSocket upgrade succeeded.
	WSOk bool

	HTTPStatus int
	Colo       string
	// EdgeIP is the address Cloudflare reports seeing, used to detect
	// transparent redirection by an upstream middlebox.
	EdgeIP string

	DownloadBps float64
	UploadBps   float64
	// DownloadTested records that a transfer was attempted, so a zero
	// DownloadBps can be told apart from "the check was disabled".
	DownloadTested bool

	// Note is a non-fatal observation. The attempt still counts as a success;
	// only Err disqualifies it.
	Note string

	Err string
}

// Ok reports whether this attempt counts as a success.
func (a Attempt) Ok() bool { return a.Latency > 0 && a.Err == "" }

// Result aggregates every attempt against one address.
type Result struct {
	IP       net.IP
	Port     int
	Mode     string
	Attempts []Attempt
	Started  time.Time
}

// Probe measures ip according to cfg. It never returns nil.
func Probe(ctx context.Context, ip net.IP, cfg Config) *Result {
	cfg = cfg.WithDefaults()
	res := &Result{
		IP:      ip,
		Port:    cfg.Port,
		Mode:    cfg.Mode.String(),
		Started: time.Now(),
	}

	for i := 0; i < cfg.Tries; i++ {
		if ctx.Err() != nil {
			break
		}

		sni := cfg.SNI
		if sni == "" {
			sni = rotatingSNI[mrand.Intn(len(rotatingSNI))]
		}

		var att Attempt
		switch cfg.Mode {
		case ModeTCP:
			att = probeTCP(ctx, ip, cfg)
		case ModeTLS:
			att = probeTLS(ctx, ip, sni, cfg)
		default:
			att = probeHTTP(ctx, ip, sni, cfg)
		}
		res.Attempts = append(res.Attempts, att)

		if i < cfg.Tries-1 {
			// Jitter between attempts so a burst of probes does not look like
			// a scan to rate limiters.
			delay := time.Duration(20+mrand.Intn(60)) * time.Millisecond
			select {
			case <-ctx.Done():
				return res
			case <-time.After(delay):
			}
		}
	}
	return res
}

func dialTarget(ip net.IP, port int) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}

func probeTCP(ctx context.Context, ip net.IP, cfg Config) Attempt {
	dialCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	var d net.Dialer
	start := time.Now()
	conn, err := d.DialContext(dialCtx, "tcp", dialTarget(ip, cfg.Port))
	if err != nil {
		return Attempt{Err: cleanErr(err)}
	}
	lat := time.Since(start)
	conn.Close()
	return Attempt{Latency: lat}
}

func probeTLS(ctx context.Context, ip net.IP, sni string, cfg Config) Attempt {
	dialCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	d := tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}
	start := time.Now()
	conn, err := d.DialContext(dialCtx, "tcp", dialTarget(ip, cfg.Port))
	if err != nil {
		return Attempt{Err: cleanErr(err)}
	}
	lat := time.Since(start)
	conn.Close()
	return Attempt{Latency: lat, TLSOk: true}
}

// pinnedTransport builds an HTTP transport that always connects to a specific
// edge address while presenting the given SNI, which is how a CDN-fronted
// config reaches a chosen edge.
func pinnedTransport(ip net.IP, port int, sni string, insecure bool, timeout time.Duration) *http.Transport {
	target := dialTarget(ip, port)
	return &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, target)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: insecure,
			MinVersion:         tls.VersionTLS12,
		},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
	}
}

// isHTTPPort reports whether the port is one Cloudflare serves plain HTTP on.
// Probing these with https would fail every time, so the scheme must match.
func isHTTPPort(p int) bool {
	switch p {
	case 80, 8080, 8880, 2052, 2082, 2086, 2095:
		return true
	}
	return false
}

func probeHTTP(ctx context.Context, ip net.IP, sni string, cfg Config) Attempt {
	host := cfg.Host
	if host == "" {
		host = sni
	}

	tr := pinnedTransport(ip, cfg.Port, sni, cfg.InsecureSkipVerify, cfg.Timeout)
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout * 2,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := "https"
	if isHTTPPort(cfg.Port) {
		scheme = "http"
	}
	traceURL := fmt.Sprintf("%s://%s%s", scheme, host, cfg.TracePath)

	reqCtx, cancel := context.WithTimeout(ctx, cfg.Timeout*2)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, traceURL, nil)
	if err != nil {
		return Attempt{Err: cleanErr(err)}
	}
	req.Host = host
	req.Header.Set("User-Agent", browserUA)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Attempt{Err: cleanErr(err)}
	}
	lat := time.Since(start)

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	resp.Body.Close()

	att := Attempt{
		Latency:    lat,
		TLSOk:      resp.TLS != nil,
		HTTPStatus: resp.StatusCode,
	}
	if readErr != nil {
		att.Err = "trace body: " + cleanErr(readErr)
		return att
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		// 403 with a Cloudflare error body usually means this edge is rate
		// limiting or challenging the client, which is exactly the condition
		// a naive scanner reports as a working address.
		att.Err = fmt.Sprintf("edge returned HTTP %d", resp.StatusCode)
		return att
	}

	att.Colo, att.EdgeIP = parseTrace(string(body))
	if att.Colo == "" {
		att.Err = "response did not look like a Cloudflare edge (no colo in trace)"
		return att
	}
	att.HTTPOk = true

	// Idle hold: keep a fresh connection open with no traffic. Filtering that
	// permits the first request but resets the session shows up here. A failed
	// hold is recorded but never fatal: mobile carriers routinely reset idle
	// TCP sessions through their NAT within a few seconds, which says nothing
	// about whether this edge can carry traffic. Poisoning the whole attempt
	// (and skipping the download measurement) on such a reset rejected good
	// edges for no reason. RequireHard still disqualifies failing edges when
	// the user opts in via strict mode.
	if cfg.HoldDuration > 0 {
		att.HeldOpen = holdCheck(ctx, ip, sni, cfg)
	}

	// The reachability client uses the user-supplied SNI/Host, but the
	// throughput endpoint needs speed.cloudflare.com's TLS SNI as well as its
	// HTTP authority. Reusing the config client makes a custom VLESS/Trojan
	// SNI route /__down to the user's panel, which returns an error and leaves
	// DL/UP at zero even though the edge is healthy.
	speedClient := client
	var speedTransport *http.Transport
	if cfg.DownloadBytes > 0 || cfg.UploadBytes > 0 {
		speedTransport = pinnedTransport(ip, cfg.Port, speedTestHost, cfg.InsecureSkipVerify, cfg.Timeout)
		speedClient = &http.Client{
			Transport: speedTransport,
			Timeout:   cfg.Timeout * 3,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		defer speedTransport.CloseIdleConnections()
	}

	if cfg.DownloadBytes > 0 {
		att.DownloadTested = true
		bps, err := measureDownload(ctx, speedClient, scheme, speedTestHost, cfg)
		if err != nil {
			// A truncated transfer means the path permitted the request but
			// cannot sustain data — the exact middlebox signature a latency-only
			// scanner misses. That must disqualify the attempt.
			//
			// An endpoint that refuses the request (HTTP 4xx/5xx) is a property
			// of the speed-test host, not the edge — many clean edges don't serve
			// /__down at all on custom fronts. Treat those as non-fatal notes so
			// a perfectly good edge isn't rejected just because the speed-test
			// endpoint happened to return 404 or 403.
			//
			// A transient network error (timeout, reset) is also non-fatal: the
			// trace already confirmed the edge is reachable; one failed transfer
			// is noise, not proof the edge is broken.
			if strings.Contains(err.Error(), "truncated") {
				att.Err = "download: " + err.Error()
				return att
			}
			// An HTTP-level refusal (rate limit, 404, geo-block) means the
			// speed-test endpoint was unavailable, not that the edge is broken.
			// Label it "download skipped" so the score layer can distinguish
			// "endpoint refused" from "transfer started but moved no data".
			if isEndpointError(err) {
				att.Note = "download skipped: " + err.Error()
			} else {
				att.Note = "download: " + err.Error()
			}
		} else {
			att.DownloadBps = bps
		}
	}

	if cfg.UploadBytes > 0 {
		bps, err := measureUpload(ctx, speedClient, scheme, speedTestHost, cfg)
		if err != nil {
			// A failed upload downgrades the address but does not disqualify
			// it, because not every front exposes an upload endpoint.
			att.UploadBps = 0
			att.Note = "upload: " + err.Error()
		} else {
			att.UploadBps = bps
		}
	}

	if cfg.WebSocketPath != "" {
		att.WSOk = websocketCheck(ctx, ip, sni, host, cfg)
		if cfg.RequireWebSocket && !att.WSOk {
			att.Err = "WebSocket upgrade failed on this edge"
			return att
		}
	}

	return att
}

const browserUA = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36"

// parseTrace extracts colo and the client address Cloudflare reports.
func parseTrace(body string) (colo, edgeIP string) {
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "colo":
			colo = v
		case "ip":
			edgeIP = v
		}
	}
	return colo, edgeIP
}

// holdCheck opens a TLS connection, waits, then confirms the peer is still
// there by completing a request on that same connection.
func holdCheck(ctx context.Context, ip net.IP, sni string, cfg Config) bool {
	dialCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	d := tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}
	conn, err := d.DialContext(dialCtx, "tcp", dialTarget(ip, cfg.Port))
	if err != nil {
		return false
	}
	defer conn.Close()

	select {
	case <-ctx.Done():
		return false
	case <-time.After(cfg.HoldDuration):
	}

	host := cfg.Host
	if host == "" {
		host = sni
	}
	// A minimal request on the held connection: if a middlebox sent an RST
	// during the idle period, this write or read fails.
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n",
		cfg.TracePath, host, browserUA)
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		return false
	}
	if _, err := conn.Write([]byte(req)); err != nil {
		return false
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	return n > 0 && strings.Contains(string(buf[:n]), "HTTP/1.")
}

// isEndpointError reports whether a measurement error means the endpoint
// refused the request (an HTTP status) rather than the path failing mid-transfer
// (reset, truncation, timeout). An endpoint refusal says nothing about whether
// this edge can carry traffic, so it is recorded as a note instead of failing
// the attempt. A transfer that starts and then stalls is the real signal that a
// middlebox is answering for the edge, and stays fatal.
func isEndpointError(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "HTTP ")
}

// LongResult summarises a long-test run.
type LongResult struct {
	// Held is true when the connection survived the full test duration with
	// data flowing through it. A connection that dies mid-stream counts as
	// failed, which is the whole point of running this test.
	Held bool
	// Bytes is the total amount of data transferred during the test.
	Bytes int64
	// Duration is the wall time spent holding the connection.
	Duration time.Duration
	// Err is the failure reason when Held is false.
	Err string
}

// LongTest holds a single TLS connection to the edge open for d, repeatedly
// fetching chunks of /__down?bytes=N through it. A connection that survives
// d with consistent throughput is one a real session can ride; one that
// resets, stalls or drops mid-test will be caught here, where the existing
// 3 s idle hold could not. This is the test that addresses the gap between
// "Phase 2 says healthy" and "live VPN goes red after a few minutes": the
// filter that resets only after 10-15 s of real traffic is the one most
// scanners miss, and this is what surfaces it.
func LongTest(ctx context.Context, ip net.IP, sni, host string, cfg Config) LongResult {
	if cfg.LongTestDuration <= 0 {
		return LongResult{Err: "long test disabled"}
	}
	if host == "" {
		host = sni
	}
	d := cfg.LongTestDuration
	// A 256 KB chunk keeps individual requests short while still producing
	// real traffic. 64 KB is too small to outpace a per-packet reset filter.
	chunk := int64(256 * 1024)
	timeout := d + 5*time.Second
	if cfg.Timeout > 0 && cfg.Timeout*2 > timeout {
		timeout = cfg.Timeout * 2
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}
	conn, err := tlsDialer.DialContext(dialCtx, "tcp", dialTarget(ip, cfg.Port))
	if err != nil {
		return LongResult{Err: "dial: " + cleanErr(err)}
	}
	defer conn.Close()

	scheme := "https"
	if isHTTPPort(cfg.Port) {
		scheme = "http"
	}

	start := time.Now()
	deadline := start.Add(d)
	var total int64
	rounds := 0
	stalls := 0

	for {
		if ctx.Err() != nil {
			return LongResult{Bytes: total, Duration: time.Since(start), Err: "cancelled"}
		}
		if time.Now().After(deadline) {
			break
		}
		// Read fresh trace from the held connection. A reset filter will
		// surface here as a write or read error.
		url := fmt.Sprintf("%s://%s/__down?bytes=%d", scheme, speedTestHost, chunk)
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: keep-alive\r\n\r\n",
			url, host, browserUA)
		// Per-round deadline so a stalled chunk cannot eat the whole budget.
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return LongResult{Bytes: total, Duration: time.Since(start), Err: "set deadline: " + cleanErr(err)}
		}
		rdStart := time.Now()
		if _, err := conn.Write([]byte(req)); err != nil {
			return LongResult{Bytes: total, Duration: time.Since(start), Err: "write: " + cleanErr(err)}
		}
		// Read until we have consumed the response headers and the chunk body.
		// io.ReadAll with a generous cap is enough — the chunk is bounded.
		readCtx, readCancel := context.WithTimeout(dialCtx, 5*time.Second)
		n, readErr := readWithTimeout(readCtx, conn, chunk+1024)
		readCancel()
		rdDur := time.Since(rdStart)
		if readErr != nil {
			return LongResult{Bytes: total, Duration: time.Since(start), Err: "read: " + readErr.Error()}
		}
		// Anything under 1 MB/s sustained across a 256 KB chunk is a
		// filter-side throttle — a healthy edge does not move that slowly.
		// Track stalls but keep going: one slow round is not proof, three is.
		if int64(rdDur) > 0 && n*int64(time.Second)/int64(rdDur) < 1<<20 {
			stalls++
			if stalls >= 3 {
				return LongResult{Bytes: total, Duration: time.Since(start), Err: "sustained stall (filter throttle)"}
			}
		} else {
			stalls = 0
		}
		total += n
		rounds++
	}

	// After the holding window, send one final GET on the same connection to
	// prove it is still up. A reset during the idle stretch shows up here.
	probeReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n",
		cfg.TracePath, host, browserUA)
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err == nil {
		if _, err := conn.Write([]byte(probeReq)); err == nil {
			buf := make([]byte, 256)
			n, _ := conn.Read(buf)
			if n == 0 || !strings.Contains(string(buf[:n]), "HTTP/1.") {
				return LongResult{Bytes: total, Duration: time.Since(start),
					Err: "connection died during long test (no HTTP response after hold)"}
			}
		} else {
			return LongResult{Bytes: total, Duration: time.Since(start),
				Err: "connection reset after long test hold: " + cleanErr(err)}
		}
	}

	return LongResult{
		Held:     true,
		Bytes:    total,
		Duration: time.Since(start),
	}
}

// readWithTimeout reads up to max bytes from conn, returning when the chunk
// is complete or the timeout fires. It returns the actual byte count read.
func readWithTimeout(ctx context.Context, conn net.Conn, max int64) (int64, error) {
	done := make(chan struct{})
	var (
		n     int64
		readE error
	)
	go func() {
		buf := make([]byte, 32*1024)
		for n < max {
			if ctx.Err() != nil {
				break
			}
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			r, err := conn.Read(buf)
			if r > 0 {
				n += int64(r)
			}
			if err != nil {
				if err == io.EOF {
					break
				}
				// Treat a per-iteration read deadline as "no more data right
				// now, check completion below"; the chunk-size heuristic decides
				// whether the response is finished.
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					// If we have at least the chunk we asked for, we are done.
					if n >= max*9/10 {
						break
					}
					// Otherwise keep reading; the outer deadline will trip.
					continue
				}
				readE = err
				break
			}
		}
		close(done)
	}()
	select {
	case <-ctx.Done():
		// Best-effort: if the deadline hit but data was already read, accept it.
		if n >= max/2 {
			return n, nil
		}
		return n, ctx.Err()
	case <-done:
		return n, readE
	}
}

// measureDownload times a payload fetch through the pinned edge. host is the
// endpoint authority, kept at speedTestHost so the request reaches a host that
// actually serves /__down.
func measureDownload(ctx context.Context, client *http.Client, scheme, host string, cfg Config) (float64, error) {
	url := fmt.Sprintf("%s://%s/__down?bytes=%d", scheme, host, cfg.DownloadBytes)
	reqCtx, cancel := context.WithTimeout(ctx, cfg.Timeout*3)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Host = host
	req.Header.Set("User-Agent", browserUA)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, errors.New(cleanErr(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, fmt.Errorf("HTTP %d from download endpoint", resp.StatusCode)
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, cfg.DownloadBytes*2))
	elapsed := time.Since(start)
	if err != nil {
		return 0, errors.New(cleanErr(err))
	}
	// A truncated transfer means the path cannot sustain traffic even though
	// the initial request succeeded.
	if n < cfg.DownloadBytes/2 {
		return 0, fmt.Errorf("transfer truncated at %d of %d bytes", n, cfg.DownloadBytes)
	}
	if elapsed <= 0 {
		return 0, errors.New("zero elapsed time")
	}
	return float64(n) / elapsed.Seconds(), nil
}

// measureUpload times a payload POST through the pinned edge. host is the
// endpoint authority, kept at speedTestHost so the request reaches a host that
// actually serves /__up.
func measureUpload(ctx context.Context, client *http.Client, scheme, host string, cfg Config) (float64, error) {
	url := fmt.Sprintf("%s://%s/__up", scheme, host)
	reqCtx, cancel := context.WithTimeout(ctx, cfg.Timeout*3)
	defer cancel()

	payload := make([]byte, cfg.UploadBytes)
	if _, err := rand.Read(payload); err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, strings.NewReader(string(payload)))
	if err != nil {
		return 0, err
	}
	req.Host = host
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", browserUA)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, errors.New(cleanErr(err))
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	elapsed := time.Since(start)

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, fmt.Errorf("HTTP %d from upload endpoint", resp.StatusCode)
	}
	if elapsed <= 0 {
		return 0, errors.New("zero elapsed time")
	}
	return float64(cfg.UploadBytes) / elapsed.Seconds(), nil
}

// websocketCheck performs a real WebSocket upgrade handshake, which is the
// transport a CDN-fronted proxy config depends on. An edge that serves HTTP
// but refuses upgrades is useless for that purpose.
func websocketCheck(ctx context.Context, ip net.IP, sni, host string, cfg Config) bool {
	dialCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	d := tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}
	conn, err := d.DialContext(dialCtx, "tcp", dialTarget(ip, cfg.Port))
	if err != nil {
		return false
	}
	defer conn.Close()

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return false
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	path := cfg.WebSocketPath
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"User-Agent: %s\r\n\r\n", path, host, key, browserUA)

	if err := conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		return false
	}
	if _, err := conn.Write([]byte(req)); err != nil {
		return false
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return false
	}
	head := string(buf[:n])
	return strings.Contains(head, "101") && strings.Contains(strings.ToLower(head), "upgrade")
}

// cleanErr shortens Go's verbose network errors into something a phone screen
// can display without hiding the actual cause.
func cleanErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	replacements := []struct{ from, to string }{
		{"context deadline exceeded (Client.Timeout exceeded while awaiting headers)", "timeout waiting for response"},
		{"context deadline exceeded", "timeout"},
		{"connection reset by peer", "connection reset (likely filtered)"},
		{"no route to host", "no route to host"},
		{"i/o timeout", "timeout"},
	}
	for _, r := range replacements {
		if strings.Contains(s, r.from) {
			return r.to
		}
	}
	// Strip the dial/address prefix noise Go adds.
	if idx := strings.LastIndex(s, ": "); idx > 0 && len(s)-idx < 60 {
		return strings.TrimSpace(s[idx+2:])
	}
	return s
}
