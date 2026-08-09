package probe

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newEdge starts a local TLS server that imitates a Cloudflare edge: it serves
// /cdn-cgi/trace, a sized download endpoint, an upload sink, and a WebSocket
// upgrade. Handlers can be disabled to simulate a broken edge.
type edgeOptions struct {
	traceBody   string
	traceStatus int
	// downloadShort truncates the payload, imitating an edge that answers the
	// first request but cannot actually carry traffic.
	downloadShort bool
	// downloadStatus makes /__down return this status, imitating an endpoint
	// that refuses the request (rate limit, challenge) while the edge is fine.
	downloadStatus int
	refuseWS       bool
	// captureHost, when non-nil, receives the Host header of the download
	// request, proving the throughput probe targets speed.cloudflare.com.
	captureHost *string
}

func newEdge(t *testing.T, opts edgeOptions) (*httptest.Server, net.IP, int) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/cdn-cgi/trace", func(w http.ResponseWriter, r *http.Request) {
		if opts.traceStatus != 0 && opts.traceStatus != 200 {
			w.WriteHeader(opts.traceStatus)
			w.Write([]byte("error"))
			return
		}
		body := opts.traceBody
		if body == "" {
			body = "fl=123abc\nh=test\nip=203.0.113.7\ncolo=FRA\nloc=DE\ntls=TLSv1.3\n"
		}
		w.Write([]byte(body))
	})
	mux.HandleFunc("/__down", func(w http.ResponseWriter, r *http.Request) {
		if opts.captureHost != nil {
			*opts.captureHost = r.Host
		}
		if opts.downloadStatus != 0 {
			w.WriteHeader(opts.downloadStatus)
			return
		}
		want, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
		if want <= 0 {
			want = 1024
		}
		if opts.downloadShort {
			want = want / 10
		}
		w.Write(make([]byte, want))
	})
	mux.HandleFunc("/__up", func(w http.ResponseWriter, r *http.Request) {
		io := make([]byte, 4096)
		for {
			if _, err := r.Body.Read(io); err != nil {
				break
			}
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if opts.refuseWS || r.Header.Get("Upgrade") != "websocket" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		buf.Flush()
		time.Sleep(100 * time.Millisecond)
	})

	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	u := srv.Listener.Addr().(*net.TCPAddr)
	return srv, u.IP, u.Port
}

func baseConfig(port int) Config {
	return Config{
		Port:               port,
		Mode:               ModeHTTP,
		Tries:              2,
		Timeout:            4 * time.Second,
		SNI:                "127.0.0.1",
		Host:               "127.0.0.1",
		InsecureSkipVerify: true,
	}.WithDefaults()
}

func TestProbeHTTPSuccess(t *testing.T) {
	_, ip, port := newEdge(t, edgeOptions{})

	cfg := baseConfig(port)
	cfg.DownloadBytes = 64 * 1024
	cfg.HoldDuration = 200 * time.Millisecond
	cfg.WebSocketPath = "/ws"

	res := Probe(context.Background(), ip, cfg)
	if len(res.Attempts) != 2 {
		t.Fatalf("got %d attempts, want 2", len(res.Attempts))
	}
	a := res.Attempts[0]
	if !a.Ok() {
		t.Fatalf("attempt failed: %s", a.Err)
	}
	if a.Colo != "FRA" {
		t.Errorf("Colo = %q, want FRA", a.Colo)
	}
	if a.EdgeIP != "203.0.113.7" {
		t.Errorf("EdgeIP = %q, want 203.0.113.7", a.EdgeIP)
	}
	if !a.TLSOk || !a.HTTPOk {
		t.Errorf("TLSOk = %v, HTTPOk = %v; both should be true", a.TLSOk, a.HTTPOk)
	}
	if !a.HeldOpen {
		t.Error("HeldOpen = false; a healthy server should survive the idle hold")
	}
	if a.DownloadBps <= 0 {
		t.Error("DownloadBps = 0; the download sample should have been measured")
	}
	if !a.WSOk {
		t.Error("WSOk = false; the server accepted the upgrade")
	}
}

// An edge that returns 403 is rate limiting or challenging the client. A naive
// scanner reports it as working, so this must be treated as a failure.
func TestProbeRejectsErrorStatus(t *testing.T) {
	_, ip, port := newEdge(t, edgeOptions{traceStatus: 403})

	res := Probe(context.Background(), ip, baseConfig(port))
	for _, a := range res.Attempts {
		if a.Ok() {
			t.Fatal("an edge returning HTTP 403 was accepted")
		}
		if !strings.Contains(a.Err, "403") {
			t.Errorf("error should mention the status code, got %q", a.Err)
		}
	}
}

// A response without a colo line is not a Cloudflare edge, which usually means
// a middlebox answered on its behalf.
func TestProbeRejectsNonCloudflareResponse(t *testing.T) {
	_, ip, port := newEdge(t, edgeOptions{traceBody: "hello world\n"})

	res := Probe(context.Background(), ip, baseConfig(port))
	for _, a := range res.Attempts {
		if a.Ok() {
			t.Fatal("a response with no colo was accepted as a Cloudflare edge")
		}
		if !strings.Contains(a.Err, "colo") {
			t.Errorf("error should explain the missing colo, got %q", a.Err)
		}
	}
}

// A truncated transfer is the signature of a path that permits the request but
// cannot sustain data, which is exactly what a latency-only scanner misses.
func TestProbeRejectsTruncatedDownload(t *testing.T) {
	_, ip, port := newEdge(t, edgeOptions{downloadShort: true})

	cfg := baseConfig(port)
	cfg.DownloadBytes = 128 * 1024

	res := Probe(context.Background(), ip, cfg)
	for _, a := range res.Attempts {
		if a.Ok() {
			t.Fatal("a truncated download was accepted")
		}
		if !strings.Contains(a.Err, "truncated") {
			t.Errorf("error should mention truncation, got %q", a.Err)
		}
	}
}

func TestProbeRequireWebSocketDisqualifies(t *testing.T) {
	_, ip, port := newEdge(t, edgeOptions{refuseWS: true})

	cfg := baseConfig(port)
	cfg.WebSocketPath = "/ws"
	cfg.RequireWebSocket = true

	res := Probe(context.Background(), ip, cfg)
	for _, a := range res.Attempts {
		if a.Ok() {
			t.Fatal("an edge refusing the WebSocket upgrade was accepted")
		}
		if !strings.Contains(a.Err, "WebSocket") {
			t.Errorf("error should mention WebSocket, got %q", a.Err)
		}
	}
}

// A closed port must fail fast rather than being reported with a latency.
func TestProbeUnreachableAddress(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	cfg := baseConfig(port)
	cfg.Timeout = time.Second
	res := Probe(context.Background(), net.ParseIP("127.0.0.1"), cfg)
	for _, a := range res.Attempts {
		if a.Ok() {
			t.Fatal("a closed port produced a successful attempt")
		}
	}
}

func TestProbeTCPAndTLSModes(t *testing.T) {
	_, ip, port := newEdge(t, edgeOptions{})

	tcpCfg := baseConfig(port)
	tcpCfg.Mode = ModeTCP
	if a := Probe(context.Background(), ip, tcpCfg).Attempts[0]; !a.Ok() {
		t.Errorf("TCP probe failed: %s", a.Err)
	}

	tlsCfg := baseConfig(port)
	tlsCfg.Mode = ModeTLS
	a := Probe(context.Background(), ip, tlsCfg).Attempts[0]
	if !a.Ok() || !a.TLSOk {
		t.Errorf("TLS probe failed: ok=%v tlsOk=%v err=%s", a.Ok(), a.TLSOk, a.Err)
	}
}

// Certificate validation must be on unless explicitly disabled, so a scan
// cannot be silently satisfied by a middlebox presenting its own certificate.
// The custom-front convenience that auto-skips verification only kicks in when
// SNI or Host is pinned; on the default rotating-SNI path it stays on.
func TestCertificateValidationIsOnByDefault(t *testing.T) {
	_, ip, port := newEdge(t, edgeOptions{})

	cfg := Config{Port: port, Mode: ModeTLS, Tries: 2, Timeout: 4 * time.Second}.WithDefaults()
	if cfg.InsecureSkipVerify {
		t.Fatal("default path auto-enabled skip-verify without a custom front")
	}

	for _, a := range Probe(context.Background(), ip, cfg).Attempts {
		if a.Ok() {
			t.Fatal("an untrusted certificate was accepted while verification was enabled")
		}
	}
}

func TestParseTrace(t *testing.T) {
	body := "fl=123\nh=speed.cloudflare.com\nip=1.2.3.4\nts=1\ncolo=AMS\nloc=NL\n"
	colo, ip := parseTrace(body)
	if colo != "AMS" {
		t.Errorf("colo = %q, want AMS", colo)
	}
	if ip != "1.2.3.4" {
		t.Errorf("ip = %q, want 1.2.3.4", ip)
	}
}

func TestParseModeRejectsGarbage(t *testing.T) {
	if _, err := ParseMode("quic"); err == nil {
		t.Error("expected an error for an unknown mode")
	}
	for _, name := range []string{"tcp", "TLS", "http", "https"} {
		if _, err := ParseMode(name); err != nil {
			t.Errorf("ParseMode(%q) failed: %v", name, err)
		}
	}
}

func TestContextCancellationStopsProbe(t *testing.T) {
	_, ip, port := newEdge(t, edgeOptions{})
	cfg := baseConfig(port)
	cfg.Tries = 5

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := Probe(ctx, ip, cfg)
	if len(res.Attempts) > 1 {
		t.Errorf("got %d attempts after cancellation, want at most 1", len(res.Attempts))
	}
}

// The throughput probes must target speed.cloudflare.com rather than the SNI:
// the rotating SNI names and a config's own panel host do not serve /__down, so
// measuring against them failed every good edge even though it carried traffic.
func TestDownloadTargetsSpeedHost(t *testing.T) {
	var got string
	_, ip, port := newEdge(t, edgeOptions{captureHost: &got})

	cfg := baseConfig(port)
	cfg.DownloadBytes = 64 * 1024
	cfg.Host = "panel.example.com" // a config link would pin this

	a := Probe(context.Background(), ip, cfg).Attempts[0]
	if !a.Ok() {
		t.Fatalf("attempt failed: %s", a.Err)
	}
	if got != speedTestHost {
		t.Fatalf("download Host = %q, want %q", got, speedTestHost)
	}
}

// A rate-limited or challenged /__down is a property of the host, not proof
// that the edge cannot carry traffic. It must downgrade the attempt to a note
// instead of turning a good address red.
func TestDownloadEndpointErrorIsNonFatal(t *testing.T) {
	_, ip, port := newEdge(t, edgeOptions{downloadStatus: 429})

	cfg := baseConfig(port)
	cfg.DownloadBytes = 64 * 1024

	a := Probe(context.Background(), ip, cfg).Attempts[0]
	if !a.Ok() {
		t.Fatalf("a rate-limited speed endpoint disqualified a good edge: %s", a.Err)
	}
	if !a.DownloadTested {
		t.Fatal("download was not marked tested")
	}
	if !strings.Contains(a.Note, "429") {
		t.Errorf("note should mention the status, got %q", a.Note)
	}
}

var _ = tls.VersionTLS12
