// Command iprocker hunts for clean, fast Cloudflare edge addresses.
//
// It is the reference client for the scanner core that the Android app also
// uses, and doubles as the way to verify the engine outside a phone.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Qezawat/IP-ROCKER/internal/cfranges"
	"github.com/Qezawat/IP-ROCKER/internal/netports"
	"github.com/Qezawat/IP-ROCKER/internal/probe"
	"github.com/Qezawat/IP-ROCKER/internal/scanner"
	"github.com/Qezawat/IP-ROCKER/internal/score"
	"github.com/Qezawat/IP-ROCKER/internal/tui"
)

var version = "dev"

func main() {
	var (
		count       = flag.Int("count", 400, "how many addresses to probe in the first pass")
		concurrency = flag.Int("concurrency", 64, "parallel probes")
		port        = flag.Int("port", 443, "edge port to probe")
		portsList   = flag.String("ports", "", "comma-separated ports to probe on every address, e.g. 443,2053,8443; 'all' uses every Cloudflare TLS port")
		minSpeed    = flag.Float64("min-speed", 0, "reject addresses slower than this many KB/s; 0 disables")
		modeName    = flag.String("mode", "http", "probe depth: tcp, tls or http")
		tries       = flag.Int("tries", 3, "attempts per address")
		timeout     = flag.Duration("timeout", 6*time.Second, "per-attempt timeout")
		hold        = flag.Duration("hold", 3*time.Second, "idle hold duration; 0 disables the reset check")
		download    = flag.Int64("download", 1024*1024, "download sample size in bytes; 0 disables")
		upload      = flag.Int64("upload", 0, "upload sample size in bytes; 0 disables")
		wsPath      = flag.String("ws-path", "", "WebSocket path to verify, e.g. /?ed=2560")
		requireWS   = flag.Bool("require-ws", false, "reject addresses that refuse a WebSocket upgrade")
		sni         = flag.String("sni", "", "TLS server name; empty rotates Cloudflare hostnames")
		host        = flag.String("host", "", "HTTP Host header; empty uses the SNI")
		strict      = flag.Bool("strict", false, "only accept addresses that are clean on every axis")
		noRep       = flag.Bool("no-reputation", false, "skip reputation lookups and run fully offline")
		extra       = flag.String("cidr", "", "comma-separated IPs/CIDRs to include (bare IPs become /32)")
		only        = flag.Bool("only-cidr", false, "scan only the CIDRs given by -cidr")
		top         = flag.Int("top", 20, "how many results to print")
		jsonOut     = flag.String("json", "", "write the full report to this file as JSON")
		txtOut      = flag.String("out", "", "write clean ip:port lines to this file")
		showVersion = flag.Bool("version", false, "print version and exit")
		quiet       = flag.Bool("quiet", false, "suppress progress output")
		ui          = flag.Bool("ui", false, "force the interactive terminal interface")
		noUI        = flag.Bool("no-ui", false, "force the plain flag-driven scan even on a terminal")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("iprocker", version)
		return
	}

	// With no flags on a real terminal, the interactive interface is what the
	// user wants: the flag surface below assumes they already know every knob
	// and its cost, which is exactly the friction that stops a scan happening.
	if *ui || (!*noUI && flag.NFlag() == 0 && flag.NArg() == 0 && isTerminal()) {
		if err := tui.Run(version); err != nil {
			fail(err)
		}
		return
	}

	mode, err := probe.ParseMode(*modeName)
	if err != nil {
		fail(err)
	}

	crit := score.DefaultCriteria()
	if *strict {
		crit = score.StrictCriteria()
	}
	if *requireWS {
		crit.RequireWebSocket = true
	}
	if *minSpeed > 0 {
		crit.MinDownloadKBps = *minSpeed
	}

	ports, err := netports.Parse(*portsList, *port)
	if err != nil {
		fail(err)
	}

	// -cidr takes IPs as well as CIDRs; a bare IP becomes a /32, so a pasted
	// address list scans instead of erroring.
	extraCIDRs, err := cfranges.ParseCustomList(*extra)
	if err != nil {
		fail(err)
	}

	opts := scanner.Options{
		Count:       *count,
		Concurrency: *concurrency,
		Ports:       ports,
		Probe: probe.Config{
			Port:             ports[0],
			Mode:             mode,
			Tries:            *tries,
			Timeout:          *timeout,
			SNI:              *sni,
			Host:             *host,
			HoldDuration:     *hold,
			DownloadBytes:    *download,
			UploadBytes:      *upload,
			WebSocketPath:    *wsPath,
			RequireWebSocket: *requireWS,
		},
		Criteria: crit,
		Ranges: cfranges.Options{
			IPv4:       true,
			ExtraCIDRs: extraCIDRs,
			OnlyExtra:  *only,
			SkipDirty:  true,
		},
		SkipReputation: *noRep,
	}

	if !*quiet {
		var lastPhase scanner.Phase = -1
		var lastPrint time.Time
		opts.Report = func(p scanner.Progress) {
			if p.Message != "" {
				fmt.Fprintf(os.Stderr, "\n! %s\n", p.Message)
				return
			}
			// Throttle redraws so a fast scan does not flood the terminal.
			if p.Phase == lastPhase && time.Since(lastPrint) < 250*time.Millisecond && p.Phase != scanner.PhaseDone {
				return
			}
			lastPhase, lastPrint = p.Phase, time.Now()
			fmt.Fprintf(os.Stderr, "\r%-22s tested %-6d hits %-4d in-flight %-3d",
				p.Phase, p.Tested, p.Hits, p.InFlight)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	s := scanner.New(opts)
	report, err := s.Run(ctx)
	if err != nil {
		fail(err)
	}
	if !*quiet {
		fmt.Fprintln(os.Stderr)
	}

	printReport(report, *top)

	if report.ReputationError != "" {
		fmt.Fprintf(os.Stderr, "\nReputation data incomplete: %s\n"+
			"Addresses above are ranked on measurement only and are not confirmed clean.\n",
			report.ReputationError)
	}

	if *jsonOut != "" {
		if err := writeJSON(*jsonOut, report); err != nil {
			fmt.Fprintf(os.Stderr, "writing JSON: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "\nFull report written to %s\n", *jsonOut)
		}
	}
	if *txtOut != "" {
		if err := writeList(*txtOut, report); err != nil {
			fmt.Fprintf(os.Stderr, "writing list: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Clean endpoints written to %s\n", *txtOut)
		}
	}
}

func printReport(r *scanner.Report, top int) {
	clean := r.Clean()
	fmt.Printf("\nProbed %d addresses in %s — %d answered, %d usable\n\n",
		r.Tested, r.Duration.Round(time.Millisecond), r.Hits, len(clean))

	if len(clean) == 0 {
		fmt.Println("No usable addresses. Best attempts and why they failed:")
		shown := 0
		for _, c := range r.Candidates {
			if shown >= top {
				break
			}
			reason := "no response"
			if len(c.Notes) > 0 {
				reason = c.Notes[0]
			}
			fmt.Printf("  %-16s %s\n", c.IP, reason)
			shown++
		}
		return
	}

	// The port column matters once several ports are probed: the same address
	// can appear more than once with different results per port.
	fmt.Printf("%-16s %-6s %-6s %-8s %-8s %-9s %-6s %-8s %s\n",
		"IP", "PORT", "SCORE", "LATENCY", "JITTER", "DOWNLOAD", "COLO", "RISK", "STATUS")
	fmt.Println(strings.Repeat("-", 95))

	for i, c := range clean {
		if i >= top {
			break
		}
		risk := "n/a"
		verdict := "⚪"
		if c.Reputation != nil && c.Reputation.Err == "" {
			risk = fmt.Sprintf("%.0f%%", c.Reputation.RiskPercent)
			verdict = c.Reputation.Verdict.Emoji()
		}
		dl := "-"
		if c.DownloadKBps > 0 {
			dl = fmt.Sprintf("%.0f KB/s", c.DownloadKBps)
		}
		flags := verdict
		if c.HeldOpen {
			flags += " stable"
		}
		if c.WSOk {
			flags += " ws"
		}
		fmt.Printf("%-16s %-6d %-6.1f %-8s %-8s %-9s %-6s %-8s %s\n",
			c.IP,
			c.Port,
			c.Total,
			fmt.Sprintf("%.0fms", c.AvgLatencyMs),
			fmt.Sprintf("%.0fms", c.JitterMs),
			dl,
			orDash(c.Colo),
			risk,
			flags,
		)
	}

	best := clean[0]
	fmt.Printf("\nBest: %s:%d — score %.1f", best.IP, best.Port, best.Total)
	if best.Reputation != nil && best.Reputation.Err == "" {
		fmt.Printf(", %s %s risk %.1f%%, %s %s",
			best.Reputation.Verdict.Emoji(),
			best.Reputation.Verdict,
			best.Reputation.RiskPercent,
			orDash(best.Reputation.Country),
			orDash(best.Reputation.City))
	}
	fmt.Println()
}

func writeJSON(path string, r *scanner.Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"tested":           r.Tested,
		"hits":             r.Hits,
		"duration_ms":      r.Duration.Milliseconds(),
		"reputation_error": r.ReputationError,
		"candidates":       r.Candidates,
	})
}

func writeList(path string, r *scanner.Report) error {
	var b strings.Builder
	for _, c := range r.Clean() {
		fmt.Fprintf(&b, "%s:%d\n", c.IP, c.Port)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "iprocker: %v\n", err)
	os.Exit(1)
}

// isTerminal reports whether stdout is an interactive terminal. Piped or
// redirected output must stay plain text so `iprocker > file` and CI keep
// working unchanged.
func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
