// Package scanner orchestrates a full hunt: generate candidates, probe them,
// expand around hits, rate the survivors, and rank the result.
package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Qezawat/IP-ROCKER/internal/cfranges"
	"github.com/Qezawat/IP-ROCKER/internal/netports"
	"github.com/Qezawat/IP-ROCKER/internal/probe"
	"github.com/Qezawat/IP-ROCKER/internal/reputation"
	"github.com/Qezawat/IP-ROCKER/internal/score"
)

// Phase identifies which stage of the hunt is running, for progress reporting.
type Phase int

const (
	PhaseIdle Phase = iota
	PhaseProbing
	PhaseNeighbors
	PhaseDone
)

func (p Phase) String() string {
	switch p {
	case PhaseProbing:
		return "probing"
	case PhaseNeighbors:
		return "expanding around hits"
	case PhaseDone:
		return "done"
	default:
		return "idle"
	}
}

// Options configures a hunt.
type Options struct {
	// Count is how many addresses to probe in the first pass.
	Count int
	// Concurrency is how many probes run at once.
	Concurrency int
	// Probe describes the per-address measurement.
	Probe probe.Config
	// Criteria decides what counts as usable.
	Criteria score.Criteria

	// Ports is the set of edge ports to probe on every address. Empty falls
	// back to Probe.Port alone. Selecting several ports multiplies the work,
	// so the count is interpreted as addresses, not as probes.
	Ports []int

	// Ranges controls candidate generation.
	Ranges cfranges.Options

	// NeighborRadius and NeighborPerHit control expansion around a hit. A
	// working edge address usually has working neighbours, so this converts
	// a handful of lucky draws into a usable list.
	NeighborRadius int
	NeighborPerHit int
	NeighborMax    int

	// TopN, when > 0, caps how many candidates are kept for the report and
	// export. It mirrors the TUI's "Phase 2 picks" — the scan still probes
	// Count addresses, but only the best TopN are surfaced.
	TopN int

	// ExportMode selects what the textual export contains. "working" keeps only
	// addresses that passed every check (the Phase 2 output); "phase1" keeps all
	// candidates that answered. The mobile UI exposes both as copy buttons.
	ExportMode string

	// Reputation, when true, enriches each candidate with an IP-reputation
	// lookup after ranking. It is best-effort: a provider outage sets
	// Report.ReputationError instead of failing the scan.
	Reputation bool

	// Report receives progress updates. It is called from worker goroutines,
	// so implementations must be safe for concurrent use.
	Report func(Progress)
	// OnHit is called as soon as an address passes the probe stage, before
	// rating, so a UI can show results streaming in.
	OnHit func(*score.Candidate)
}

// WithDefaults fills unset fields.
func (o Options) WithDefaults() Options {
	if o.Count <= 0 {
		o.Count = 500
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 64
	}
	o.Probe = o.Probe.WithDefaults()
	if len(o.Ports) == 0 {
		o.Ports = []int{o.Probe.Port}
	} else {
		o.Ports = netports.Normalise(o.Ports)
	}
	if o.NeighborRadius <= 0 {
		o.NeighborRadius = 24
	}
	if o.NeighborPerHit <= 0 {
		o.NeighborPerHit = 8
	}
	if o.NeighborMax <= 0 {
		o.NeighborMax = 300
	}
	// Scans are IPv4-only; the IPv6 space is not supported.
	o.Ranges.IPv4 = true
	if o.Criteria.Weights == (score.Weights{}) {
		o.Criteria = score.DefaultCriteria()
	}
	return o
}

// Progress is a snapshot of an in-flight hunt.
type Progress struct {
	Phase    Phase
	Tested   int64
	Total    int64
	Hits     int64
	InFlight int64
	// Message carries a human-readable note.
	Message string
}

// Report summarises a finished hunt.
type Report struct {
	Candidates []*score.Candidate
	Tested     int64
	Hits       int64
	Duration   time.Duration
	// ReputationError is non-empty when reputation lookups were requested but
	// the provider could not be reached, so the results are not reputation-verified.
	ReputationError string
}

// Clean returns only the candidates that passed every requirement.
func (r *Report) Clean() []*score.Candidate {
	var out []*score.Candidate
	for _, c := range r.Candidates {
		if c.Healthy {
			out = append(out, c)
		}
	}
	return out
}

// ExportText renders candidates as one endpoint per line. mode selects what is
// included: "working" keeps only the addresses that passed every check (the
// Phase 2 output), anything else keeps every candidate that answered (Phase 1).
// limit, when > 0, caps the number of lines to the highest-scoring candidates.
func (r *Report) ExportText(mode string, limit int) string {
	cands := r.Candidates
	if mode == "working" {
		cands = r.Clean()
	}
	if limit > 0 && len(cands) > limit {
		cands = cands[:limit]
	}
	lines := make([]string, 0, len(cands))
	for _, c := range cands {
		lines = append(lines, c.Endpoint)
	}
	return strings.Join(lines, "\n")
}

// Scanner runs hunts.
type Scanner struct {
	opts Options

	tested   atomic.Int64
	hits     atomic.Int64
	inFlight atomic.Int64
}

// New builds a Scanner.
func New(opts Options) *Scanner {
	return &Scanner{opts: opts}
}

// Run executes a full hunt and blocks until it finishes or ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) (*Report, error) {
	start := time.Now()

	src, err := cfranges.NewSource(s.opts.Ranges)
	if err != nil {
		return nil, err
	}

	var (
		mu      sync.Mutex
		results []*probe.Result
	)
	collect := func(r *probe.Result) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	}

	// Pass 1: weighted random sweep.
	// Total counts probes, not addresses, so selecting several ports is
	// reflected honestly in the progress bar rather than overshooting 100%.
	s.report(Progress{
		Phase: PhaseProbing,
		Total: int64(s.opts.Count) * int64(len(s.opts.Ports)),
	})
	done := ctx.Done()
	stream := src.Stream(done, s.opts.Count)
	hitIPs := s.probeStream(ctx, stream, collect)

	// Pass 2: expand around every address that answered, since Cloudflare
	// allocates working edges in contiguous runs.
	if len(hitIPs) > 0 && s.opts.NeighborMax > 0 && ctx.Err() == nil {
		var neighbors []net.IP
		seen := make(map[string]struct{}, len(hitIPs))
		for _, ip := range hitIPs {
			seen[ip.String()] = struct{}{}
		}
		for _, ip := range hitIPs {
			if len(neighbors) >= s.opts.NeighborMax {
				break
			}
			for _, n := range src.NeighborsOf(ip, s.opts.NeighborRadius, s.opts.NeighborPerHit) {
				if _, dup := seen[n.String()]; dup {
					continue
				}
				seen[n.String()] = struct{}{}
				neighbors = append(neighbors, n)
				if len(neighbors) >= s.opts.NeighborMax {
					break
				}
			}
		}
		if len(neighbors) > 0 {
			s.report(Progress{
				Phase:  PhaseNeighbors,
				Tested: s.tested.Load(),
				Total:  s.tested.Load() + int64(len(neighbors))*int64(len(s.opts.Ports)),
				Hits:   s.hits.Load(),
			})
			ch := make(chan net.IP, len(neighbors))
			for _, n := range neighbors {
				ch <- n
			}
			close(ch)
			s.probeStream(ctx, ch, collect)
		}
	}

	mu.Lock()
	snapshot := make([]*probe.Result, len(results))
	copy(snapshot, results)
	mu.Unlock()

	cands := make([]*score.Candidate, 0, len(snapshot))
	for _, r := range snapshot {
		cands = append(cands, score.Evaluate(r, s.opts.Criteria))
	}
	score.Rank(cands)

	// Long-test the top healthy candidates before TopN is applied. The 3 s
	// idle hold in the regular probe cannot catch filters that reset a
	// session after 10-15 s of real traffic — the failure mode where the
	// scan reports "healthy" but live VPN use goes red minutes later. A
	// long test on the top survivors closes that gap, at the cost of one
	// extra LongTestDuration of work per candidate (run in parallel).
	if s.opts.Probe.LongTest && s.opts.Probe.LongTestDuration > 0 && ctx.Err() == nil {
		s.longTestTop(ctx, cands)
		// Demote any candidate the long test ruled out, then re-rank so the
		// survivors float to the top.
		for _, c := range cands {
			if !c.Healthy {
				score.Rank(cands)
				break
			}
		}
	}

	// TopN mirrors the TUI "Phase 2 picks": the scan still probes Count
	// addresses, but only the best TopN are kept for the report and export.
	if s.opts.TopN > 0 && len(cands) > s.opts.TopN {
		cands = cands[:s.opts.TopN]
	}

	// Reputation enrichment is best-effort and never fails the scan: a provider
	// outage sets Report.ReputationError so the UI can say "not verified clean".
	var repErr string
	if s.opts.Reputation {
		repErr = s.enrichReputation(ctx, cands)
	}

	s.report(Progress{Phase: PhaseDone, Tested: s.tested.Load(), Hits: s.hits.Load()})

	return &Report{
		Candidates:      cands,
		Tested:          s.tested.Load(),
		Hits:            s.hits.Load(),
		Duration:        time.Since(start),
		ReputationError: repErr,
	}, nil
}

// probeStream probes every address arriving on src and returns those that
// answered, for neighbour expansion.
func (s *Scanner) probeStream(ctx context.Context, src <-chan net.IP, collect func(*probe.Result)) []net.IP {
	sem := make(chan struct{}, s.opts.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var hits []net.IP
	seenHit := make(map[string]struct{})

	for ip := range src {
		if ctx.Err() != nil {
			break
		}
		// Every selected port is a separate probe of the same address. They are
		// dispatched independently so one slow port does not stall the others.
		for _, port := range s.opts.Ports {
			if ctx.Err() != nil {
				break
			}
			sem <- struct{}{}
			wg.Add(1)
			s.inFlight.Add(1)

			go func(ip net.IP, port int) {
				defer func() {
					<-sem
					s.inFlight.Add(-1)
					wg.Done()
				}()

				cfg := s.opts.Probe
				cfg.Port = port

				r := probe.Probe(ctx, ip, cfg)
				s.tested.Add(1)
				collect(r)

				if anyOk(r) {
					s.hits.Add(1)
					// Neighbour expansion works on addresses, so an address that
					// answered on several ports is only queued once.
					key := ip.String()
					mu.Lock()
					if _, dup := seenHit[key]; !dup {
						seenHit[key] = struct{}{}
						hits = append(hits, ip)
					}
					mu.Unlock()
					if s.opts.OnHit != nil {
						s.opts.OnHit(score.Evaluate(r, s.opts.Criteria))
					}
				}
				s.report(Progress{
					Phase:    PhaseProbing,
					Hits:     s.hits.Load(),
					Tested:   s.tested.Load(),
					InFlight: s.inFlight.Load(),
				})
			}(ip, port)
		}
	}

	wg.Wait()
	return hits
}

func (s *Scanner) report(p Progress) {
	if s.opts.Report != nil {
		s.opts.Report(p)
	}
}

func anyOk(r *probe.Result) bool {
	if r == nil {
		return false
	}
	for _, a := range r.Attempts {
		if a.Ok() {
			return true
		}
	}
	return false
}

// longTestTop runs a long-duration test on the top healthy candidates.
//
// The test runs on a bounded pool (the 8 best healthy candidates) so a 5k
// scan does not balloon into hours of work. Failed long tests demote the
// candidate to unhealthy with a note explaining why; the report can then
// show "this looked fast but the connection died under sustained load".
// Run in parallel, since each test is independent and slow.
func (s *Scanner) longTestTop(ctx context.Context, cands []*score.Candidate) {
	const longTestPool = 8
	pool := make([]*score.Candidate, 0, longTestPool)
	for _, c := range cands {
		if c.Healthy {
			pool = append(pool, c)
			if len(pool) >= longTestPool {
				break
			}
		}
	}
	if len(pool) == 0 {
		return
	}

	s.report(Progress{
		Phase:  PhaseNeighbors,
		Message: fmt.Sprintf("long-testing top %d survivors for %.0fs each", len(pool), s.opts.Probe.LongTestDuration.Seconds()),
	})

	cfg := s.opts.Probe
	sem := make(chan struct{}, 4) // at most 4 parallel long tests
	var wg sync.WaitGroup
	for _, c := range pool {
		wg.Add(1)
		sem <- struct{}{}
		go func(c *score.Candidate) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			ip := net.ParseIP(c.IP)
			if ip == nil {
				return
			}
			sni := cfg.SNI
			if sni == "" {
				// Match the rotating SNI used by the regular probe so the
				// test routes through the same TLS server name a real
				// session would use.
				sni = "speed.cloudflare.com"
			}
			host := cfg.Host
			if host == "" {
				host = sni
			}
			res := probe.LongTest(ctx, ip, sni, host, cfg)
			if !res.Held {
				c.Healthy = false
				note := "long test failed: " + res.Err
				if res.Duration > 0 {
					note += fmt.Sprintf(" (held %s, %d bytes)", res.Duration.Round(time.Second), res.Bytes)
				}
				c.Notes = append(c.Notes, note)
			}
		}(c)
	}
	wg.Wait()
}

// enrichReputation looks up the IP reputation for each candidate. The lookups
// run concurrently and never fail the scan: if any of them errors, the returned
// string is non-empty so the caller can warn that results are not verified clean.
func (s *Scanner) enrichReputation(ctx context.Context, cands []*score.Candidate) string {
	if len(cands) == 0 {
		return ""
	}

	type result struct {
		cand *score.Candidate
		info *reputation.Info
	}
	ch := make(chan result, len(cands))
	var wg sync.WaitGroup
	for _, c := range cands {
		wg.Add(1)
		go func(c *score.Candidate) {
			defer wg.Done()
			ch <- result{cand: c, info: reputation.Lookup(ctx, c.IP)}
		}(c)
	}
	go func() {
		wg.Wait()
		close(ch)
	}()

	failed := false
	for r := range ch {
		r.cand.Reputation = r.info
		if r.info != nil && r.info.Err != "" {
			failed = true
		}
		// Strict / "require clean" mode disqualifies an address whose reputation
		// was not conclusively clean (proxy/VPN/Tor or an unverified lookup).
		if s.opts.Criteria.RequireClean && !reputationClean(r.info) {
			r.cand.Healthy = false
			r.cand.Notes = append(r.cand.Notes, "reputation not clean (proxy/VPN/Tor or unverified)")
		}
	}
	if failed {
		return "reputation provider unavailable — results not verified clean"
	}
	return ""
}

// reputationClean reports whether the lookup conclusively shows a clean address.
func reputationClean(info *reputation.Info) bool {
	return info != nil && info.Err == "" && info.Verdict == reputation.VerdictClean
}
