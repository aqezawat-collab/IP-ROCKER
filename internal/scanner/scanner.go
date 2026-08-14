// Package scanner orchestrates a full hunt: generate candidates, probe them,
// expand around hits, rate the survivors, and rank the result.
package scanner

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Qezawat/IP-ROCKER/internal/cfranges"
	"github.com/Qezawat/IP-ROCKER/internal/netports"
	"github.com/Qezawat/IP-ROCKER/internal/probe"
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
		cands = append(cands, score.Evaluate(r, nil, s.opts.Criteria))
	}
	score.Rank(cands)

	// TopN mirrors the TUI "Phase 2 picks": the scan still probes Count
	// addresses, but only the best TopN are kept for the report and export.
	if s.opts.TopN > 0 && len(cands) > s.opts.TopN {
		cands = cands[:s.opts.TopN]
	}

	s.report(Progress{Phase: PhaseDone, Tested: s.tested.Load(), Hits: s.hits.Load()})

	return &Report{
		Candidates: cands,
		Tested:     s.tested.Load(),
		Hits:       s.hits.Load(),
		Duration:   time.Since(start),
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
						s.opts.OnHit(score.Evaluate(r, nil, s.opts.Criteria))
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
