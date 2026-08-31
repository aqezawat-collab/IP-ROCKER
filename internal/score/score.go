// Package score turns raw probe measurements into a single ranking figure.
package score

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Qezawat/IP-ROCKER/internal/probe"
	"github.com/Qezawat/IP-ROCKER/internal/reputation"
)

// Weights control how much each dimension contributes. They sum to 1.0.
type Weights struct {
	Latency   float64
	Stability float64
	Download  float64
	Upload    float64
}

// DefaultWeights favour responsiveness first, then raw speed.
func DefaultWeights() Weights {
	return Weights{
		Latency:   0.35,
		Stability: 0.35,
		Download:  0.20,
		Upload:    0.10,
	}
}

// Candidate is one scored address, ready for display or export.
type Candidate struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`

	AvgLatency   time.Duration `json:"-"`
	AvgLatencyMs float64       `json:"avg_latency_ms"`
	MinLatencyMs float64       `json:"min_latency_ms"`
	JitterMs     float64       `json:"jitter_ms"`
	LossPercent  float64       `json:"loss_percent"`

	DownloadKBps float64 `json:"download_kbps"`
	UploadKBps   float64 `json:"upload_kbps"`

	Colo     string `json:"colo,omitempty"`
	HeldOpen bool   `json:"held_open"`
	WSOk     bool   `json:"websocket_ok"`
	TLSOk    bool   `json:"tls_ok"`

	// Total is the composite 0..100 ranking figure.
	Total float64 `json:"score"`

	// Component scores, retained so the total can be recomputed once the whole
	// population is known. Latency is only meaningful relative to the other
	// addresses in the same scan, which is not available while a single
	// candidate is being evaluated.
	stabilityScore float64
	downloadScore  float64
	uploadScore    float64
	weights        Weights

	// Healthy is false when the address failed a hard requirement, in which
	// case it is reported but never recommended.
	Healthy bool `json:"healthy"`
	// Verdict is always unknown; kept for JSON compatibility with older UIs.
	Verdict string `json:"verdict"`
	// Reputation is the optional IP-reputation lookup for this address. It is
	// nil when the scan did not request reputation or the lookup failed.
	Reputation *reputation.Info `json:"reputation,omitempty"`
	// Notes explains the outcome to the user.
	Notes []string `json:"notes,omitempty"`

	// Endpoint is the address:port form used in exports and configs.
	Endpoint string `json:"endpoint"`
}

// Criteria defines what counts as a usable address.
type Criteria struct {
	// RequireHold disqualifies addresses that were reset during the idle hold.
	RequireHold bool
	// RequireWebSocket disqualifies addresses that refused a WebSocket upgrade.
	RequireWebSocket bool
	// RequireClean disqualifies addresses whose reputation lookup was not clean
	// (proxy/VPN/Tor) or could not be verified. Set by strict mode.
	RequireClean bool
	// MinDownloadKBps disqualifies addresses slower than this. Zero disables.
	MinDownloadKBps float64
	// MaxLossPercent disqualifies addresses above this loss level.
	MaxLossPercent float64
	// MaxLatency disqualifies addresses slower than this. Zero disables.
	MaxLatency time.Duration
	Weights    Weights
}

// DefaultCriteria is a balanced profile: proven-carrying.
func DefaultCriteria() Criteria {
	return Criteria{
		RequireHold:      false,
		RequireWebSocket: false,
		MaxLossPercent:   50,
		Weights:          DefaultWeights(),
	}
}

// StrictCriteria only accepts addresses that are green on every axis.
func StrictCriteria() Criteria {
	c := DefaultCriteria()
	c.RequireHold = true
	c.RequireWebSocket = true
	c.RequireClean = true
	c.MinDownloadKBps = 200
	c.MaxLossPercent = 34
	c.MaxLatency = 2500 * time.Millisecond
	return c
}

// Evaluate combines a probe result into a Candidate.
func Evaluate(r *probe.Result, c Criteria) *Candidate {
	if c.Weights == (Weights{}) {
		c.Weights = DefaultWeights()
	}

	cand := &Candidate{
		IP:      r.IP.String(),
		Port:    r.Port,
		Verdict: "unknown",
	}
	cand.Endpoint = cand.IP + ":" + strconv.Itoa(cand.Port)

	stats := summarise(r)
	cand.AvgLatency = stats.avg
	cand.AvgLatencyMs = ms(stats.avg)
	cand.MinLatencyMs = ms(stats.min)
	cand.JitterMs = ms(stats.jitter)
	cand.LossPercent = stats.loss
	cand.DownloadKBps = stats.downloadBps / 1024
	cand.UploadKBps = stats.uploadBps / 1024
	cand.Colo = stats.colo
	cand.HeldOpen = stats.held
	cand.WSOk = stats.wsOk
	cand.TLSOk = stats.tlsOk

	cand.Healthy = true

	if stats.successes < 1 {
		cand.Healthy = false
		if stats.lastErr != "" {
			cand.Notes = append(cand.Notes, stats.lastErr)
		} else {
			cand.Notes = append(cand.Notes, "no successful attempt")
		}
	}
	if r.Mode != "tcp" && !stats.tlsOk && r.Port != 80 {
		cand.Healthy = false
		cand.Notes = append(cand.Notes, "TLS handshake never completed")
	}
	if stats.loss > c.MaxLossPercent && c.MaxLossPercent > 0 {
		cand.Healthy = false
		cand.Notes = append(cand.Notes, "packet loss above threshold")
	}
	if c.MaxLatency > 0 && stats.avg > c.MaxLatency {
		cand.Healthy = false
		cand.Notes = append(cand.Notes, "latency above threshold")
	}
	if c.RequireHold && stats.holdTested && !stats.held {
		cand.Healthy = false
		cand.Notes = append(cand.Notes, "connection reset during idle hold")
	}
	if c.RequireWebSocket && !stats.wsOk {
		cand.Healthy = false
		cand.Notes = append(cand.Notes, "WebSocket upgrade unavailable")
	}
	// Only enforce the speed floor when a download was actually attempted and
	// completed. If the download endpoint was unavailable (HTTP 4xx, timeout)
	// the test is recorded as a note, not as a disqualifying failure, so
	// DownloadKBps stays zero through no fault of the edge. Penalising a zero
	// that means "not measured" the same way as a zero that means "too slow"
	// rejects good edges purely because speed.cloudflare.com was unreachable.
	if stats.downloadTested && stats.downloadBps <= 0 {
		cand.Healthy = false
		cand.Notes = append(cand.Notes, "download test failed")
	}
	if c.MinDownloadKBps > 0 && stats.downloadTested && stats.downloadBps > 0 && cand.DownloadKBps < c.MinDownloadKBps {
		cand.Healthy = false
		cand.Notes = append(cand.Notes, "download below threshold")
	}
	// Upload is an explicit user-enabled requirement. A timeout, reset, or
	// rejected upload leaves UploadBps at zero; that must not be treated as a
	// usable bidirectional edge when the upload test was requested.
	if stats.uploadTested && stats.uploadBps <= 0 {
		cand.Healthy = false
		cand.Notes = append(cand.Notes, "upload test failed")
	}

	// A provisional total, correct for everything except latency. Latency is
	// finalised by Rank once the whole population is visible.
	cand.weights = c.Weights
	cand.stabilityScore = stabilityScore(stats)
	cand.downloadScore = scale(stats.downloadBps/1024, 50, 4096, false)
	cand.uploadScore = scale(stats.uploadBps/1024, 25, 1024, false)
	if stats.successes == 0 {
		cand.Total = 0
	} else {
		cand.Total = cand.combine(scale(ms(stats.avg), 30, 1500, true))
	}

	// An address that answers unusually fast but then cannot move data is the
	// signature of a middlebox answering on the edge's behalf rather than the
	// edge itself. Flag it, because a latency-only view rates it best in class.
	//
	// Only fire when the download was truly attempted AND produced zero bytes —
	// not when the speed-test endpoint was simply unavailable (HTTP 4xx, timeout,
	// no /__down route). In those cases downloadBps stays zero but the edge may
	// be perfectly clean; the endpoint outage is recorded as a note, not a fault.
	// We distinguish the two by checking that at least one attempt had a real
	// transfer error (downloadBps==0 AND downloadTested AND no download error
	// note was left by probe — i.e. the request reached the edge and got data
	// back but the volume was near zero, which is the true middlebox signature).
	if stats.successes > 0 && stats.downloadTested && stats.downloadBps <= 0 &&
		stats.avg > 0 && ms(stats.avg) < 250 && !stats.downloadEndpointUnavailable {
		cand.Notes = append(cand.Notes,
			"answered in under 250 ms but carried no data — likely a middlebox, not the edge")
	}

	cand.Notes = append(cand.Notes, stats.notes...)
	return cand
}

// combine folds a latency sub-score into the retained component scores.
func (c *Candidate) combine(latScore float64) float64 {
	w := c.weights
	if w == (Weights{}) {
		w = DefaultWeights()
	}
	total := latScore*w.Latency +
		c.stabilityScore*w.Stability +
		c.downloadScore*w.Download +
		c.uploadScore*w.Upload
	return math.Round(clamp(total, 0, 100)*10) / 10
}

type stats struct {
	avg, min, jitter time.Duration
	loss             float64
	successes        int
	downloadBps      float64
	uploadBps        float64
	downloadTested   bool
	uploadTested     bool
	colo             string
	tlsOk            bool
	held             bool
	holdTested       bool
	wsOk             bool
	lastErr          string
	notes            []string
	// downloadEndpointUnavailable is true when a download was attempted but the
	// speed-test endpoint refused the request (HTTP 4xx/5xx, timeout, no route)
	// rather than the transfer being truncated mid-stream. This distinguishes
	// "endpoint not reachable" from "edge answered but moved no data", which is
	// the real middlebox signature.
	downloadEndpointUnavailable bool
}

func summarise(r *probe.Result) stats {
	var s stats
	if r == nil || len(r.Attempts) == 0 {
		s.loss = 100
		return s
	}

	var sum time.Duration
	var lats []time.Duration
	for _, a := range r.Attempts {
		if a.Err != "" {
			s.lastErr = a.Err
		}
		if a.Note != "" {
			s.notes = append(s.notes, a.Note)
			// A note that starts with "download skipped" means the speed-test
			// endpoint refused the request (HTTP 4xx, timeout, no /__down route).
			// This is not a sign the edge is broken; mark it so the middlebox
			// heuristic below does not fire on a good edge with an unavailable
			// endpoint.
			if strings.HasPrefix(a.Note, "download skipped") {
				s.downloadEndpointUnavailable = true
			}
		}
		if a.TLSOk {
			s.tlsOk = true
		}
		if a.WSOk {
			s.wsOk = true
		}
		if a.HeldOpen {
			s.held = true
			s.holdTested = true
		}
		if a.Err == "connection was reset during idle hold" {
			s.holdTested = true
		}
		if a.Colo != "" {
			s.colo = a.Colo
		}
		if a.DownloadBps > s.downloadBps {
			s.downloadBps = a.DownloadBps
		}
		if a.DownloadTested {
			s.downloadTested = true
		}
		if a.UploadTested {
			s.uploadTested = true
		}
		if a.UploadBps > s.uploadBps {
			s.uploadBps = a.UploadBps
		}
		if !a.Ok() {
			continue
		}
		s.successes++
		sum += a.Latency
		lats = append(lats, a.Latency)
		if s.min == 0 || a.Latency < s.min {
			s.min = a.Latency
		}
	}

	s.loss = float64(len(r.Attempts)-s.successes) / float64(len(r.Attempts)) * 100
	if s.successes == 0 {
		return s
	}
	s.avg = sum / time.Duration(s.successes)

	if len(lats) >= 2 {
		mean := float64(s.avg)
		var variance float64
		for _, l := range lats {
			d := float64(l) - mean
			variance += d * d
		}
		s.jitter = time.Duration(math.Sqrt(variance / float64(len(lats))))
	}
	return s
}

// stabilityScore blends loss, jitter and the hold and WebSocket outcomes.
func stabilityScore(s stats) float64 {
	if s.successes == 0 {
		return 0
	}
	v := (100 - s.loss) * 0.5
	// Jitter is best at zero; a perfectly stable connection must score full
	// marks, not zero. scale() returns 0 for v<=0, so map a zero jitter to the
	// best score explicitly.
	jscore := scale(ms(s.jitter), 5, 400, true)
	if s.jitter == 0 {
		jscore = 100
	}
	v += jscore * 0.3
	if s.held {
		v += 15
	}
	if s.wsOk {
		v += 5
	}
	return clamp(v, 0, 100)
}

// scale maps v within [best, worst] onto 0..100. When lowerIsBetter is true,
// best is the smaller bound.
func scale(v, best, worst float64, lowerIsBetter bool) float64 {
	if v <= 0 {
		return 0
	}
	if lowerIsBetter {
		if v <= best {
			return 100
		}
		if v >= worst {
			return 0
		}
		return (worst - v) / (worst - best) * 100
	}
	if v >= worst {
		return 100
	}
	if v <= best {
		return v / best * 40
	}
	return 40 + (v-best)/(worst-best)*60
}

func ms(d time.Duration) float64 {
	return math.Round(float64(d.Microseconds())/1000*100) / 100
}

func clamp(v, lo, hi float64) float64 {
	return math.Max(lo, math.Min(hi, v))
}

// Rank finalises latency scoring against the whole population, then sorts
// best-first: healthy before unhealthy, then by score.
//
// Latency is scored relatively rather than against fixed absolute bounds. On a
// long path every reachable edge may sit near 700-800 ms, and an absolute scale
// would score all of them badly while rewarding an address that answered in
// 200 ms — which on such a path is usually a middlebox replying on the edge's
// behalf, not a genuinely closer edge. Relative scoring makes the best
// reachable address score well and keeps the ordering meaningful on any network.
func Rank(cands []*Candidate) {
	rescoreLatency(cands)

	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.Healthy != b.Healthy {
			return a.Healthy
		}
		if a.Total != b.Total {
			return a.Total > b.Total
		}
		return a.AvgLatency < b.AvgLatency
	})
}

// rescoreLatency recomputes each candidate's total using a latency scale
// derived from the population that actually answered.
func rescoreLatency(cands []*Candidate) {
	var measured []float64
	for _, c := range cands {
		if c.AvgLatencyMs > 0 {
			measured = append(measured, c.AvgLatencyMs)
		}
	}
	if len(measured) == 0 {
		return
	}

	sorted := make([]float64, len(measured))
	copy(sorted, measured)
	sort.Float64s(sorted)

	best := sorted[0]
	// The 90th percentile is the "worst acceptable" anchor. Using the true
	// maximum would let one pathological outlier compress everyone else into
	// the top of the scale.
	worst := sorted[percentileIndex(len(sorted), 0.90)]

	// Keep a floor of separation so a population with nearly identical
	// latencies does not amplify millisecond noise into large score gaps.
	const minSpreadMs = 120
	if worst-best < minSpreadMs {
		worst = best + minSpreadMs
	}

	for _, c := range cands {
		if c.AvgLatencyMs <= 0 {
			c.Total = 0
			continue
		}
		c.Total = c.combine(scale(c.AvgLatencyMs, best, worst, true))
	}
}

func percentileIndex(n int, p float64) int {
	if n <= 1 {
		return 0
	}
	idx := int(float64(n-1) * p)
	if idx < 0 {
		return 0
	}
	if idx >= n {
		return n - 1
	}
	return idx
}
