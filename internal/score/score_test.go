package score

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Qezawat/IP-ROCKER/internal/probe"
)

func httpResult(ip string, lat time.Duration, held, ws bool, dlBps float64, attempts int) *probe.Result {
	r := &probe.Result{IP: net.ParseIP(ip), Port: 443, Mode: "http", Started: time.Now()}
	for i := 0; i < attempts; i++ {
		r.Attempts = append(r.Attempts, probe.Attempt{
			Latency:     lat,
			TLSOk:       true,
			HTTPOk:      true,
			HeldOpen:    held,
			WSOk:        ws,
			HTTPStatus:  200,
			Colo:        "FRA",
			DownloadBps: dlBps,
		})
	}
	return r
}

// An address that resets during the idle hold must be disqualified even when
// the rest of its metrics are perfect.
func TestResetDuringHoldDisqualifies(t *testing.T) {
	r := &probe.Result{IP: net.ParseIP("3.3.3.3"), Port: 443, Mode: "http"}
	r.Attempts = append(r.Attempts, probe.Attempt{
		Latency: 50 * time.Millisecond, TLSOk: true, HTTPStatus: 200, Colo: "FRA",
		Err: "connection was reset during idle hold",
	})
	r.Attempts = append(r.Attempts, probe.Attempt{
		Latency: 50 * time.Millisecond, TLSOk: true, HTTPStatus: 200, Colo: "FRA",
		Err: "connection was reset during idle hold",
	})

	cand := Evaluate(r, DefaultCriteria())
	if cand.Healthy {
		t.Error("an address reset during the idle hold was marked healthy")
	}
}

func TestLossAndFailureAreReported(t *testing.T) {
	r := &probe.Result{IP: net.ParseIP("5.5.5.5"), Port: 443, Mode: "http"}
	r.Attempts = []probe.Attempt{
		{Latency: 80 * time.Millisecond, TLSOk: true, HTTPStatus: 200, Colo: "FRA", HeldOpen: true},
		{Err: "timeout"},
		{Err: "connection reset (likely filtered)"},
	}

	cand := Evaluate(r, DefaultCriteria())
	if cand.LossPercent < 60 {
		t.Errorf("loss = %.1f%%, want about 66%%", cand.LossPercent)
	}
	if cand.Healthy {
		t.Error("an address failing two of three attempts was marked healthy")
	}
}

func TestNoSuccessScoresZero(t *testing.T) {
	r := &probe.Result{IP: net.ParseIP("6.6.6.6"), Port: 443, Mode: "http"}
	r.Attempts = []probe.Attempt{{Err: "timeout"}, {Err: "timeout"}}

	cand := Evaluate(r, DefaultCriteria())
	if cand.Total != 0 {
		t.Errorf("score = %.1f, want 0 for an address that never answered", cand.Total)
	}
	if cand.Healthy {
		t.Error("an address that never answered was marked healthy")
	}
	if len(cand.Notes) == 0 {
		t.Error("expected a note explaining the failure")
	}
}

// Score must be monotonic in latency, so the ordering the user sees is stable
// and explainable rather than arbitrary.
func TestFasterScoresHigherAmongEqualPeers(t *testing.T) {
	c := DefaultCriteria()
	fast := Evaluate(httpResult("7.7.7.7", 60*time.Millisecond, true, true, 1_000_000, 3), c)
	slow := Evaluate(httpResult("8.8.8.8", 600*time.Millisecond, true, true, 1_000_000, 3), c)
	Rank([]*Candidate{fast, slow})
	if fast.Total <= slow.Total {
		t.Errorf("fast scored %.1f but slow scored %.1f", fast.Total, slow.Total)
	}
}

// On a long path every reachable edge sits near the same high latency. Absolute
// scoring would rate them all poorly; relative scoring must let the best of the
// population score well, because that is the address the user should pick.
func TestHighLatencyPopulationStillScoresWell(t *testing.T) {
	c := DefaultCriteria()
	cands := []*Candidate{
		Evaluate(httpResult("1.0.0.1", 710*time.Millisecond, true, true, 5_000_000, 3), c),
		Evaluate(httpResult("1.0.0.2", 780*time.Millisecond, true, true, 5_000_000, 3), c),
		Evaluate(httpResult("1.0.0.3", 830*time.Millisecond, true, true, 5_000_000, 3), c),
	}
	Rank(cands)

	best := cands[0]
	if best.IP != "1.0.0.1" {
		t.Errorf("ranking put %s first, want the lowest-latency address", best.IP)
	}
	if best.Total < 85 {
		t.Errorf("best of a uniformly high-latency population scored %.1f, "+
			"expected 85 or more", best.Total)
	}
}

// A near-identical population must not have millisecond noise amplified into
// large score differences.
func TestNearIdenticalLatenciesAreNotAmplified(t *testing.T) {
	c := DefaultCriteria()
	cands := []*Candidate{
		Evaluate(httpResult("2.0.0.1", 700*time.Millisecond, true, true, 2_000_000, 3), c),
		Evaluate(httpResult("2.0.0.2", 705*time.Millisecond, true, true, 2_000_000, 3), c),
	}
	Rank(cands)

	if diff := cands[0].Total - cands[1].Total; diff > 2 {
		t.Errorf("a 5 ms difference produced a %.1f point score gap", diff)
	}
}

// An address that answers implausibly fast but moves no data is a middlebox
// signature, and the user must be told rather than shown it ranked top.
func TestFastButNoDataIsFlagged(t *testing.T) {
	r := &probe.Result{IP: net.ParseIP("9.9.9.9"), Port: 443, Mode: "http"}
	r.Attempts = []probe.Attempt{
		{
			Latency: 180 * time.Millisecond, TLSOk: true, HTTPOk: true,
			HTTPStatus: 200, Colo: "FRA", HeldOpen: true,
			DownloadTested: true, DownloadBps: 0,
		},
		{
			Latency: 190 * time.Millisecond, TLSOk: true, HTTPOk: true,
			HTTPStatus: 200, Colo: "FRA", HeldOpen: true,
			DownloadTested: true, DownloadBps: 0,
		},
	}

	cand := Evaluate(r, DefaultCriteria())
	found := false
	for _, n := range cand.Notes {
		if strings.Contains(n, "middlebox") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a middlebox warning, got notes: %v", cand.Notes)
	}
}
