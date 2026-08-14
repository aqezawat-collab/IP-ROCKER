package scanner

import (
	"sort"
	"strings"
	"testing"

	"github.com/Qezawat/IP-ROCKER/internal/score"
)

// ensure the score package is referenced even if mkCand is inlined.
var _ = score.Candidate{}

// candidate is a tiny helper so the export test does not depend on the full
// probe pipeline.
func mkCand(ip string, port int, healthy bool, total float64) *score.Candidate {
	return &score.Candidate{
		IP:       ip,
		Port:     port,
		Healthy:  healthy,
		Total:    total,
		Endpoint: ip + ":" + itoa(port),
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func TestExportTextPhase2Working(t *testing.T) {
	cands := []*score.Candidate{
		mkCand("1.2.3.4", 443, false, 90),
		mkCand("5.6.7.8", 8443, true, 80),
		mkCand("9.10.11.12", 443, true, 95),
	}
	// The report is produced after score.Rank, so the candidates arrive sorted
	// best-first. Simulate that ordering here.
	sort.Slice(cands, func(i, j int) bool { return cands[i].Total > cands[j].Total })
	rep := &Report{Candidates: cands}

	// Phase 1 keeps every answer.
	phase1 := rep.ExportText("phase1", 0)
	if got := strings.Count(phase1, "\n") + 1; got != 3 {
		t.Fatalf("phase1 expected 3 lines, got %d", got)
	}

	// Phase 2 keeps only the healthy ones, highest score first.
	phase2 := rep.ExportText("working", 0)
	lines := strings.Split(phase2, "\n")
	if len(lines) != 2 {
		t.Fatalf("phase2 expected 2 lines, got %d", len(lines))
	}
	if lines[0] != "9.10.11.12:443" {
		t.Fatalf("phase2 top pick wrong: %q", lines[0])
	}

	// TopN caps the output.
	top1 := rep.ExportText("working", 1)
	if strings.Count(top1, "\n")+1 != 1 {
		t.Fatalf("topN=1 expected 1 line, got %d", strings.Count(top1, "\n")+1)
	}
}
