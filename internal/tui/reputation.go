package tui

import (
	"fmt"

	"github.com/Qezawat/IP-ROCKER/internal/reputation"
	"github.com/Qezawat/IP-ROCKER/internal/score"
)

// verdictMark renders a single reputation verdict glyph for a candidate. An
// address whose lookup failed or was skipped is shown as "?", never as clean.
func verdictMark(c *score.Candidate) string {
	if c.Reputation == nil || c.Reputation.Err != "" {
		return styDim.Render("?")
	}
	switch c.Reputation.Verdict {
	case reputation.VerdictClean:
		return styGood.Render("clean")
	case reputation.VerdictCaution:
		return styWarn.Render("caution")
	default:
		return styBad.Render("bad")
	}
}

// riskStr renders the reputation risk percentage, or "n/a" when the lookup was
// skipped or failed — a failed lookup must not read as zero risk.
func riskStr(r *reputation.Info) string {
	if r == nil || r.Err != "" {
		return "n/a"
	}
	return fmt.Sprintf("%d%%", r.RiskPercent)
}
