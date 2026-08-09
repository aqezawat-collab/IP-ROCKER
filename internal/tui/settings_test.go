package tui

import (
	"strings"
	"testing"
	"time"
)

// A speed floor cannot mean anything without a download sample, so it must
// collapse to zero rather than filter on data that was never measured.
func TestMinSpeedCollapsesWithoutDownloadSample(t *testing.T) {
	s := defaultSettings()
	s.minIdx = 3 // 500 KB/s
	if got := s.minSpeedKBps(); got != 500 {
		t.Fatalf("with a sample on, want 500, got %v", got)
	}

	s.dlIdx = 0 // Off
	if got := s.minSpeedKBps(); got != 0 {
		t.Fatalf("with the sample off, want 0, got %v", got)
	}
	if c := s.criteria(); c.MinDownloadKBps != 0 {
		t.Fatalf("criteria kept a floor of %v with no sample", c.MinDownloadKBps)
	}
}

// The min-speed row must disappear when it cannot act.
func TestMinSpeedRowHiddenWhenSampleOff(t *testing.T) {
	s := defaultSettings()
	if !hasRow(s.rows(), rowMinSpeed) {
		t.Fatal("min speed row missing while the download sample is on")
	}
	s.dlIdx = 0
	if hasRow(s.rows(), rowMinSpeed) {
		t.Fatal("min speed row still shown with the download sample off")
	}
}

func hasRow(rows []setupRow, want setupRow) bool {
	for _, r := range rows {
		if r == want {
			return true
		}
	}
	return false
}

// The sample range has to reach a size that can actually distinguish a
// middlebox from a real edge; the old 1 MB ceiling could not.
func TestDownloadPresetsReachTwentyMegabytes(t *testing.T) {
	max := int64(0)
	for _, v := range downloadValues {
		if v > max {
			max = v
		}
	}
	if max < 20<<20 {
		t.Fatalf("largest download preset is %d bytes, want at least 20 MB", max)
	}
	if downloadValues[0] != 0 {
		t.Fatal("first download preset must be Off")
	}
	if len(downloadValues) != len(downloadPills)-1 {
		t.Fatalf("download pills (%d incl. custom) and values (%d) are out of step",
			len(downloadPills), len(downloadValues))
	}
}

// The floor must be expressible at the speed a genuinely usable edge measured.
func TestMinSpeedPresetsReachFiveMegabytesPerSecond(t *testing.T) {
	max := 0.0
	for _, v := range minSpeedValues {
		if v > max {
			max = v
		}
	}
	if max < 5000 {
		t.Fatalf("largest speed floor is %v KB/s, want at least 5000", max)
	}
	if len(minSpeedValues) != len(minSpeedPills)-1 {
		t.Fatalf("min-speed pills (%d incl. custom) and values (%d) are out of step",
			len(minSpeedPills), len(minSpeedValues))
	}
}

// A custom entry given in MB has to survive the round trip, including fractions.
func TestCustomDownloadInMegabytes(t *testing.T) {
	s := defaultSettings()
	s.dlIdx = len(downloadPills) - 1
	if err := s.applyCustom(rowDownload, " 8 "); err != nil {
		t.Fatalf("applyCustom: %v", err)
	}
	if got, want := s.downloadBytes(), int64(8<<20); got != want {
		t.Fatalf("8 MB became %d bytes, want %d", got, want)
	}
	if err := s.applyCustom(rowDownload, "0.5"); err != nil {
		t.Fatalf("applyCustom fraction: %v", err)
	}
	if got, want := s.downloadBytes(), int64(512<<10); got != want {
		t.Fatalf("0.5 MB became %d bytes, want %d", got, want)
	}
	if err := s.applyCustom(rowDownload, "-3"); err == nil {
		t.Fatal("a negative sample size was accepted")
	}
}

// Thousands separators are how a human types a large count, so they must parse.
func TestCustomCountAcceptsSeparators(t *testing.T) {
	s := defaultSettings()
	s.countIdx = len(countPills) - 1
	if err := s.applyCustom(rowCount, "12,500"); err != nil {
		t.Fatalf("applyCustom: %v", err)
	}
	if got := s.count(); got != 12500 {
		t.Fatalf("12,500 became %d", got)
	}
}

// An empty custom slot must fall back to a runnable value rather than zero,
// because a scan of zero addresses silently does nothing.
func TestEmptyCustomFallsBackToRunnableValues(t *testing.T) {
	s := defaultSettings()
	s.countIdx = len(countPills) - 1
	s.workerIdx = len(workerPills) - 1
	if s.count() <= 0 {
		t.Fatalf("empty custom count produced %d", s.count())
	}
	if s.workers() <= 0 {
		t.Fatalf("empty custom worker count produced %d", s.workers())
	}
}

// The timeout range has to include sub-second values for an aggressive sweep and
// reach far enough for a slow censored path.
func TestTimeoutRangeSpansAggressiveToPatient(t *testing.T) {
	if timeoutValues[0] > 500*time.Millisecond {
		t.Fatalf("fastest timeout is %v, want 500ms or less", timeoutValues[0])
	}
	last := timeoutValues[len(timeoutValues)-1]
	if last < 8*time.Second {
		t.Fatalf("slowest timeout is %v, want at least 8s", last)
	}
	if len(timeoutValues) != len(timeoutPills) {
		t.Fatal("timeout pills and values are out of step")
	}
}

// The default must not be a setting that throws away every healthy edge on a
// censored mobile link, where a good edge answers near 700-800 ms.
func TestDefaultTimeoutSurvivesHighLatencyPath(t *testing.T) {
	s := defaultSettings()
	if s.timeout() < time.Second {
		t.Fatalf("default timeout %v discards healthy 700-800 ms edges", s.timeout())
	}
}

// The advice string must change with the value, or the number carries no cost
// information at all.
func TestHintsChangeWithValue(t *testing.T) {
	s := defaultSettings()
	s.timeoutIdx = 0
	fast := s.hintFor(rowTimeout)
	s.timeoutIdx = len(timeoutValues) - 1
	slow := s.hintFor(rowTimeout)
	if fast == slow || fast == "" {
		t.Fatalf("timeout hint did not change with the value: %q vs %q", fast, slow)
	}

	s = defaultSettings()
	s.dlIdx = 0
	off := s.hintFor(rowDownload)
	s.dlIdx = len(downloadValues) - 1
	big := s.hintFor(rowDownload)
	if off == big || off == "" {
		t.Fatalf("download hint did not change with the value: %q vs %q", off, big)
	}
}

// The cost line has to state the derived arithmetic the user cannot do in their
// head: probes = addresses x ports, plus the payload per answering address.
func TestCostLineStatesProbesAndPayload(t *testing.T) {
	s := defaultSettings()
	s.countIdx = 2 // 2,500
	s.portIdx = 2  // 443,2053,8443
	line := s.costLine()
	if !strings.Contains(line, "7,500 probes") {
		t.Fatalf("cost line missing the probe product: %q", line)
	}
	if !strings.Contains(line, "downloaded per answering address") {
		t.Fatalf("cost line missing the payload cost: %q", line)
	}

	s.dlIdx = 0
	if strings.Contains(s.costLine(), "downloaded per answering address") {
		t.Fatalf("cost line still charges for a disabled download: %q", s.costLine())
	}
}

// "all" must expand to every Cloudflare TLS port in the cost arithmetic too, or
// the number shown understates the work by six times.
func TestCostLineCountsAllPorts(t *testing.T) {
	s := defaultSettings()
	s.countIdx = 0 // 500
	s.portIdx = 3  // all
	if got := s.costLine(); !strings.Contains(got, "3,000 probes") {
		t.Fatalf("all-ports cost line was %q", got)
	}
}

// Strict mode keeps its generous latency ceiling: a tight one rejects every
// reachable address on a long path.
func TestStrictKeepsGenerousLatencyCeiling(t *testing.T) {
	s := defaultSettings()
	s.strictIdx = 1
	c := s.criteria()
	if c.MaxLatency < 2*time.Second {
		t.Fatalf("strict latency ceiling %v is too tight for a censored path", c.MaxLatency)
	}
	if !c.RequireClean {
		t.Fatal("strict mode did not require a clean verdict")
	}
}

// A wide sweep must be allowed rather than clamped; the UI warns instead.
func TestWideSweepIsAllowed(t *testing.T) {
	s := defaultSettings()
	s.countIdx = len(countValues) - 1
	if s.count() < 20000 {
		t.Fatalf("largest count preset is %d, want at least 20000", s.count())
	}
	if !strings.Contains(s.hintFor(rowCount), "long") {
		t.Fatalf("no runtime warning on the widest sweep: %q", s.hintFor(rowCount))
	}
	s.workerIdx = len(workerValues) - 1
	if s.workers() < 500 {
		t.Fatalf("largest worker preset is %d, want at least 500", s.workers())
	}
}

// Every row must resolve to a pill set and a valid index, or the setup page
// panics the first time that row is selected.
func TestEveryRowHasPills(t *testing.T) {
	s := defaultSettings()
	for _, r := range s.rows() {
		ps, idx := s.pillsFor(r)
		if len(ps) == 0 {
			t.Fatalf("row %q has no pills", rowLabel(r))
		}
		if idx < 0 || idx >= len(ps) {
			t.Fatalf("row %q index %d out of range for %d pills", rowLabel(r), idx, len(ps))
		}
		if rowLabel(r) == "" {
			t.Fatalf("row %d has no label", r)
		}
		if s.hintFor(r) == "" {
			t.Fatalf("row %q has no hint", rowLabel(r))
		}
	}
}

// setIdx has to write the row it was given; a copy-paste slip here silently
// moves the wrong knob.
func TestSetIdxTargetsTheRightRow(t *testing.T) {
	s := defaultSettings()
	for _, r := range s.rows() {
		ps, _ := s.pillsFor(r)
		want := len(ps) - 1
		s.setIdx(r, want)
		if _, got := s.pillsFor(r); got != want {
			t.Fatalf("row %q: set %d, read back %d", rowLabel(r), want, got)
		}
	}
}

// The probe config must carry the sample sizes and timing the setup page shows,
// or the scan measures something other than what the user chose.
func TestProbeConfigReflectsSettings(t *testing.T) {
	s := defaultSettings()
	s.dlIdx = 6 // 5 MB
	s.upIdx = 2 // 512 KB
	s.triesIdx = 4
	cfg := s.probeConfig(2053)
	if cfg.Port != 2053 {
		t.Fatalf("port %d", cfg.Port)
	}
	if cfg.DownloadBytes != 5<<20 {
		t.Fatalf("download bytes %d", cfg.DownloadBytes)
	}
	if cfg.UploadBytes != 512<<10 {
		t.Fatalf("upload bytes %d", cfg.UploadBytes)
	}
	if cfg.Tries != 6 {
		t.Fatalf("tries %d", cfg.Tries)
	}
	if cfg.HoldDuration <= 0 {
		t.Fatal("idle hold disabled: an ISP that resets after the first GET would pass")
	}
}

// The custom-ranges paste row appears only once a custom scope is chosen; a
// knob that cannot act should not be shown, just like the min-speed row.
func TestRangesListRowHiddenUntilCustomSelected(t *testing.T) {
	s := defaultSettings()
	if hasRow(s.rows(), rowRangesList) {
		t.Fatal("paste row shown while the scope is the built-in ranges")
	}
	s.rangesIdx = 1
	if !hasRow(s.rows(), rowRangesList) {
		t.Fatal("paste row missing with add-custom selected")
	}
}

// The pasted list must accept bare IPs, CIDRs, newlines and commas, and count
// the entries so the row can show a short summary instead of the raw text.
func TestCustomRangesParseAndCount(t *testing.T) {
	s := defaultSettings()
	if err := s.applyCustom(rowRangesList, "1.2.3.0/24\n5.6.7.8, 9.9.9.0/24"); err != nil {
		t.Fatalf("applyCustom: %v", err)
	}
	if got := s.customRangeCount(); got != 3 {
		t.Fatalf("customRangeCount = %d, want 3", got)
	}
	if got := s.rangesSummary(); got != "3 ranges" {
		t.Fatalf("summary = %q", got)
	}

	before := s.rangesText
	if err := s.applyCustom(rowRangesList, "banana"); err == nil {
		t.Fatal("an invalid range list was accepted")
	}
	if s.rangesText != before {
		t.Fatal("a rejected list changed the stored text")
	}

	if err := s.applyCustom(rowRangesList, "   "); err != nil {
		t.Fatalf("clearing the list errored: %v", err)
	}
	if s.customRangeCount() != 0 {
		t.Fatal("cleared list still counts ranges")
	}
}

// The cost line must say the scope, because "only custom" changes how many
// addresses the count actually means.
func TestCostLineNotesCustomScope(t *testing.T) {
	s := defaultSettings()
	if strings.Contains(s.costLine(), "custom") {
		t.Fatalf("default scope mentioned custom ranges: %q", s.costLine())
	}
	s.rangesIdx = 2
	if err := s.applyCustom(rowRangesList, "1.2.3.0/24"); err != nil {
		t.Fatalf("applyCustom: %v", err)
	}
	if !strings.Contains(s.costLine(), "only custom ranges") {
		t.Fatalf("cost line missing the scope: %q", s.costLine())
	}
}

// The custom prompt must only appear on rows that have a custom slot selected.
func TestCustomPromptOnlyOnCustomSlot(t *testing.T) {
	s := defaultSettings()
	if p, _ := s.customPrompt(rowCount); p != "" {
		t.Fatalf("prompt offered on a preset selection: %q", p)
	}
	s.countIdx = len(countPills) - 1
	if p, _ := s.customPrompt(rowCount); p == "" {
		t.Fatal("no prompt on the custom slot")
	}
	if p, _ := s.customPrompt(rowPorts); p != "" {
		t.Fatalf("ports row has no custom slot but offered %q", p)
	}
}

func TestHumanBytesAndInt(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{512 << 10, "512 KB"},
		{1 << 20, "1 MB"},
		{20 << 20, "20 MB"},
		{1536 << 10, "1.5 MB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := humanInt(20000); got != "20,000" {
		t.Errorf("humanInt(20000) = %q", got)
	}
	if got := humanInt(500); got != "500" {
		t.Errorf("humanInt(500) = %q", got)
	}
}
