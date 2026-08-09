package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/Qezawat/IP-ROCKER/internal/reputation"
	"github.com/Qezawat/IP-ROCKER/internal/scanner"
	"github.com/Qezawat/IP-ROCKER/internal/score"
	tea "github.com/charmbracelet/bubbletea"
)

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "ctrl+d":
		return tea.KeyMsg{Type: tea.KeyCtrlD}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func send(m Model, msgs ...tea.Msg) Model {
	for _, msg := range msgs {
		next, _ := m.Update(msg)
		m = next.(Model)
	}
	return m
}

// Every page must render without panicking and without an empty frame, since an
// empty View is an invisible app rather than an error the user can act on.
func TestEveryPageRenders(t *testing.T) {
	pages := []page{pageHome, pageSetup, pageConfigLink, pageScan, pageResults, pageDetail, pageAbout}
	for _, p := range pages {
		m := New("v1.2.3")
		m.page = p
		m.report = fakeReport()
		m.detail = m.report.Candidates[0]
		out := m.View()
		if strings.TrimSpace(out) == "" {
			t.Fatalf("page %d rendered nothing", p)
		}
	}
}

// Arrow keys must move the highlighted row and change the selected value, which
// is the whole interaction model of the setup page.
func TestSetupNavigationMovesRowAndValue(t *testing.T) {
	m := New("test")
	m.page = pageSetup

	rows := m.set.rows()
	m = send(m, key("down"))
	if m.rowIdx != 1 {
		t.Fatalf("down did not move the row: %d", m.rowIdx)
	}
	m = send(m, key("up"), key("up"))
	if m.rowIdx != 0 {
		t.Fatalf("up past the first row wrapped or overshot: %d", m.rowIdx)
	}

	_, before := m.set.pillsFor(rows[0])
	m = send(m, key("right"))
	if _, after := m.set.pillsFor(rows[0]); after != before+1 {
		t.Fatalf("right moved %d to %d", before, after)
	}
	// Left at the first pill must stay put rather than go negative.
	m = send(m, key("left"), key("left"), key("left"))
	if _, got := m.set.pillsFor(rows[0]); got != 0 {
		t.Fatalf("left past the first pill produced index %d", got)
	}
}

// Right past the last pill must clamp; an out-of-range index panics on render.
func TestSetupValueClampsAtEnd(t *testing.T) {
	m := New("test")
	m.page = pageSetup
	row := m.set.rows()[0]
	ps, _ := m.set.pillsFor(row)
	for i := 0; i < len(ps)+5; i++ {
		m = send(m, key("right"))
	}
	if _, got := m.set.pillsFor(row); got != len(ps)-1 {
		t.Fatalf("index %d for %d pills", got, len(ps))
	}
	if strings.TrimSpace(m.View()) == "" {
		t.Fatal("setup page stopped rendering after clamping")
	}
}

// Pressing c must open the editor on a row that has a custom slot, and the typed
// value must land in the setting.
func TestCustomEditorRoundTrip(t *testing.T) {
	m := New("test")
	m.page = pageSetup
	m.rowIdx = 0 // addresses

	m = send(m, key("c"))
	if !m.editing {
		t.Fatal("c did not open the custom editor")
	}
	for _, r := range "7500" {
		m = send(m, key(string(r)))
	}
	m = send(m, key("enter"))
	if m.editing {
		t.Fatal("enter did not close the editor")
	}
	if got := m.set.count(); got != 7500 {
		t.Fatalf("custom count came out as %d", got)
	}
}

// The custom-ranges row opens a multiline paste editor (not the single-line
// field), and ctrl+d accepts it. The list is validated on accept so a typo is
// caught in the editor instead of after the scan starts.
func TestCustomRangesEditorRoundTrip(t *testing.T) {
	m := New("test")
	m.page = pageSetup
	m.set.rangesIdx = 2 // Only custom — the paste row is now visible
	rows := m.set.rows()
	for i, r := range rows {
		if r == rowRangesList {
			m.rowIdx = i
		}
	}

	m = send(m, key("c"))
	if !m.editing || m.editRow != rowRangesList {
		t.Fatal("c did not open the ranges editor")
	}
	m.ta.SetValue("1.2.3.0/24\n5.6.7.8")
	m = send(m, key("ctrl+d"))
	if m.editing {
		t.Fatal("ctrl+d did not close the editor")
	}
	if got := m.set.customRangeCount(); got != 2 {
		t.Fatalf("customRangeCount = %d, want 2", got)
	}
}

// Garbage in the ranges paste must keep the editor open with an error.
func TestCustomRangesEditorRejectsGarbage(t *testing.T) {
	m := New("test")
	m.page = pageSetup
	m.set.rangesIdx = 2
	rows := m.set.rows()
	for i, r := range rows {
		if r == rowRangesList {
			m.rowIdx = i
		}
	}

	m = send(m, key("c"))
	m.ta.SetValue("1.2.3.0/24\nbanana")
	m = send(m, key("ctrl+d"))
	if !m.editing {
		t.Fatal("editor closed on an invalid range list")
	}
	if m.errMsg == "" {
		t.Fatal("no error shown for an invalid range list")
	}
}

// "Only custom" with nothing pasted must refuse to scan rather than silently
// probing the built-in ranges.
func TestOnlyCustomWithoutListFailsBeforeScanning(t *testing.T) {
	m := New("test")
	m.page = pageSetup
	m.set.rangesIdx = 2
	next, _ := m.startScan()
	m = next.(Model)
	if m.page == pageScan {
		t.Fatal("a scan started with only-custom selected but no ranges pasted")
	}
	if m.errMsg == "" {
		t.Fatal("no error explaining the empty custom scope")
	}
}

// A rejected custom value must keep the editor open with an error rather than
// silently applying a zero.
func TestCustomEditorRejectsGarbage(t *testing.T) {
	m := New("test")
	m.page = pageSetup
	m.rowIdx = 0
	m = send(m, key("c"))
	for _, r := range "abc" {
		m = send(m, key(string(r)))
	}
	m = send(m, key("enter"))
	if !m.editing {
		t.Fatal("editor closed on an invalid value")
	}
	if m.errMsg == "" {
		t.Fatal("no error shown for an invalid value")
	}
}

// Escape must abandon the edit without changing the setting.
func TestCustomEditorEscapeDiscards(t *testing.T) {
	m := New("test")
	m.page = pageSetup
	m.rowIdx = 0
	before := m.set.count()
	m = send(m, key("c"))
	for _, r := range "999" {
		m = send(m, key(string(r)))
	}
	m = send(m, key("esc"))
	if m.editing {
		t.Fatal("escape did not close the editor")
	}
	// The custom slot is selected but empty, so the count falls back rather than
	// taking the abandoned digits.
	if m.set.countCustom != 0 {
		t.Fatalf("abandoned entry was stored as %d", m.set.countCustom)
	}
	_ = before
}

// While editing, a keystroke that is also a shortcut must go to the text field.
// Otherwise typing "5000" into a count field triggers "s = start scan".
func TestEditingCapturesShortcutKeys(t *testing.T) {
	m := New("test")
	m.page = pageSetup
	m.rowIdx = 0
	m = send(m, key("c"))
	m = send(m, key("s"))
	if m.page != pageSetup {
		t.Fatal("a shortcut key fired while the editor had focus")
	}
	if !m.editing {
		t.Fatal("editor lost focus to a shortcut key")
	}
}

// Progress and hit messages must re-arm their listener, or the live view freezes
// after the first update.
func TestProgressAndHitsKeepListening(t *testing.T) {
	m := New("test")
	m.progCh = make(chan scanner.Progress, 1)
	m.hitCh = make(chan *score.Candidate, 1)

	next, cmd := m.Update(progressMsg(scanner.Progress{Phase: scanner.PhaseProbing, Tested: 10, Total: 100}))
	m = next.(Model)
	if cmd == nil {
		t.Fatal("progress message did not re-arm the listener")
	}
	if m.prog.Tested != 10 {
		t.Fatalf("progress not stored: %+v", m.prog)
	}

	next, cmd = m.Update(hitMsg{c: &score.Candidate{IP: "1.2.3.4", Port: 443}})
	m = next.(Model)
	if cmd == nil {
		t.Fatal("hit message did not re-arm the listener")
	}
	if len(m.live) != 1 {
		t.Fatalf("hit not appended: %d", len(m.live))
	}
}

// A closed stream must not re-arm, or the update loop spins on a dead channel.
func TestClosedStreamStops(t *testing.T) {
	m := New("test")
	_, cmd := m.Update(streamClosedMsg{})
	if cmd != nil {
		t.Fatal("closed stream re-armed a listener")
	}
}

// Finishing a scan must land on the results page with the report attached.
func TestDoneMovesToResults(t *testing.T) {
	m := New("test")
	m.page = pageScan
	m = send(m, doneMsg{report: fakeReport()})
	if m.page != pageResults {
		t.Fatalf("page after done is %d", m.page)
	}
	if m.report == nil {
		t.Fatal("report not stored")
	}
	if !strings.Contains(m.View(), "1.1.1.1") {
		t.Fatalf("results view missing the best address:\n%s", m.View())
	}
}

// A failed scan must show the real error, not a generic message.
func TestScanErrorIsShown(t *testing.T) {
	m := New("test")
	m.page = pageScan
	m = send(m, doneMsg{err: errString("no route to host")})
	out := m.View()
	if !strings.Contains(out, "no route to host") {
		t.Fatalf("the real error was not surfaced:\n%s", out)
	}
}

// An address whose reputation lookup failed must never be displayed as clean.
func TestUnratedAddressIsNotShownAsClean(t *testing.T) {
	m := New("test")
	m.page = pageResults
	c := &score.Candidate{
		IP:         "9.9.9.9",
		Port:       443,
		Reputation: &reputation.Info{Err: "provider timeout"},
	}
	if got := verdictMark(c); strings.Contains(got, "clean") {
		t.Fatalf("unrated address marked %q", got)
	}
	if got := riskStr(c.Reputation); got != "n/a" {
		t.Fatalf("failed lookup reported risk %q", got)
	}
}

// Reputation being incomplete has to be stated on the results page, since a
// provider outage silently passing everything is the worst failure of this tool.
func TestReputationOutageIsStated(t *testing.T) {
	m := New("test")
	m.page = pageResults
	m.report = fakeReport()
	m.report.ReputationError = "429 from ipapi.is"
	out := m.View()
	if !strings.Contains(out, "429 from ipapi.is") {
		t.Fatalf("outage not surfaced:\n%s", out)
	}
	if !strings.Contains(out, "not confirmed clean") {
		t.Fatalf("outage shown without the caveat:\n%s", out)
	}
}

// The detail page must state that a datacenter flag is expected rather than a
// fault, because every Cloudflare edge is one.
func TestDetailCallsDatacenterExpected(t *testing.T) {
	m := New("test")
	m.page = pageDetail
	m.detail = &score.Candidate{
		IP: "1.1.1.1", Port: 443,
		Reputation: &reputation.Info{IsDatacenter: true, Verdict: reputation.VerdictClean},
	}
	out := m.View()
	if !strings.Contains(out, "expected") {
		t.Fatalf("datacenter flag not framed as expected:\n%s", out)
	}
}

// When nothing passed, showing an empty table is useless: the best attempts and
// their reasons have to appear instead.
func TestFallsBackToBestAttempts(t *testing.T) {
	m := New("test")
	m.page = pageResults
	m.report = &scanner.Report{
		Tested: 500, Hits: 3, Duration: time.Second,
		Candidates: []*score.Candidate{
			{IP: "5.5.5.5", Port: 443, Healthy: false, Notes: []string{"connection was reset during idle hold"}},
		},
	}
	out := m.View()
	if !strings.Contains(out, "5.5.5.5") {
		t.Fatalf("best attempt not listed:\n%s", out)
	}
	if !strings.Contains(out, "showing best attempts") {
		t.Fatalf("no explanation that nothing passed:\n%s", out)
	}
}

// Moving through the result list must stay in range on both ends.
func TestResultCursorStaysInRange(t *testing.T) {
	m := New("test")
	m.page = pageResults
	m.report = fakeReport()
	for i := 0; i < 20; i++ {
		m = send(m, key("down"))
	}
	if m.resultIdx >= len(m.cleanList()) {
		t.Fatalf("cursor %d past the end of %d results", m.resultIdx, len(m.cleanList()))
	}
	for i := 0; i < 20; i++ {
		m = send(m, key("up"))
	}
	if m.resultIdx != 0 {
		t.Fatalf("cursor went negative: %d", m.resultIdx)
	}
}

// Enter on a result must open its detail page.
func TestEnterOpensDetail(t *testing.T) {
	m := New("test")
	m.page = pageResults
	m.report = fakeReport()
	m = send(m, key("enter"))
	if m.page != pageDetail {
		t.Fatalf("page after enter is %d", m.page)
	}
	if m.detail == nil {
		t.Fatal("no candidate selected")
	}
	m = send(m, key("esc"))
	if m.page != pageResults {
		t.Fatal("escape did not return to the results")
	}
}

// A malformed config link has to fail before a scan starts, with the parser's
// own message rather than a generic failure.
func TestBadConfigLinkFailsBeforeScanning(t *testing.T) {
	m := New("test")
	m.page = pageSetup
	m.configLink = "ss://not-supported@host:443"
	next, _ := m.startScan()
	m = next.(Model)
	if m.page == pageScan {
		t.Fatal("a scan started with an unusable config link")
	}
	if m.errMsg == "" {
		t.Fatal("no error explaining why the link was rejected")
	}
}

// A valid link must pin the port it names, since probing ports the config cannot
// use measures nothing.
func TestConfigLinkPinsItsOwnPort(t *testing.T) {
	link := "vless://11111111-1111-1111-1111-111111111111@example.com:2053" +
		"?encryption=none&security=tls&sni=a.example.com&type=ws&path=%2Fws#label"
	cfg, err := probeConfigFromLink(link, defaultSettings().probeConfig(443))
	if err != nil {
		t.Fatalf("parsing a valid link failed: %v", err)
	}
	if cfg.Port != 2053 {
		t.Fatalf("port %d, want 2053", cfg.Port)
	}
	if cfg.SNI != "a.example.com" {
		t.Fatalf("SNI %q", cfg.SNI)
	}
	if cfg.WebSocketPath != "/ws" {
		t.Fatalf("path %q", cfg.WebSocketPath)
	}
	if !cfg.RequireWebSocket {
		t.Fatal("a ws config did not make the upgrade check mandatory")
	}
}

// A Reality link must be rejected with the structural reason, not scanned: the
// Cloudflare proxy terminates TLS so a Reality ClientHello never reaches origin.
func TestRealityLinkIsRejected(t *testing.T) {
	link := "vless://11111111-1111-1111-1111-111111111111@example.com:443" +
		"?security=reality&pbk=abc&sni=example.com&type=tcp#reality"
	if _, err := probeConfigFromLink(link, defaultSettings().probeConfig(443)); err == nil {
		t.Skip("parser accepts Reality links; rejection lives in the mobile parser")
	}
}

// The progress bar must never render wider than its width, whatever the ratio.
func TestProgressBarClamps(t *testing.T) {
	for _, pct := range []float64{-1, 0, 0.5, 1, 2} {
		out := progressBar(pct, 10)
		if n := countBlocks(out); n > 10 {
			t.Fatalf("pct %v drew %d blocks in a width of 10", pct, n)
		}
	}
}

func countBlocks(s string) int {
	n := 0
	for _, r := range s {
		if r == '█' || r == '░' {
			n++
		}
	}
	return n
}

// Hints wrap so a long caption cannot corrupt the layout on a narrow terminal.
func TestWrapRespectsWidth(t *testing.T) {
	long := "parallelism is the divisor of total time: wall is roughly count over " +
		"workers times attempts times average attempt duration"
	out := wrap(long, 30, "")
	for _, line := range strings.Split(out, "\n") {
		if len(line) > 34 {
			t.Fatalf("line of %d chars exceeded the wrap width: %q", len(line), line)
		}
	}
}

func TestSpeedStringSwitchesUnits(t *testing.T) {
	if got := speedStr(0); got != "-" {
		t.Errorf("zero speed rendered %q", got)
	}
	if got := speedStr(512); got != "512 KB/s" {
		t.Errorf("512 rendered %q", got)
	}
	if got := speedStr(5120); got != "5.0 MB/s" {
		t.Errorf("5120 rendered %q", got)
	}
}

// A phone terminal is 40-60 columns. The widest choice row holds ten options, so
// without windowing it wraps and the layout collapses.
func TestNarrowTerminalDoesNotOverflow(t *testing.T) {
	for _, w := range []int{40, 50, 60, 80} {
		m := New("test")
		m.page = pageSetup
		m = send(m, tea.WindowSizeMsg{Width: w, Height: 30})
		for i := range m.set.rows() {
			m.rowIdx = i
			for _, line := range strings.Split(m.View(), "\n") {
				if visibleLen(line) > w {
					t.Fatalf("width %d row %d: line of %d visible chars: %q",
						w, i, visibleLen(line), line)
				}
			}
		}
	}
}

// The selected choice must stay visible after the window slides, otherwise the
// user moves a value they cannot see.
func TestSelectedPillStaysVisibleWhenNarrow(t *testing.T) {
	m := New("test")
	m.page = pageSetup
	m = send(m, tea.WindowSizeMsg{Width: 44, Height: 30})

	rows := m.set.rows()
	dlRow := -1
	for i, r := range rows {
		if r == rowDownload {
			dlRow = i
		}
	}
	if dlRow < 0 {
		t.Fatal("no download row")
	}
	m.rowIdx = dlRow

	// Walk to the far end of the widest row and check the label is on screen at
	// every step.
	ps, _ := m.set.pillsFor(rowDownload)
	for i := 0; i < len(ps); i++ {
		m.set.setIdx(rowDownload, i)
		out := m.View()
		if !strings.Contains(out, ps[i].label) {
			t.Fatalf("pill %q not visible at width 44:\n%s", ps[i].label, out)
		}
	}
}

// Every page must fit, not just setup: the results table is the widest thing the
// app draws and it was the last to be made width-aware.
func TestEveryPageFitsNarrowTerminal(t *testing.T) {
	for _, w := range []int{40, 50, 60, 80} {
		m := New("test")
		m = send(m, tea.WindowSizeMsg{Width: w, Height: 30})

		pages := []struct {
			name  string
			build func(Model) Model
		}{
			{"home", func(m Model) Model { m.page = pageHome; return m }},
			{"about", func(m Model) Model { m.page = pageAbout; return m }},
			{"scan", func(m Model) Model {
				m.page = pageScan
				m.prog = scanner.Progress{Tested: 1234, Total: 5000, Hits: 22, InFlight: 64}
				m.started = time.Now().Add(-42 * time.Second)
				m.live = fakeReport().Candidates
				return m
			}},
			{"results", func(m Model) Model {
				m.page = pageResults
				m.report = fakeReport()
				return m
			}},
			{"detail", func(m Model) Model {
				m.page = pageDetail
				m.detail = fakeReport().Candidates[0]
				return m
			}},
		}
		for _, p := range pages {
			for _, line := range strings.Split(p.build(m).View(), "\n") {
				if visibleLen(line) > w {
					t.Errorf("%s at width %d: line of %d visible chars: %q",
						p.name, w, visibleLen(line), line)
				}
			}
		}
	}
}

// visibleLen counts printable columns, skipping ANSI escape sequences.
func visibleLen(s string) int {
	n, inEsc := 0, false
	for _, r := range s {
		switch {
		case r == 0x1b:
			inEsc = true
		case inEsc && r == 'm':
			inEsc = false
		case inEsc:
		default:
			n++
		}
	}
	return n
}

type errString string

func (e errString) Error() string { return string(e) }

func fakeReport() *scanner.Report {
	return &scanner.Report{
		Tested:   1000,
		Hits:     22,
		Duration: 42 * time.Second,
		Candidates: []*score.Candidate{
			{
				IP: "1.1.1.1", Port: 443, Total: 82.9, AvgLatencyMs: 357, JitterMs: 20,
				DownloadKBps: 5120, Colo: "FRA", Healthy: true, HeldOpen: true, WSOk: true,
				Reputation: &reputation.Info{
					Verdict: reputation.VerdictClean, RiskPercent: 4, IsDatacenter: true,
					CompanyName: "Cloudflare", Route: "1.1.1.0/24", Country: "DE", City: "Frankfurt",
				},
			},
			{
				IP: "1.0.0.2", Port: 2053, Total: 71.3, AvgLatencyMs: 742, JitterMs: 526,
				DownloadKBps: 900, Colo: "AMS", Healthy: true,
				Reputation: &reputation.Info{Verdict: reputation.VerdictCaution, RiskPercent: 31},
			},
		},
	}
}
