// Package tui is the interactive terminal interface for the scanner: a menu, a
// setup page of preset pills, a live scan view and a results table.
//
// It exists because the flag-driven CLI requires the user to already know every
// knob and its cost. On a phone, typing a dozen flags is the friction that stops
// a scan happening at all.
package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Qezawat/IP-ROCKER/internal/cfranges"
	"github.com/Qezawat/IP-ROCKER/internal/netports"
	"github.com/Qezawat/IP-ROCKER/internal/reputation"
	"github.com/Qezawat/IP-ROCKER/internal/scanner"
	"github.com/Qezawat/IP-ROCKER/internal/score"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type page int

const (
	pageHome page = iota
	pageSetup
	pageConfigLink
	pageScan
	pageResults
	pageDetail
	pageAbout
)

// menu entries on the home page.
var menuItems = []struct{ label, desc string }{
	{"Quick scan", "sensible defaults, straight to a result"},
	{"Custom scan", "tune count, ports, timeout, sample size"},
	{"Scan with my config", "paste a vless:// or trojan:// link"},
	{"About", "what the score means"},
	{"Quit", ""},
}

// Model is the bubbletea model for the whole app.
type Model struct {
	version string
	page    page
	width   int
	height  int

	menuIdx int

	set     settings
	rowIdx  int // index into set.rows()
	editing bool
	input   textinput.Model
	// ta is the multiline editor for the custom-ranges paste, which a single
	// line cannot hold.
	ta      textarea.Model
	editRow setupRow
	errMsg  string

	configLink string
	linkNote   string

	// scan state
	cancel    context.CancelFunc
	progCh    chan scanner.Progress
	hitCh     chan *score.Candidate
	prog      scanner.Progress
	live      []*score.Candidate
	report    *scanner.Report
	scanErr   error
	started   time.Time
	spinFrame int

	resultIdx int
	detail    *score.Candidate
}

// New builds the initial model.
func New(version string) Model {
	ti := textinput.New()
	ti.Prompt = "  > "
	ti.CharLimit = 512

	ta := textarea.New()
	ta.Prompt = "  > "
	ta.Placeholder = "1.2.3.0/24\n5.6.7.8\n# my panel"
	ta.CharLimit = 0
	ta.ShowLineNumbers = false
	ta.SetWidth(60)
	ta.SetHeight(5)

	return Model{
		version: version,
		set:     defaultSettings(),
		input:   ti,
		ta:      ta,
	}
}

// Run starts the interactive interface.
func Run(version string) error {
	p := tea.NewProgram(New(version), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

type tickMsg time.Time
type progressMsg scanner.Progress
type hitMsg struct{ c *score.Candidate }
type streamClosedMsg struct{}
type doneMsg struct {
	report *scanner.Report
	err    error
}

func tick() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// waitProgress and waitHit turn a channel the scanner writes to into a stream of
// bubbletea messages. Each one re-arms itself, which is the supported way to
// bridge goroutine output into the update loop: calling Program.Send from a
// worker would race with the model.
func waitProgress(ch <-chan scanner.Progress) tea.Cmd {
	return func() tea.Msg {
		p, ok := <-ch
		if !ok {
			return streamClosedMsg{}
		}
		return progressMsg(p)
	}
}

func waitHit(ch <-chan *score.Candidate) tea.Cmd {
	return func() tea.Msg {
		c, ok := <-ch
		if !ok {
			return streamClosedMsg{}
		}
		return hitMsg{c: c}
	}
}

func (m Model) Init() tea.Cmd { return tick() }

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tickMsg:
		m.spinFrame++
		return m, tick()

	case progressMsg:
		m.prog = scanner.Progress(msg)
		return m, waitProgress(m.progCh)

	case hitMsg:
		m.live = append(m.live, msg.c)
		return m, waitHit(m.hitCh)

	case streamClosedMsg:
		return m, nil

	case doneMsg:
		m.report, m.scanErr = msg.report, msg.err
		m.cancel = nil
		m.page = pageResults
		m.resultIdx = 0
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Text entry owns every key except the accept/cancel pair. The ranges paste
	// is a multiline field, so there enter inserts a newline and ctrl+d accepts;
	// everywhere else enter accepts and the field is single-line.
	if m.editing {
		if m.editRow == rowRangesList {
			switch k.String() {
			case "esc":
				m.editing = false
				m.errMsg = ""
				return m, nil
			case "ctrl+d":
				if err := m.set.applyCustom(m.editRow, m.ta.Value()); err != nil {
					m.errMsg = err.Error()
					return m, nil
				}
				m.editing = false
				m.errMsg = ""
				return m, nil
			}
			var cmd tea.Cmd
			m.ta, cmd = m.ta.Update(k)
			return m, cmd
		}
		switch k.String() {
		case "esc":
			m.editing = false
			m.errMsg = ""
			return m, nil
		case "enter":
			if m.page == pageConfigLink {
				m.configLink = strings.TrimSpace(m.input.Value())
				m.editing = false
				m.page = pageSetup
				return m, nil
			}
			if err := m.set.applyCustom(m.editRow, m.input.Value()); err != nil {
				m.errMsg = err.Error()
				return m, nil
			}
			m.editing = false
			m.errMsg = ""
			return m, nil
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(k)
		return m, cmd
	}

	switch m.page {
	case pageHome:
		return m.keyHome(k)
	case pageSetup:
		return m.keySetup(k)
	case pageConfigLink:
		return m.keySetup(k)
	case pageScan:
		switch k.String() {
		case "esc", "q", "ctrl+c":
			if m.cancel != nil {
				m.cancel()
			}
			return m, nil
		}
	case pageResults:
		return m.keyResults(k)
	case pageDetail:
		switch k.String() {
		case "esc", "q", "left", "h":
			m.page = pageResults
		case "ctrl+c":
			return m, tea.Quit
		}
	case pageAbout:
		switch k.String() {
		case "esc", "q", "enter":
			m.page = pageHome
		case "ctrl+c":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m Model) keyHome(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "up", "k":
		if m.menuIdx > 0 {
			m.menuIdx--
		}
	case "down", "j":
		if m.menuIdx < len(menuItems)-1 {
			m.menuIdx++
		}
	case "enter":
		switch m.menuIdx {
		case 0:
			m.set = defaultSettings()
			return m.startScan()
		case 1:
			m.page = pageSetup
			m.rowIdx = 0
		case 2:
			m.page = pageConfigLink
			m.input.SetValue(m.configLink)
			m.input.Placeholder = "vless://...@host:443?type=ws&path=/..."
			m.input.Focus()
			m.editing = true
		case 3:
			m.page = pageAbout
		case 4:
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m Model) keySetup(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	rows := m.set.rows()
	if m.rowIdx >= len(rows) {
		m.rowIdx = len(rows) - 1
	}
	row := rows[m.rowIdx]
	ps, idx := m.set.pillsFor(row)

	switch k.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc", "q":
		m.page = pageHome
	case "up", "k":
		if m.rowIdx > 0 {
			m.rowIdx--
		}
	case "down", "j":
		if m.rowIdx < len(rows)-1 {
			m.rowIdx++
		}
	case "left", "h":
		if idx > 0 {
			m.set.setIdx(row, idx-1)
		}
	case "right", "l":
		if idx < len(ps)-1 {
			m.set.setIdx(row, idx+1)
		}
	case "c":
		// A row with a custom slot jumps straight to it. A free-entry row (the
		// custom ranges paste) opens the editor directly.
		if len(ps) > 0 && ps[len(ps)-1].custom {
			m.set.setIdx(row, len(ps)-1)
			return m.openEditor(row)
		}
		if prompt, _ := m.set.customPrompt(row); prompt != "" {
			return m.openEditor(row)
		}
	case "enter":
		if prompt, _ := m.set.customPrompt(row); prompt != "" {
			return m.openEditor(row)
		}
		return m.startScan()
	case "s":
		return m.startScan()
	}
	return m, nil
}

func (m Model) openEditor(row setupRow) (tea.Model, tea.Cmd) {
	_, initial := m.set.customPrompt(row)
	m.editRow = row
	if row == rowRangesList {
		m.ta.SetValue(initial)
		if m.width > 0 {
			m.ta.SetWidth(max(20, m.width-6))
			// Six lines keeps a pasted block in view without burying the setup
			// page beneath it on a short phone screen.
			m.ta.SetHeight(min(6, max(3, m.height-16)))
		}
		m.ta.Focus()
		m.editing = true
		return m, nil
	}
	m.input.SetValue(initial)
	m.input.Placeholder = ""
	m.input.CursorEnd()
	m.input.Focus()
	m.editing = true
	return m, nil
}

func (m Model) keyResults(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	clean := m.cleanList()
	switch k.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc":
		m.page = pageHome
	case "up", "k":
		if m.resultIdx > 0 {
			m.resultIdx--
		}
	case "down", "j":
		if m.resultIdx < len(clean)-1 {
			m.resultIdx++
		}
	case "enter", "right", "l":
		if m.resultIdx < len(clean) {
			m.detail = clean[m.resultIdx]
			m.page = pageDetail
		}
	case "w":
		if err := m.writeList(); err != nil {
			m.errMsg = err.Error()
		} else {
			m.errMsg = ""
		}
	case "r":
		return m.startScan()
	}
	return m, nil
}

func (m Model) cleanList() []*score.Candidate {
	if m.report == nil {
		return nil
	}
	if c := m.report.Clean(); len(c) > 0 {
		return c
	}
	return m.report.Candidates
}

// writeList saves the clean endpoints next to the working directory, which is
// what the user actually wants to paste into a panel.
func (m *Model) writeList() error {
	clean := m.cleanList()
	if len(clean) == 0 {
		return fmt.Errorf("nothing to write")
	}
	name := fmt.Sprintf("iprocker-%s.txt", time.Now().Format("20060102-150405"))
	var b strings.Builder
	for _, c := range clean {
		fmt.Fprintf(&b, "%s:%d\n", c.IP, c.Port)
	}
	if err := os.WriteFile(name, []byte(b.String()), 0o644); err != nil {
		return err
	}
	m.linkNote = "saved to " + name
	return nil
}

// ---------------------------------------------------------------------------
// Running a scan
// ---------------------------------------------------------------------------

func (m Model) startScan() (tea.Model, tea.Cmd) {
	ports, err := netports.Parse(m.set.ports(), 443)
	if err != nil {
		m.errMsg = err.Error()
		return m, nil
	}

	// Custom ranges were validated when the paste was accepted, but re-parsing
	// here keeps startScan self-contained: a rangesText set another way cannot
	// silently produce a scan of the wrong scope.
	extraCIDRs, err := m.set.ranges()
	if err != nil {
		m.errMsg = err.Error()
		return m, nil
	}
	if m.set.rangesIdx == 2 && len(extraCIDRs) == 0 {
		m.errMsg = "only-custom is selected but no ranges are pasted (edit the Custom row)"
		return m, nil
	}

	probeCfg := m.set.probeConfig(ports[0])

	// A config link pins SNI, host, path and port to the user's real front, so
	// the scan measures exactly the path their traffic will take. Parsing it here
	// means a malformed link fails before any probe is sent.
	if link := strings.TrimSpace(m.configLink); link != "" {
		probeCfg, err = probeConfigFromLink(link, probeCfg)
		if err != nil {
			m.errMsg = err.Error()
			return m, nil
		}
		ports = []int{probeCfg.Port}
	}

	opts := scanner.Options{
		Count:       m.set.count(),
		Concurrency: m.set.workers(),
		Ports:       ports,
		Probe:       probeCfg,
		Criteria:    m.set.criteria(),
		Ranges: cfranges.Options{
			IPv4:       true,
			SkipDirty:  true,
			ExtraCIDRs: extraCIDRs,
			OnlyExtra:  m.set.rangesIdx == 2,
		},
		SkipReputation: !m.set.reputation(),
	}

	// Buffered and non-blocking: a scan must never stall because the UI is mid
	// frame, and a dropped progress tick costs nothing since the next one carries
	// the same cumulative counters.
	progCh := make(chan scanner.Progress, 256)
	hitCh := make(chan *score.Candidate, 256)
	opts.Report = func(p scanner.Progress) {
		select {
		case progCh <- p:
		default:
		}
	}
	opts.OnHit = func(c *score.Candidate) {
		select {
		case hitCh <- c:
		default:
		}
	}

	m.live = nil
	m.report = nil
	m.scanErr = nil
	m.prog = scanner.Progress{}
	m.started = time.Now()
	m.page = pageScan
	m.errMsg = ""
	m.linkNote = ""
	m.progCh = progCh
	m.hitCh = hitCh

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	run := func() tea.Msg {
		rep, err := scanner.New(opts).Run(ctx)
		return doneMsg{report: rep, err: err}
	}

	return m, tea.Batch(run, waitProgress(progCh), waitHit(hitCh), tick())
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

func (m Model) View() string {
	switch m.page {
	case pageHome:
		return m.viewHome()
	case pageSetup, pageConfigLink:
		return m.viewSetup()
	case pageScan:
		return m.viewScan()
	case pageResults:
		return m.viewResults()
	case pageDetail:
		return m.viewDetail()
	case pageAbout:
		return m.viewAbout()
	}
	return ""
}

func (m Model) viewHome() string {
	var sb strings.Builder
	sb.WriteString(banner(m.width))
	sb.WriteString("\n\n")
	sb.WriteString(styDim.Render("  clean Cloudflare edge finder · " + m.version))
	sb.WriteString("\n\n")

	// The description only fits beside the label on a wide terminal. On a phone
	// it goes under the selected entry instead of being wrapped or clipped.
	inline := m.width <= 0 || m.width >= 80
	for i, it := range menuItems {
		cursor := "   "
		label := styText.Render(fmt.Sprintf("%-22s", it.label))
		if i == m.menuIdx {
			cursor = styAccent.Render(" ▸ ")
			label = stySelected.Render(fmt.Sprintf("%-22s", it.label))
		}
		line := "  " + cursor + label
		if it.desc != "" && inline {
			line += "  " + styDim.Render(it.desc)
		}
		sb.WriteString(line + "\n")
		if it.desc != "" && !inline && i == m.menuIdx {
			sb.WriteString("      " + styDim.Render(wrap(it.desc, m.proseWidth(6), "      ")) + "\n")
		}
	}
	sb.WriteString("\n")
	sb.WriteString(m.keyHint("↑/↓ move", "enter select", "q quit"))
	sb.WriteString("\n")
	return sb.String()
}

func (m Model) viewSetup() string {
	var sb strings.Builder
	sb.WriteString(styTitle.Render("\n  IP-ROCKER · scan setup") + "\n")
	sb.WriteString(styDim.Render("  "+strings.Repeat("─", m.ruleWidth(66))) + "\n\n")

	if m.page == pageConfigLink || m.configLink != "" {
		shown := m.configLink
		if m.editing && m.page == pageConfigLink {
			sb.WriteString("  " + styText.Render("Paste your config link:") + "\n")
			sb.WriteString(m.input.View() + "\n\n")
			sb.WriteString(styHint.Render("  enter accept   esc cancel") + "\n")
			return sb.String()
		}
		if shown != "" {
			sb.WriteString("  " + styAccent.Render("config: ") + styText.Render(linkSummary(shown)) + "\n")
			sb.WriteString(styDim.Render("  SNI, host, path and port come from the link; the ports row is ignored") + "\n\n")
		}
	}

	rows := m.set.rows()
	if m.rowIdx >= len(rows) {
		m.rowIdx = len(rows) - 1
	}

	for i, r := range rows {
		ps, idx := m.set.pillsFor(r)
		marker := "   "
		label := styDim.Render(fmt.Sprintf("%-11s", rowLabel(r)))
		if i == m.rowIdx {
			marker = styAccent.Render(" ▸ ")
			label = styHead.Render(fmt.Sprintf("%-11s", rowLabel(r)))
		}
		sb.WriteString("  " + marker + label + renderPills(ps, idx, m.pillBudget()) + "\n")
		if i == m.rowIdx {
			sb.WriteString("      " + styHint.Render(wrap(m.set.hintFor(r), m.proseWidth(6), "      ")) + "\n")
		}
	}

	sb.WriteString("\n  " + styAccent.Render("cost: ") +
		styText.Render(wrap(m.set.costLine(), m.proseWidth(8), "        ")) + "\n")

	if m.editing {
		prompt, _ := m.set.customPrompt(m.editRow)
		sb.WriteString("\n  " + styText.Render(prompt) + "\n")
		if m.editRow == rowRangesList {
			sb.WriteString(m.ta.View() + "\n")
			sb.WriteString(styHint.Render("  enter newline   ctrl+d accept   esc cancel") + "\n")
		} else {
			sb.WriteString(m.input.View() + "\n")
			sb.WriteString(styHint.Render("  enter accept   esc cancel") + "\n")
		}
	}
	if m.errMsg != "" {
		sb.WriteString("\n  " + styBad.Render("! "+m.errMsg) + "\n")
	}

	sb.WriteString("\n" + m.keyHint("↑/↓ row", "←/→ value", "c custom", "s start", "esc back") + "\n")
	return sb.String()
}

func (m Model) viewScan() string {
	var sb strings.Builder
	spin := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}[m.spinFrame%10]

	sb.WriteString(styTitle.Render("\n  IP-ROCKER · scanning") + "\n")
	sb.WriteString(styDim.Render("  "+strings.Repeat("─", m.ruleWidth(66))) + "\n\n")

	phase := m.prog.Phase.String()
	sb.WriteString(fmt.Sprintf("  %s  %s\n\n", styAccent.Render(spin), styHead.Render(phase)))

	pct := 0.0
	if m.prog.Total > 0 {
		pct = float64(m.prog.Tested) / float64(m.prog.Total)
		if pct > 1 {
			pct = 1
		}
	}
	sb.WriteString("  " + progressBar(pct, m.barWidth()) + fmt.Sprintf("  %3.0f%%\n\n", pct*100))

	if m.width > 0 && m.width < 58 {
		sb.WriteString(fmt.Sprintf("  tested %s   answered %s\n  in flight %d   elapsed %s\n\n",
			styText.Render(humanInt(int(m.prog.Tested))),
			styGood.Render(humanInt(int(m.prog.Hits))),
			m.prog.InFlight,
			time.Since(m.started).Round(time.Second)))
	} else {
		sb.WriteString(fmt.Sprintf("  tested %s   answered %s   in flight %d   elapsed %s\n\n",
			styText.Render(humanInt(int(m.prog.Tested))),
			styGood.Render(humanInt(int(m.prog.Hits))),
			m.prog.InFlight,
			time.Since(m.started).Round(time.Second)))
	}

	if m.prog.Message != "" {
		sb.WriteString("  " + styWarn.Render("! "+m.prog.Message) + "\n\n")
	}

	if len(m.live) > 0 {
		// The full row needs ~52 columns. Below that the colo and port are the
		// first things to go, since latency and throughput are what the user is
		// watching while the scan runs.
		wide := m.width <= 0 || m.width >= 54
		if wide {
			sb.WriteString(styHead.Render(fmt.Sprintf("  %-16s %-6s %-9s %-9s %s", "IP", "PORT", "LATENCY", "DOWNLOAD", "COLO")) + "\n")
		} else {
			sb.WriteString(styHead.Render(fmt.Sprintf("  %-16s %-8s %s", "IP", "LATENCY", "DOWN")) + "\n")
		}
		start := 0
		if len(m.live) > 10 {
			start = len(m.live) - 10
		}
		for _, c := range m.live[start:] {
			if wide {
				sb.WriteString(fmt.Sprintf("  %-16s %-6d %-9s %-9s %s\n",
					c.IP, c.Port, msStr(c.AvgLatencyMs), speedStr(c.DownloadKBps), orDash(c.Colo)))
			} else {
				sb.WriteString(fmt.Sprintf("  %-16s %-8s %s\n",
					c.IP, msStr(c.AvgLatencyMs), speedStr(c.DownloadKBps)))
			}
		}
	} else {
		sb.WriteString(styDim.Render("  no address has answered yet") + "\n")
	}

	sb.WriteString("\n" + m.keyHint("esc cancel the scan") + "\n")
	return sb.String()
}

func (m Model) viewResults() string {
	var sb strings.Builder
	sb.WriteString(styTitle.Render("\n  IP-ROCKER · results") + "\n")
	sb.WriteString(styDim.Render("  "+strings.Repeat("─", m.ruleWidth(78))) + "\n\n")

	if m.scanErr != nil {
		sb.WriteString("  " + styBad.Render("scan failed: "+m.scanErr.Error()) + "\n\n")
		sb.WriteString(styHint.Render("  esc back   r retry") + "\n")
		return sb.String()
	}
	if m.report == nil {
		return sb.String()
	}

	clean := m.report.Clean()
	sep := " — "
	if m.width > 0 && m.width < 48 {
		sep = "\n  "
	}
	sb.WriteString(fmt.Sprintf("  probed %s in %s%s%s answered, %s usable\n\n",
		styText.Render(humanInt(int(m.report.Tested))),
		m.report.Duration.Round(time.Millisecond), sep,
		styText.Render(humanInt(int(m.report.Hits))),
		styGood.Render(humanInt(len(clean)))))

	list := m.cleanList()
	if len(list) == 0 {
		sb.WriteString("  " + styWarn.Render("nothing answered. Try a longer timeout or more addresses.") + "\n\n")
		sb.WriteString(styHint.Render("  esc back   r retry") + "\n")
		return sb.String()
	}
	if len(clean) == 0 {
		sb.WriteString("  " + styWarn.Render("no address passed every requirement; showing best attempts") + "\n\n")
	}

	// The full table needs ~85 columns. A phone gets IP, score, latency and the
	// verdict mark; everything else is one keypress away on the detail page.
	wide := m.width <= 0 || m.width >= 88
	if wide {
		sb.WriteString(styHead.Render(fmt.Sprintf("  %-16s %-5s %-6s %-8s %-8s %-10s %-5s %-6s %s",
			"IP", "PORT", "SCORE", "LATENCY", "JITTER", "DOWNLOAD", "COLO", "RISK", "")) + "\n")
	} else {
		sb.WriteString(styHead.Render(fmt.Sprintf("  %-16s %-5s %-7s %s",
			"IP", "SCORE", "PING", "")) + "\n")
	}

	limit := m.set.topN()
	if limit <= 0 || limit > len(list) {
		limit = len(list)
	}
	// Keep the selected row on screen on a short terminal.
	from := 0
	visible := 14
	if m.resultIdx >= visible {
		from = m.resultIdx - visible + 1
	}
	for i := from; i < limit && i < from+visible; i++ {
		c := list[i]
		row := fmt.Sprintf("%-16s %-5.1f %-7s %s",
			c.IP, c.Total, msStr(c.AvgLatencyMs), shortVerdict(c))
		if wide {
			row = fmt.Sprintf("%-16s %-5d %-6.1f %-8s %-8s %-10s %-5s %-6s %s",
				c.IP, c.Port, c.Total, msStr(c.AvgLatencyMs), msStr(c.JitterMs),
				speedStr(c.DownloadKBps), orDash(c.Colo), riskStr(c.Reputation), verdictMark(c))
		}
		if i == m.resultIdx {
			sb.WriteString(styAccent.Render(" ▸") + stySelected.Render(row) + "\n")
		} else {
			sb.WriteString("  " + styText.Render(row) + "\n")
		}
	}

	if m.report.ReputationError != "" {
		sb.WriteString("\n  " + styWarn.Render("reputation check failed: "+m.report.ReputationError) + "\n")
		sb.WriteString("  " + styDim.Render("addresses above are usable on measurement alone, not verified clean") + "\n")
	}
	if m.linkNote != "" {
		sb.WriteString("\n  " + styGood.Render(m.linkNote) + "\n")
	}
	if m.errMsg != "" {
		sb.WriteString("\n  " + styBad.Render("! "+m.errMsg) + "\n")
	}

	sb.WriteString("\n" + m.keyHint("↑/↓ move", "enter details", "w write list", "r rescan", "esc menu") + "\n")
	return sb.String()
}

func (m Model) viewDetail() string {
	c := m.detail
	if c == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(styTitle.Render(fmt.Sprintf("\n  %s:%d", c.IP, c.Port)) + "\n")
	sb.WriteString(styDim.Render("  "+strings.Repeat("─", m.ruleWidth(66))) + "\n\n")

	// The key column shrinks on a phone so the value still fits beside it.
	keyw := 18
	if m.width > 0 && m.width < 56 {
		keyw = 12
	}
	line := func(k, v string) {
		sb.WriteString(fmt.Sprintf("  %-*s %s\n", keyw, styDim.Render(k), v))
	}
	line("score", fmt.Sprintf("%.1f / 100", c.Total))
	line("latency", fmt.Sprintf("%s avg, %s best", msStr(c.AvgLatencyMs), msStr(c.MinLatencyMs)))
	line("jitter", msStr(c.JitterMs))
	line("loss", fmt.Sprintf("%.0f%%", c.LossPercent))
	line("download", speedStr(c.DownloadKBps))
	if c.UploadKBps > 0 {
		line("upload", speedStr(c.UploadKBps))
	}
	line("colo", orDash(c.Colo))
	line("held open", yesNo(c.HeldOpen))
	line("websocket", yesNo(c.WSOk))

	if r := c.Reputation; r != nil && r.Err == "" {
		sb.WriteString("\n")
		line("verdict", fmt.Sprintf("%s %s", r.Verdict.Emoji(), r.Verdict))
		line("risk", fmt.Sprintf("%.1f%%", r.RiskPercent))
		line("abuser", yesNo(r.IsAbuser))
		line("proxy", yesNo(r.IsProxy))
		// Every edge is a datacentre address, so this is stated as expected
		// rather than as a fault.
		if m.width > 0 && m.width < 56 {
			line("datacenter", yesNo(r.IsDatacenter))
			sb.WriteString("  " + styDim.Render("(expected for Cloudflare)") + "\n")
		} else {
			line("datacenter", yesNo(r.IsDatacenter)+styDim.Render("  (expected for Cloudflare)"))
		}
		line("route", orDash(r.Route))
		line("company", orDash(r.CompanyName))
		line("abuse score", fmt.Sprintf("%.2f", r.CompanyAbuse))
		line("location", fmt.Sprintf("%s %s", orDash(r.Country), orDash(r.City)))
	} else if c.Reputation != nil && c.Reputation.Err != "" {
		sb.WriteString("\n  " + styWarn.Render("reputation lookup failed: "+c.Reputation.Err) + "\n")
		sb.WriteString("  " + styDim.Render("this address is not confirmed clean") + "\n")
	}

	if len(c.Notes) > 0 {
		sb.WriteString("\n")
		for _, n := range c.Notes {
			sb.WriteString("  " + styWarn.Render("• "+n) + "\n")
		}
	}

	sb.WriteString("\n" + m.keyHint("esc back") + "\n")
	return sb.String()
}

func (m Model) viewAbout() string {
	// The prose is wrapped at render time rather than hard-wrapped in literals,
	// because the same text has to fit both a 40-column phone and a desktop.
	w := m.proseWidth(2)
	para := func(s string) string { return wrap(s, w, "  ") }
	// A hanging indent costs its own width on every continuation line, so the
	// wrap budget has to be reduced by it or the block overflows on the right.
	weight := func(name, pct, text string) string {
		head := fmt.Sprintf("%-11s%s", name, pct)
		if m.width > 0 && m.width < 62 {
			// The body is indented under its own heading, first line included.
			return head + "\n    " + wrap(text, w-4, "    ")
		}
		const hang = "                  "
		return wrap(head+"  "+text, w-len(hang)+2, hang)
	}

	body := []string{
		styHead.Render("How an address is ranked"),
		"",
		weight("reputation", "35%", "ipapi.is abuse/proxy flags per address and per route."),
		weight("latency", "25%", "scored against the other addresses in this same scan, not "+
			"against a fixed scale. On a censored mobile path a reply faster than "+
			"the physics allows is a middlebox answering for the edge, so it is "+
			"not rewarded."),
		weight("stability", "20%", "jitter, loss and surviving an idle hold."),
		weight("download", "15%", "a real payload transfer through the edge."),
		weight("upload", "5%", "upstream capacity, when enabled."),
		"",
		styHead.Render("Why a bigger timeout can be better"),
		"",
		para("Timeout is a ceiling on waiting, not a fixed cost: a 250 ms edge " +
			"takes 250 ms whether the ceiling is 500 ms or 2500 ms. It is only " +
			"spent on failures. On a long path healthy edges answer near " +
			"700-800 ms, so a 500 ms ceiling returns nothing at all. Speed comes " +
			"from workers, which divide the total time; attempts only measure " +
			"loss and jitter."),
		"",
		styHead.Render("Flags"),
		"",
		para("datacenter is expected — every Cloudflare edge is one."),
		para("An address whose reputation lookup failed is never called clean."),
	}
	return "\n  " + strings.Join(body, "\n  ") + "\n\n" + m.keyHint("esc back") + "\n"
}

// ---------------------------------------------------------------------------
// Small render helpers
// ---------------------------------------------------------------------------

// renderPills draws a row of choices, windowed to a character budget.
//
// A phone terminal is often 40-60 columns and the widest row here holds ten
// choices, so drawing them all unconditionally wraps and destroys the layout.
// The window slides to keep the selection visible and shows ‹ › when there is
// more to either side.
func renderPills(ps []pill, sel, budget int) string {
	if budget <= 0 {
		budget = 1 << 30
	}
	width := func(p pill) int { return len(p.label) + 3 }

	// Grow a window outward from the selection until the budget is spent.
	from, to := sel, sel+1
	used := width(ps[sel])
	for from > 0 || to < len(ps) {
		grew := false
		if to < len(ps) && used+width(ps[to]) <= budget {
			used += width(ps[to])
			to++
			grew = true
		}
		if from > 0 && used+width(ps[from-1]) <= budget {
			used += width(ps[from-1])
			from--
			grew = true
		}
		if !grew {
			break
		}
	}

	var sb strings.Builder
	if from > 0 {
		sb.WriteString(styDim.Render("‹ "))
	}
	for i := from; i < to; i++ {
		txt := " " + ps[i].label + " "
		if i == sel {
			sb.WriteString(styPillOn.Render(txt))
		} else {
			sb.WriteString(styPillOff.Render(txt))
		}
		sb.WriteString(" ")
	}
	if to < len(ps) {
		sb.WriteString(styDim.Render("›"))
	}
	return sb.String()
}

// pillBudget is the character room left for choices after the label gutter.
// Zero width (before the first WindowSizeMsg) means no limit, which matches a
// full-size terminal and keeps tests independent of terminal size.
func (m Model) pillBudget() int {
	if m.width <= 0 {
		return 0
	}
	// 16 columns go to the indent, marker and label gutter; 3 more are reserved
	// for the ‹ › overflow arrows.
	b := m.width - 20
	if b < 12 {
		b = 12
	}
	return b
}

// proseWidth is the wrap width for a block indented by indent columns.
//
// It subtracts twice the indent, not once: lipgloss pads every line of a
// multi-line block out to the widest one, so a continuation line already
// carrying the indent gets the outer prefix added on top of it.
func (m Model) proseWidth(indent int) int {
	if m.width <= 0 {
		return 62
	}
	w := m.width - 2*indent
	if w < 20 {
		w = 20
	}
	return w
}

// ruleWidth sizes the horizontal rule to the terminal instead of a fixed 66,
// which overflows a 40-column phone terminal and wraps into a second line.
func (m Model) ruleWidth(max int) int {
	if m.width <= 0 {
		return max
	}
	w := m.width - 2
	if w > max {
		w = max
	}
	if w < 8 {
		w = 8
	}
	return w
}

// barWidth keeps the progress bar and its percentage on one line.
func (m Model) barWidth() int {
	if m.width <= 0 {
		return 46
	}
	w := m.width - 14
	if w < 10 {
		w = 10
	}
	if w > 60 {
		w = 60
	}
	return w
}

// progressBar clamps in both directions. A negative ratio is reachable in
// practice: the neighbour-expansion phase resets Tested before Total, so a frame
// rendered in between would panic on a negative repeat count.
func progressBar(pct float64, width int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 1 {
		pct = 1
	}
	filled := int(pct * float64(width))
	if filled > width {
		filled = width
	}
	return styAccent.Render(strings.Repeat("█", filled)) +
		styDim.Render(strings.Repeat("░", width-filled))
}

func msStr(v float64) string {
	if v <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.0fms", v)
}

func speedStr(kbps float64) string {
	switch {
	case kbps <= 0:
		return "-"
	case kbps >= 1024:
		return fmt.Sprintf("%.1f MB/s", kbps/1024)
	default:
		return fmt.Sprintf("%.0f KB/s", kbps)
	}
}

func riskStr(r *reputation.Info) string {
	if r == nil || r.Err != "" {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%%", r.RiskPercent)
}

// shortVerdict is a single glyph, for the narrow results table where the word
// would not fit beside the address.
func shortVerdict(c *score.Candidate) string {
	if c.Reputation == nil || c.Reputation.Err != "" {
		return styDim.Render("?")
	}
	switch c.Reputation.Verdict {
	case reputation.VerdictClean:
		return styGood.Render("ok")
	case reputation.VerdictCaution:
		return styWarn.Render("!")
	case reputation.VerdictDirty:
		return styBad.Render("x")
	}
	return styDim.Render("?")
}

func verdictMark(c *score.Candidate) string {
	if c.Reputation == nil || c.Reputation.Err != "" {
		return styDim.Render("unrated")
	}
	switch c.Reputation.Verdict {
	case reputation.VerdictClean:
		return styGood.Render("clean")
	case reputation.VerdictCaution:
		return styWarn.Render("caution")
	case reputation.VerdictDirty:
		return styBad.Render("dirty")
	}
	return styDim.Render("unknown")
}

func yesNo(b bool) string {
	if b {
		return styGood.Render("yes")
	}
	return styDim.Render("no")
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// keyHint renders a footer of key bindings, packing as many as fit per line.
//
// A single joined string overflows a 40-column terminal and wraps mid-binding,
// which reads as garbage; packing whole bindings keeps each one intact.
func (m Model) keyHint(items ...string) string {
	width := m.width
	if width <= 0 {
		width = 100
	}
	var lines []string
	cur := ""
	for _, it := range items {
		next := it
		if cur != "" {
			next = cur + "   " + it
		}
		if len(next)+2 > width && cur != "" {
			lines = append(lines, "  "+cur)
			cur = it
			continue
		}
		cur = next
	}
	if cur != "" {
		lines = append(lines, "  "+cur)
	}
	return styHint.Render(strings.Join(lines, "\n"))
}

// wrap breaks a hint across lines so a long caption does not corrupt the layout
// on a narrow phone terminal.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	cur := words[0]
	for _, w := range words[1:] {
		if len(cur)+1+len(w) > width {
			lines = append(lines, cur)
			cur = w
			continue
		}
		cur += " " + w
	}
	lines = append(lines, cur)
	return strings.Join(lines, "\n"+indent)
}
