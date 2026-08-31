package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Qezawat/IP-ROCKER/internal/cfranges"
	"github.com/Qezawat/IP-ROCKER/internal/probe"
	"github.com/Qezawat/IP-ROCKER/internal/score"
)

// setupRow identifies a tunable line on the setup page. Order is display order.
type setupRow int

const (
	rowCount setupRow = iota
	rowWorkers
	rowPorts
	rowTimeout
	rowTries
	rowDownload
	rowMinSpeed
	rowUpload
	rowStrict
	rowTopN
	rowRanges
	rowRangesList
)

// pill is one choice on a setup row. A zero Custom marks the free-entry slot.
type pill struct {
	label  string
	custom bool
}

func pills(labels ...string) []pill {
	out := make([]pill, 0, len(labels))
	for _, l := range labels {
		out = append(out, pill{label: l})
	}
	return out
}

func withCustom(p []pill) []pill { return append(p, pill{label: "Custom", custom: true}) }

// Preset tables. These are deliberately generous at the top end: a wide sweep
// with a large sample is how a rare clean block gets found and proven, and the
// UI warns about the cost instead of forbidding it.
var (
	countPills    = withCustom(pills("500", "1,000", "2,500", "5,000", "10,000", "20,000"))
	countValues   = []int{500, 1000, 2500, 5000, 10000, 20000}
	workerPills   = withCustom(pills("50", "100", "200", "300", "500"))
	workerValues  = []int{50, 100, 200, 300, 500}
	portPills     = pills("443", "443,2053", "443,2053,8443", "all (6 ports)")
	portValues    = []string{"443", "443,2053", "443,2053,8443", "all"}
	timeoutPills  = pills("400ms", "1s", "2s", "2.5s", "4s", "6s", "10s")
	timeoutValues = []time.Duration{
		400 * time.Millisecond, time.Second, 2 * time.Second,
		2500 * time.Millisecond, 4 * time.Second, 6 * time.Second, 10 * time.Second,
	}
	triesPills  = pills("1", "2", "3", "4", "6")
	triesValues = []int{1, 2, 3, 4, 6}
	// Download sample reaches 20 MB. A 256 KB sample cannot tell a 1 MB/s
	// middlebox from a 5 MB/s edge, which is the whole point of the test.
	downloadPills  = withCustom(pills("Off", "128 KB", "256 KB", "512 KB", "1 MB", "2 MB", "5 MB", "10 MB", "20 MB"))
	downloadValues = []int64{0, 128 << 10, 256 << 10, 512 << 10, 1 << 20, 2 << 20, 5 << 20, 10 << 20, 20 << 20}
	// Speed floor reaches 5 MB/s so the field observation "usable edges pull
	// 5 MB/s" can actually be expressed as a filter.
	minSpeedPills  = withCustom(pills("Off", "100 KB/s", "250 KB/s", "500 KB/s", "1 MB/s", "2 MB/s", "5 MB/s"))
	minSpeedValues = []float64{0, 100, 250, 500, 1000, 2000, 5000}
	uploadPills    = pills("Off", "128 KB", "512 KB", "1 MB", "2 MB")
	uploadValues   = []int64{0, 128 << 10, 512 << 10, 1 << 20, 2 << 20}
	onOffPills     = pills("On", "Off")
	offOnPills     = pills("Off", "On")
	topPills       = pills("10", "25", "50", "100", "All")
	topValues      = []int{10, 25, 50, 100, 0}
	// Ranges scope: 0 = built-in Cloudflare ranges, 1 = built-in plus the
	// pasted list, 2 = the pasted list alone.
	rangesPills = pills("Full CF ranges", "Add custom", "Only custom")
)

// settings is the setup page's state: an index per row plus any custom entry.
type settings struct {
	countIdx    int
	countCustom int
	workerIdx   int
	workerCust  int
	portIdx     int
	timeoutIdx  int
	triesIdx    int
	dlIdx       int
	dlCustomMB  float64
	minIdx      int
	minCustom   float64
	upIdx       int
	strictIdx   int // 0 = off
	topIdx      int
	// rangesIdx picks the scan scope; rangesText is the pasted IP/CIDR list.
	rangesIdx  int
	rangesText string
}

func defaultSettings() settings {
	return settings{
		countIdx:   1, // 1,000
		workerIdx:  1, // 100
		portIdx:    0,
		timeoutIdx: 3, // 2.5s — a healthy edge on a censored mobile path answers near 700-800 ms
		triesIdx:   2, // 3
		dlIdx:      5, // 2 MB
		minIdx:     0,
		upIdx:      0,
		strictIdx:  0,
		topIdx:     1,
		rangesIdx:  0,
	}
}

func (s settings) count() int {
	if s.countIdx == len(countPills)-1 {
		if s.countCustom > 0 {
			return s.countCustom
		}
		return countValues[0]
	}
	return countValues[s.countIdx]
}

func (s settings) workers() int {
	if s.workerIdx == len(workerPills)-1 {
		if s.workerCust > 0 {
			return s.workerCust
		}
		return workerValues[0]
	}
	return workerValues[s.workerIdx]
}

func (s settings) ports() string { return portValues[s.portIdx] }

func (s settings) timeout() time.Duration { return timeoutValues[s.timeoutIdx] }

func (s settings) tries() int { return triesValues[s.triesIdx] }

// downloadBytes returns the sample size, honouring a custom value given in MB.
func (s settings) downloadBytes() int64 {
	if s.dlIdx == len(downloadPills)-1 {
		if s.dlCustomMB > 0 {
			return int64(s.dlCustomMB * float64(1<<20))
		}
		return 0
	}
	return downloadValues[s.dlIdx]
}

// minSpeedKBps returns the speed floor. It is meaningless without a download
// sample, so it collapses to zero when the sample is off.
func (s settings) minSpeedKBps() float64 {
	if s.downloadBytes() <= 0 {
		return 0
	}
	if s.minIdx == len(minSpeedPills)-1 {
		if s.minCustom > 0 {
			return s.minCustom
		}
		return 0
	}
	return minSpeedValues[s.minIdx]
}

func (s settings) uploadBytes() int64 { return uploadValues[s.upIdx] }

func (s settings) strict() bool { return s.strictIdx == 1 }

func (s settings) topN() int { return topValues[s.topIdx] }

// ranges returns the validated custom ranges, or nil when none are set.
func (s settings) ranges() ([]string, error) {
	if strings.TrimSpace(s.rangesText) == "" {
		return nil, nil
	}
	return cfranges.ParseCustomList(s.rangesText)
}

func (s settings) customRangeCount() int {
	r, err := s.ranges()
	if err != nil {
		return 0
	}
	return len(r)
}

// rangesSummary is the pill text for the list row: a count, not the entries,
// because the entries can be arbitrarily long and the pill has to fit a phone.
func (s settings) rangesSummary() string {
	switch n := s.customRangeCount(); {
	case n == 0:
		return "none yet — press c"
	case n == 1:
		return "1 range"
	default:
		return fmt.Sprintf("%d ranges", n)
	}
}

// rows returns the visible rows. The download-dependent rows are hidden when the
// download test is off, because a knob that cannot act should not be shown. The
// paste row appears only once a custom scope is selected, for the same reason.
func (s settings) rows() []setupRow {
	out := []setupRow{rowCount, rowWorkers, rowPorts, rowTimeout, rowTries, rowDownload}
	if s.downloadBytes() > 0 {
		out = append(out, rowMinSpeed)
	}
	out = append(out, rowUpload, rowStrict, rowTopN, rowRanges)
	if s.rangesIdx != 0 {
		out = append(out, rowRangesList)
	}
	return out
}

func (s settings) pillsFor(r setupRow) ([]pill, int) {
	switch r {
	case rowCount:
		return countPills, s.countIdx
	case rowWorkers:
		return workerPills, s.workerIdx
	case rowPorts:
		return portPills, s.portIdx
	case rowTimeout:
		return timeoutPills, s.timeoutIdx
	case rowTries:
		return triesPills, s.triesIdx
	case rowDownload:
		return downloadPills, s.dlIdx
	case rowMinSpeed:
		return minSpeedPills, s.minIdx
	case rowUpload:
		return uploadPills, s.upIdx
	case rowStrict:
		return offOnPills, s.strictIdx
	case rowTopN:
		return topPills, s.topIdx
	case rowRanges:
		return rangesPills, s.rangesIdx
	case rowRangesList:
		return []pill{{label: s.rangesSummary()}}, 0
	}
	return nil, 0
}

func (s *settings) setIdx(r setupRow, i int) {
	switch r {
	case rowCount:
		s.countIdx = i
	case rowWorkers:
		s.workerIdx = i
	case rowPorts:
		s.portIdx = i
	case rowTimeout:
		s.timeoutIdx = i
	case rowTries:
		s.triesIdx = i
	case rowDownload:
		s.dlIdx = i
	case rowMinSpeed:
		s.minIdx = i
	case rowUpload:
		s.upIdx = i
	case rowStrict:
		s.strictIdx = i
	case rowTopN:
		s.topIdx = i
	case rowRanges:
		s.rangesIdx = i
	case rowRangesList:
		// The list row has nothing to cycle; it only opens the editor.
	}
}

// label and hint describe a row. The hint changes with the value where the cost
// of the choice is not obvious from the number alone.
func rowLabel(r setupRow) string {
	switch r {
	case rowCount:
		return "Addresses"
	case rowWorkers:
		return "Workers"
	case rowPorts:
		return "Ports"
	case rowTimeout:
		return "Timeout"
	case rowTries:
		return "Attempts"
	case rowDownload:
		return "DL sample"
	case rowMinSpeed:
		return "Min speed"
	case rowUpload:
		return "UL sample"
	case rowStrict:
		return "Strict"
	case rowTopN:
		return "Show top"
	case rowRanges:
		return "Ranges"
	case rowRangesList:
		return "Custom"
	}
	return ""
}

func (s settings) hintFor(r setupRow) string {
	switch r {
	case rowCount:
		n := s.count()
		switch {
		case n <= 1000:
			return "quick look, a minute or two"
		case n <= 5000:
			return "wide sweep, several minutes and noticeable data use"
		default:
			return "very wide sweep; this is how rare clean blocks are found, but it runs long"
		}
	case rowWorkers:
		return "parallelism is the divisor of total time: wall ~ (count/workers) x attempts x avg"
	case rowPorts:
		return "a censoring ISP often blocks only some TLS ports; each port multiplies probes"
	case rowTimeout:
		t := s.timeout()
		switch {
		case t < 400*time.Millisecond:
			return "extreme: on a mobile link most healthy edges are discarded as failures"
		case t < time.Second:
			return "very aggressive: healthy edges near 700-800 ms will be thrown away"
		case t < 2500*time.Millisecond:
			return "fast, suits a stable connection"
		case t <= 8*time.Second:
			return "balanced; timeout is a ceiling, only spent on failures"
		default:
			return "patient: catches slow-but-usable edges at longer runtime"
		}
	case rowTries:
		return "attempts measure loss and jitter; they do not raise the timeout ceiling"
	case rowDownload:
		b := s.downloadBytes()
		switch {
		case b <= 0:
			return "off: addresses that answer but cannot carry traffic will pass"
		case b < 1<<20:
			return "small sample, cheap; too small to separate a middlebox from a real edge"
		case b <= 5<<20:
			return "good balance: enough payload to measure real throughput"
		default:
			return "large sample: accurate throughput, but this is the main driver of data use"
		}
	case rowMinSpeed:
		if s.minSpeedKBps() <= 0 {
			return "off: no throughput floor applied"
		}
		return "discards edges that answer and hold but cannot carry traffic"
	case rowUpload:
		return "a proxy needs both directions; upload costs the same data upstream"
	case rowStrict:
		return "clean, stable, fast and WebSocket-capable only; far fewer results"
	case rowTopN:
		return "how many rows the result table prints"
	case rowRanges:
		switch s.rangesIdx {
		case 1:
			return "built-in Cloudflare ranges plus your pasted list"
		case 2:
			return "only your pasted list; the built-in ranges are ignored"
		default:
			return "the built-in Cloudflare edge ranges"
		}
	case rowRangesList:
		return "paste IPs or CIDRs, one per line or comma-separated; bare IPs become /32; # comments ignored"
	}
	return ""
}

// costLine states the arithmetic the user cannot do in their head: total probes
// and the worst-case payload the download sample implies.
func (s settings) costLine() string {
	nPorts := len(strings.Split(s.ports(), ","))
	if s.ports() == "all" {
		nPorts = 6
	}
	probes := s.count() * nPorts
	head := fmt.Sprintf("%s probes (%s addresses", humanInt(probes), humanInt(s.count()))
	if nPorts == 1 {
		head += ")"
	} else {
		head += fmt.Sprintf(" x %d ports)", nPorts)
	}
	parts := []string{head}
	if b := s.downloadBytes(); b > 0 {
		parts = append(parts, fmt.Sprintf("%s downloaded per answering address", humanBytes(b)))
	}
	if u := s.uploadBytes(); u > 0 {
		parts = append(parts, fmt.Sprintf("%s uploaded per answering address", humanBytes(u)))
	}
	switch s.rangesIdx {
	case 1:
		parts = append(parts, "built-in + custom ranges")
	case 2:
		parts = append(parts, "only custom ranges")
	}
	return strings.Join(parts, "  ·  ")
}

// customPrompt describes the free-entry field for a row, or "" when the row has
// no custom slot selected.
func (s settings) customPrompt(r setupRow) (prompt, initial string) {
	if r == rowRangesList {
		return "paste IPs or CIDRs, one per line or comma-separated", s.rangesText
	}
	ps, idx := s.pillsFor(r)
	if idx != len(ps)-1 || !ps[len(ps)-1].custom {
		return "", ""
	}
	switch r {
	case rowCount:
		return "how many addresses?", itoaOrEmpty(s.countCustom)
	case rowWorkers:
		return "how many parallel workers?", itoaOrEmpty(s.workerCust)
	case rowDownload:
		return "download sample in MB (e.g. 8 or 0.5)", ftoaOrEmpty(s.dlCustomMB)
	case rowMinSpeed:
		return "minimum speed in KB/s (e.g. 3000)", ftoaOrEmpty(s.minCustom)
	}
	return "", ""
}

func (s *settings) applyCustom(r setupRow, raw string) error {
	if r == rowRangesList {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			s.rangesText = ""
			return nil
		}
		// Validated on submit so a typo is fixed in the editor, not discovered
		// after the scan starts.
		if _, err := cfranges.ParseCustomList(raw); err != nil {
			return err
		}
		s.rangesText = raw
		return nil
	}

	raw = strings.TrimSpace(strings.ReplaceAll(raw, ",", ""))
	if raw == "" {
		return nil
	}
	switch r {
	case rowCount, rowWorkers:
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return fmt.Errorf("enter a whole number above zero")
		}
		if r == rowCount {
			s.countCustom = n
		} else {
			s.workerCust = n
		}
	case rowDownload, rowMinSpeed:
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil || f <= 0 {
			return fmt.Errorf("enter a number above zero")
		}
		if r == rowDownload {
			s.dlCustomMB = f
		} else {
			s.minCustom = f
		}
	}
	return nil
}

// criteria builds the scoring rules from the setup page.
func (s settings) criteria() score.Criteria {
	c := score.DefaultCriteria()
	if s.strict() {
		c = score.StrictCriteria()
	}
	if v := s.minSpeedKBps(); v > 0 {
		c.MinDownloadKBps = v
	}
	return c
}

// probeConfig builds the per-address measurement from the setup page.
func (s settings) probeConfig(port int) probe.Config {
	return probe.Config{
		Port:          port,
		Mode:          probe.ModeHTTP,
		Tries:         s.tries(),
		Timeout:       s.timeout(),
		HoldDuration:  3 * time.Second,
		LongTest:        false,
		LongTestDuration: 0,
		DownloadBytes: s.downloadBytes(),
		UploadBytes:   s.uploadBytes(),
	}
}

func itoaOrEmpty(n int) string {
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func ftoaOrEmpty(f float64) string {
	if f <= 0 {
		return ""
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func humanInt(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func humanBytes(b int64) string {
	switch {
	case b >= 1<<20:
		v := float64(b) / float64(1<<20)
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d MB", int64(v))
		}
		return fmt.Sprintf("%.1f MB", v)
	case b >= 1<<10:
		return fmt.Sprintf("%d KB", b>>10)
	default:
		return fmt.Sprintf("%d B", b)
	}
}
