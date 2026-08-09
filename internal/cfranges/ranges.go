// Package cfranges holds Cloudflare's published edge ranges, used as the default
// scan scope when the user has not supplied their own CIDRs.
//
// The list (cf_ranges.txt) is the full set of Cloudflare IPv4 edge /24 blocks as
// published on the date noted in that file. It is intentionally exhaustive
// rather than weighted: on a long path (Iran -> Frankfurt, etc.) the reachable
// edges live in blocks our earlier hand-picked "cleanest" weights would have
// under-sampled, so we now draw uniformly across the whole space and let the
// probe + reputation stages do the filtering. Every block is eligible; weights
// only bias the draw, they never discard.
//
// To use a custom scope, pass ExtraCIDRs (Settings -> Custom Ranges / file
// import) or flip OnlyExtra to ignore the built-in list entirely.
package cfranges

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
)

//go:embed cf_ranges.txt
var defaultRanges string

// Block is one Cloudflare CIDR plus its scan priority.
type Block struct {
	CIDR string
	// Weight biases random selection. 1.0 = neutral. Higher means the block is
	// drawn more often. Weights never exclude a block.
	Weight float64
	// Note documents why the weight is what it is.
	Note string
}

// V4Blocks is the default Cloudflare IPv4 edge space, loaded from cf_ranges.txt.
// It is exposed (and named) for callers that want to inspect the built-in set.
var V4Blocks = loadDefaultBlocks()

func loadDefaultBlocks() []Block {
	out := make([]Block, 0, 5000)
	for _, line := range strings.Split(defaultRanges, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, _, err := net.ParseCIDR(line); err != nil {
			continue
		}
		out = append(out, Block{CIDR: line, Weight: 1.0})
	}
	if len(out) == 0 {
		// Fallback so the package is never empty even if the embed is missing.
		out = []Block{{CIDR: "104.16.0.0/12", Weight: 1.0}}
	}
	return out
}

// KnownDirtySubnets are /22-or-smaller ranges observed to be almost entirely
// proxy/VPN/abuser flagged. Addresses inside them are skipped outright.
var KnownDirtySubnets = []string{
	"103.21.244.0/23",
	"141.101.120.0/22",
}

// Source generates candidate addresses from a weighted block set.
type Source struct {
	nets    []*net.IPNet
	weights []float64
	cum     []float64
	dirty   []*net.IPNet
	rng     *rand.Rand
}

// Options configures a Source.
type Options struct {
	IPv4 bool
	// ExtraCIDRs are added to the pool with neutral weight.
	ExtraCIDRs []string
	// OnlyExtra treats ExtraCIDRs as the entire scan scope, ignoring the
	// built-in Cloudflare blocks.
	OnlyExtra bool
	// SkipDirty drops addresses that fall inside KnownDirtySubnets.
	SkipDirty bool
	// Seed makes generation reproducible when non-zero.
	Seed int64
}

// ParseCustomList splits a pasted list of IPs and CIDRs into validated ranges.
//
// It accepts newline- and comma-separated entries (so a pasted file and a
// single line both work), ignores blank lines and # comments, and turns a bare
// IP into a /32 (or /128 for IPv6). The result is ready for Options.ExtraCIDRs.
func ParseCustomList(raw string) ([]string, error) {
	var out []string
	for _, entry := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	}) {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		// "1.2.3.0/24 # frankfurt" — keep the entry, drop the comment.
		if i := strings.Index(entry, "#"); i >= 0 {
			entry = strings.TrimSpace(entry[:i])
			if entry == "" {
				continue
			}
		}
		if ip := net.ParseIP(entry); ip != nil {
			if ip.To4() != nil {
				entry += "/32"
			} else {
				entry += "/128"
			}
		}
		if _, _, err := net.ParseCIDR(entry); err != nil {
			return nil, fmt.Errorf("%q is not a valid IP or CIDR", entry)
		}
		out = append(out, entry)
	}
	return out, nil
}

// NewSource builds a weighted address generator.
func NewSource(opts Options) (*Source, error) {
	seed := opts.Seed
	if seed == 0 {
		seed = rand.Int63()
	}
	s := &Source{rng: rand.New(rand.NewSource(seed))}

	add := func(b Block) error {
		_, n, err := net.ParseCIDR(strings.TrimSpace(b.CIDR))
		if err != nil {
			return fmt.Errorf("bad CIDR %q: %w", b.CIDR, err)
		}
		w := b.Weight
		if w <= 0 {
			w = 1
		}
		// Scale weight by block size so a /12 is not drawn as often as a /24
		// purely because both have weight 1.
		ones, bits := n.Mask.Size()
		size := pow2(bits - ones)
		s.nets = append(s.nets, n)
		s.weights = append(s.weights, w*size)
		return nil
	}

	if !opts.OnlyExtra {
		if opts.IPv4 {
			for _, b := range V4Blocks {
				if err := add(b); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, c := range opts.ExtraCIDRs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if err := add(Block{CIDR: c, Weight: 1}); err != nil {
			return nil, err
		}
	}
	if len(s.nets) == 0 {
		return nil, fmt.Errorf("no ranges selected")
	}

	if opts.SkipDirty {
		for _, c := range KnownDirtySubnets {
			if _, n, err := net.ParseCIDR(c); err == nil {
				s.dirty = append(s.dirty, n)
			}
		}
	}

	s.cum = make([]float64, len(s.weights))
	var sum float64
	for i, w := range s.weights {
		sum += w
		s.cum[i] = sum
	}
	return s, nil
}

// Nets exposes the loaded ranges, used by the neighbour scanner to confirm a
// candidate still belongs to Cloudflare space.
func (s *Source) Nets() []*net.IPNet { return s.nets }

// IsDirty reports whether ip falls inside a known-polluted subnet.
func (s *Source) IsDirty(ip net.IP) bool {
	for _, n := range s.dirty {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Random returns one weighted-random address, skipping dirty subnets.
func (s *Source) Random() net.IP {
	for attempt := 0; attempt < 64; attempt++ {
		total := s.cum[len(s.cum)-1]
		r := s.rng.Float64() * total
		idx := sort.SearchFloat64s(s.cum, r)
		if idx >= len(s.nets) {
			idx = len(s.nets) - 1
		}
		ip := randomInNet(s.nets[idx], s.rng)
		if !s.IsDirty(ip) {
			return ip
		}
	}
	// All attempts landed in dirty space; return the last draw anyway rather
	// than blocking the scan.
	return randomInNet(s.nets[0], s.rng)
}

// Stream emits unique random addresses until ctx is done or count is reached.
// count <= 0 means unlimited.
func (s *Source) Stream(done <-chan struct{}, count int) <-chan net.IP {
	ch := make(chan net.IP, 128)
	go func() {
		defer close(ch)
		seenCap := max(count, 64)
		seen := make(map[string]struct{}, seenCap)
		sent := 0
		// Cap wasted draws so a tiny custom CIDR cannot spin forever.
		misses := 0
		for count <= 0 || sent < count {
			ip := s.Random()
			key := ip.String()
			// An unbounded scan (count<=0) would grow seen forever; roll it
			// over once it gets large so memory stays flat.
			if len(seen) > 100000 {
				seen = make(map[string]struct{}, seenCap)
			}
			if _, dup := seen[key]; dup {
				misses++
				if misses > 10000 {
					return
				}
				continue
			}
			misses = 0
			seen[key] = struct{}{}
			select {
			case <-done:
				return
			case ch <- ip:
				sent++
			}
		}
	}()
	return ch
}

// NeighborsOf returns up to limit addresses adjacent to ip that are still
// inside Cloudflare space and not dirty. A working edge IP usually sits in a
// block of working edge IPs, so this converts one hit into many.
func (s *Source) NeighborsOf(ip net.IP, radius, limit int) []net.IP {
	if radius <= 0 || limit <= 0 {
		return nil
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	base := binary.BigEndian.Uint32(ip4)
	out := make([]net.IP, 0, limit)
	for d := 1; d <= radius && len(out) < limit; d++ {
		for _, delta := range [2]int64{int64(d), -int64(d)} {
			v := int64(base) + delta
			if v < 0 || v > 0xFFFFFFFF {
				continue
			}
			cand := make(net.IP, 4)
			binary.BigEndian.PutUint32(cand, uint32(v))
			if s.IsDirty(cand) || !s.contains(cand) {
				continue
			}
			out = append(out, cand)
		}
	}
	return out
}

func (s *Source) contains(ip net.IP) bool {
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func randomInNet(n *net.IPNet, rng *rand.Rand) net.IP {
	if ip4 := n.IP.To4(); ip4 != nil {
		base := binary.BigEndian.Uint32(ip4)
		mask := binary.BigEndian.Uint32(net.IP(n.Mask).To4())
		host := rng.Uint32() & ^mask
		// Avoid .0 and .255 host bytes; Cloudflare does not serve them and
		// probing them just burns budget.
		if host&0xFF == 0 {
			host |= 1
		} else if host&0xFF == 0xFF {
			host &= ^uint32(1)
		}
		out := make(net.IP, 4)
		binary.BigEndian.PutUint32(out, base|host)
		return out
	}
	out := make(net.IP, len(n.IP))
	copy(out, n.IP)
	for i := range out {
		out[i] = n.IP[i] | (byte(rng.Intn(256)) & ^n.Mask[i])
	}
	return out
}

func pow2(n int) float64 {
	f := 1.0
	for i := 0; i < n && i < 62; i++ {
		f *= 2
	}
	return f
}
