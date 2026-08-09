package cfranges

import (
	"net"
	"testing"
)

func TestKnownDirtySubnetsAreSkipped(t *testing.T) {
	s, err := NewSource(Options{IPv4: true, SkipDirty: true, Seed: 42})
	if err != nil {
		t.Fatalf("NewSource: %v", err)
	}
	// 103.21.244.0/23 measured 80% abuser and 100% proxy, so no generated
	// address should ever land inside it.
	for i := 0; i < 20000; i++ {
		ip := s.Random()
		if s.IsDirty(ip) {
			t.Fatalf("generated address %s inside a known-dirty subnet", ip)
		}
	}
}

// Weighting must favour the blocks that measured clean, otherwise the scanner
// wastes its probe budget in polluted space like a naive uniform scanner.
func TestWeightingFavoursCleanBlocks(t *testing.T) {
	s, err := NewSource(Options{IPv4: true, SkipDirty: true, Seed: 7})
	if err != nil {
		t.Fatalf("NewSource: %v", err)
	}
	_, polluted, _ := net.ParseCIDR("108.162.192.0/18")
	_, clean, _ := net.ParseCIDR("172.64.0.0/13")

	var pollutedHits, cleanHits int
	const n = 20000
	for i := 0; i < n; i++ {
		ip := s.Random()
		switch {
		case clean.Contains(ip):
			cleanHits++
		case polluted.Contains(ip):
			pollutedHits++
		}
	}
	if cleanHits <= pollutedHits {
		t.Errorf("clean block drawn %d times vs polluted %d; weighting is not taking effect",
			cleanHits, pollutedHits)
	}
}

func TestGeneratedAddressesAvoidNetworkAndBroadcastBytes(t *testing.T) {
	s, err := NewSource(Options{IPv4: true, Seed: 3})
	if err != nil {
		t.Fatalf("NewSource: %v", err)
	}
	for i := 0; i < 5000; i++ {
		ip := s.Random().To4()
		if ip == nil {
			t.Fatal("expected an IPv4 address")
		}
		if last := ip[3]; last == 0 || last == 255 {
			t.Fatalf("generated %s with unusable host byte %d", ip, last)
		}
	}
}

func TestStreamProducesUniqueAddresses(t *testing.T) {
	s, err := NewSource(Options{IPv4: true, Seed: 11})
	if err != nil {
		t.Fatalf("NewSource: %v", err)
	}
	done := make(chan struct{})
	defer close(done)

	seen := map[string]bool{}
	count := 0
	for ip := range s.Stream(done, 500) {
		key := ip.String()
		if seen[key] {
			t.Fatalf("Stream emitted %s twice", key)
		}
		seen[key] = true
		count++
	}
	if count != 500 {
		t.Errorf("Stream emitted %d addresses, want 500", count)
	}
}

func TestNeighborsStayInsideCloudflareSpace(t *testing.T) {
	s, err := NewSource(Options{IPv4: true, SkipDirty: true, Seed: 5})
	if err != nil {
		t.Fatalf("NewSource: %v", err)
	}
	hit := net.ParseIP("104.16.132.229")
	neighbors := s.NeighborsOf(hit, 16, 10)
	if len(neighbors) == 0 {
		t.Fatal("expected neighbours around an address in a large block")
	}
	for _, n := range neighbors {
		if !s.contains(n) {
			t.Errorf("neighbour %s fell outside the loaded ranges", n)
		}
		if n.Equal(hit) {
			t.Error("neighbour list included the original address")
		}
	}
}

func TestOnlyExtraLimitsScope(t *testing.T) {
	_, want, _ := net.ParseCIDR("192.0.2.0/24")
	s, err := NewSource(Options{
		IPv4:       true,
		ExtraCIDRs: []string{"192.0.2.0/24"},
		OnlyExtra:  true,
		Seed:       9,
	})
	if err != nil {
		t.Fatalf("NewSource: %v", err)
	}
	for i := 0; i < 1000; i++ {
		if ip := s.Random(); !want.Contains(ip) {
			t.Fatalf("generated %s outside the requested scope", ip)
		}
	}
}

func TestNoRangesSelectedIsAnError(t *testing.T) {
	if _, err := NewSource(Options{}); err == nil {
		t.Error("expected an error when no ranges are selected")
	}
}

func TestParseCustomList(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"blanks and comments only", "# list\n\n  \n", nil},
		{"one per line", "1.2.3.0/24\n5.6.7.8\n", []string{"1.2.3.0/24", "5.6.7.8/32"}},
		{"comma separated", " 1.2.3.0/24 , 5.6.7.8 ", []string{"1.2.3.0/24", "5.6.7.8/32"}},
		{"mixed separators", "1.2.3.0/24,5.6.7.8\n9.9.9.0/24", []string{"1.2.3.0/24", "5.6.7.8/32", "9.9.9.0/24"}},
		{"trailing comment", "1.2.3.0/24 # frankfurt", []string{"1.2.3.0/24"}},
		{"crlf paste", "1.2.3.0/24\r\n5.6.7.8\r\n", []string{"1.2.3.0/24", "5.6.7.8/32"}},
		{"ipv6 bare", "2001:db8::1", []string{"2001:db8::1/128"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCustomList(tt.in)
			if err != nil {
				t.Fatalf("ParseCustomList: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("entry %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseCustomListRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"banana", "1.2.3.4/33", "300.1.2.3"} {
		if _, err := ParseCustomList(bad); err == nil {
			t.Errorf("ParseCustomList(%q) accepted garbage", bad)
		}
	}
	// A valid entry must not be rejected just because one later line is bad.
	if _, err := ParseCustomList("1.2.3.0/24\nnot-an-ip"); err == nil {
		t.Error("a mixed list with a bad line was accepted")
	}
}
