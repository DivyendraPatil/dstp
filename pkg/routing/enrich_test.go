package routing

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestParseHopAddress(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{"1  gateway (192.168.1.1)  1.2 ms", "192.168.1.1"},
		{"2  96.120.1.2  8.9 ms", "96.120.1.2"},
		{"3  * * *", ""},
		{"4  ae1.example.net (2001:db8::1)  2 ms", "2001:db8::1"},
	}
	for _, tc := range cases {
		got := ParseHopAddress(tc.line)
		if tc.want == "" {
			if got.IsValid() {
				t.Fatalf("%q -> %v", tc.line, got)
			}
			continue
		}
		if got.String() != tc.want {
			t.Fatalf("%q -> %s want %s", tc.line, got, tc.want)
		}
	}
}

type stubASN struct {
	m map[string]ASNInfo
}

func (s stubASN) LookupIP(_ context.Context, ip netip.Addr) (ASNInfo, error) {
	if info, ok := s.m[ip.String()]; ok {
		return info, nil
	}
	return ASNInfo{}, context.Canceled
}

func TestEnrichHopsAndFormat(t *testing.T) {
	hops := []HopASN{
		{Hop: 1, Address: netip.MustParseAddr("192.168.1.1")},
		{Hop: 2, Address: netip.MustParseAddr("8.8.8.8")},
		{Hop: 3, Address: netip.MustParseAddr("1.1.1.1")},
		{Hop: 4},
	}
	prov := stubASN{m: map[string]ASNInfo{
		"8.8.8.8": {ASN: 15169, Name: "GOOGLE - Google LLC, US"},
		"1.1.1.1": {ASN: 13335, Name: "CLOUDFLARENET - Cloudflare, Inc., US"},
	}}
	out := EnrichHops(context.Background(), hops, prov, 4)
	if !out[0].Private {
		t.Fatalf("private: %+v", out[0])
	}
	if out[1].ASN != 15169 || out[2].ASN != 13335 {
		t.Fatalf("%+v", out)
	}
	if !out[3].Unknown {
		t.Fatal("empty hop should be unknown")
	}
	path := CollapseObservedASNPath(out)
	sum := FormatHopSummary(out, path)
	if !strings.Contains(sum, "observed ASN path:") || !strings.Contains(sum, "AS15169") {
		t.Fatalf("%s", sum)
	}
	if !strings.Contains(FormatObservedASNPath(path), "private -> AS15169 -> AS13335") {
		t.Fatalf("%v", path.Labels)
	}
}
