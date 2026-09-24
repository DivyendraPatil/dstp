package routing

import (
	"net/netip"
	"testing"
)

func TestClassifyAddr(t *testing.T) {
	cases := []struct {
		ip   string
		want AddrClass
	}{
		{"8.8.8.8", AddrPublic},
		{"1.1.1.1", AddrPublic},
		{"2001:4860:4860::8888", AddrPublic},
		{"10.0.0.1", AddrPrivate},
		{"192.168.1.1", AddrPrivate},
		{"172.16.5.5", AddrPrivate},
		{"127.0.0.1", AddrLoopback},
		{"::1", AddrLoopback},
		{"169.254.1.1", AddrLinkLocal},
		{"fe80::1", AddrLinkLocal},
		{"224.0.0.1", AddrMulticast},
		{"ff02::1", AddrMulticast},
		{"0.0.0.0", AddrUnspecified},
		{"::", AddrUnspecified},
		{"192.0.2.10", AddrDocumentation},
		{"198.51.100.1", AddrDocumentation},
		{"203.0.113.50", AddrDocumentation},
		{"2001:db8::1", AddrDocumentation},
		{"100.64.0.1", AddrCGNAT},
		{"198.18.0.1", AddrReserved},
	}
	for _, tc := range cases {
		addr := netip.MustParseAddr(tc.ip)
		got := ClassifyAddr(addr)
		if got != tc.want {
			t.Errorf("ClassifyAddr(%s)=%s want %s", tc.ip, got, tc.want)
		}
		public := IsPublicRoutable(addr)
		if (tc.want == AddrPublic) != public {
			t.Errorf("IsPublicRoutable(%s)=%v want %v", tc.ip, public, tc.want == AddrPublic)
		}
	}
	if ClassifyAddr(netip.Addr{}) != AddrInvalid {
		t.Fatal("invalid addr")
	}
}

func TestCollapseObservedASNPath(t *testing.T) {
	hops := []HopASN{
		{Hop: 1, Address: netip.MustParseAddr("192.168.1.1"), Private: true},
		{Hop: 2, ASN: 7922, Name: "Comcast"},
		{Hop: 3, ASN: 7922, Name: "Comcast"},
		{Hop: 4, Unknown: true},
		{Hop: 5, ASN: 3356},
		{Hop: 6, ASN: 13335},
		{Hop: 7, ASN: 13335},
	}
	path := CollapseObservedASNPath(hops)
	wantLabels := []string{"private", "AS7922", "unknown", "AS3356", "AS13335"}
	wantASNs := []uint32{0, 7922, 0, 3356, 13335}
	if len(path.Labels) != len(wantLabels) {
		t.Fatalf("labels=%v want %v", path.Labels, wantLabels)
	}
	for i := range wantLabels {
		if path.Labels[i] != wantLabels[i] || path.ASNs[i] != wantASNs[i] {
			t.Fatalf("path=%v/%v want %v/%v", path.Labels, path.ASNs, wantLabels, wantASNs)
		}
	}
	if path.Note == "" {
		t.Fatal("expected note clarifying observed vs BGP AS_PATH")
	}
}

func TestMapRIPERPKIStatus(t *testing.T) {
	cases := []struct {
		in, status, detail string
	}{
		{"valid", RPKIValid, ""},
		{"invalid_asn", RPKIInvalid, "invalid_asn"},
		{"invalid_length", RPKIInvalid, "invalid_length"},
		{"unknown", RPKINotFound, ""},
		{"", RPKIUnknown, ""},
		{"weird", RPKIUnknown, "weird"},
	}
	for _, tc := range cases {
		st, d := MapRIPERPKIStatus(tc.in)
		if st != tc.status || d != tc.detail {
			t.Fatalf("%q -> %q/%q want %q/%q", tc.in, st, d, tc.status, tc.detail)
		}
	}
}
