package routing

import (
	"net/netip"
	"strconv"
)

// AddrClass classifies an IP for routing enrichment decisions.
type AddrClass string

const (
	AddrPublic        AddrClass = "public"
	AddrPrivate       AddrClass = "private"
	AddrLoopback      AddrClass = "loopback"
	AddrLinkLocal     AddrClass = "link_local"
	AddrMulticast     AddrClass = "multicast"
	AddrUnspecified   AddrClass = "unspecified"
	AddrDocumentation AddrClass = "documentation"
	AddrCGNAT         AddrClass = "cgnat"
	AddrReserved      AddrClass = "reserved"
	AddrInvalid       AddrClass = "invalid"
)

// documentation / special-use prefixes (RFC 5737, 3849, 6598, etc.).
var (
	doc4a = mustPrefix("192.0.2.0/24")    // TEST-NET-1
	doc4b = mustPrefix("198.51.100.0/24") // TEST-NET-2
	doc4c = mustPrefix("203.0.113.0/24")  // TEST-NET-3
	doc6  = mustPrefix("2001:db8::/32")
	cgnat = mustPrefix("100.64.0.0/10") // RFC 6598
	bench = mustPrefix("198.18.0.0/15") // RFC 2544 benchmarking
)

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

// ClassifyAddr returns the special-use class for addr.
func ClassifyAddr(addr netip.Addr) AddrClass {
	if !addr.IsValid() {
		return AddrInvalid
	}
	switch {
	case addr.IsUnspecified():
		return AddrUnspecified
	case addr.IsLoopback():
		return AddrLoopback
	case addr.IsMulticast():
		return AddrMulticast
	case addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast():
		return AddrLinkLocal
	case addr.IsPrivate():
		return AddrPrivate
	case doc4a.Contains(addr) || doc4b.Contains(addr) || doc4c.Contains(addr) || doc6.Contains(addr):
		return AddrDocumentation
	case cgnat.Contains(addr):
		return AddrCGNAT
	case bench.Contains(addr):
		return AddrReserved
	default:
		return AddrPublic
	}
}

// IsPublicRoutable reports whether addr should be sent to public ASN/RPKI APIs.
func IsPublicRoutable(addr netip.Addr) bool {
	return ClassifyAddr(addr) == AddrPublic
}

// CollapseObservedASNPath collapses adjacent duplicate ASNs from traceroute hops.
// This is an observed traceroute ASN path, not the BGP AS_PATH attribute.
func CollapseObservedASNPath(hops []HopASN) ObservedASNPath {
	out := ObservedASNPath{
		Note: "observed traceroute ASN path (not BGP AS_PATH)",
	}
	var lastLabel string
	var haveLast bool

	appendUnique := func(asn uint32, label string) {
		if haveLast && label == lastLabel {
			return
		}
		out.ASNs = append(out.ASNs, asn)
		out.Labels = append(out.Labels, label)
		lastLabel, haveLast = label, true
	}

	for _, h := range hops {
		switch {
		case h.Private || (h.Address.IsValid() && !IsPublicRoutable(h.Address)):
			appendUnique(0, "private")
		case h.Unknown || h.ASN == 0:
			appendUnique(0, "unknown")
		default:
			appendUnique(h.ASN, "AS"+strconv.FormatUint(uint64(h.ASN), 10))
		}
	}
	return out
}
