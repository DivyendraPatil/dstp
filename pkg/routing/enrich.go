package routing

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

// ParseHopAddress extracts the first IP from a traceroute hop line.
// Returns an invalid Addr when the hop has no address (e.g. "* * *").
func ParseHopAddress(line string) netip.Addr {
	fields := strings.Fields(line)
	for _, f := range fields {
		f = strings.Trim(f, "(),")
		if addr, err := netip.ParseAddr(f); err == nil {
			return addr
		}
	}
	return netip.Addr{}
}

// ParseHopNumber returns the hop index from a numbered traceroute line.
func ParseHopNumber(line string) int {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return 0
	}
	n := strings.TrimSuffix(fields[0], ".")
	v, err := strconv.Atoi(n)
	if err != nil {
		return 0
	}
	return v
}

// EnrichHops fills ASN metadata for public hop IPs using provider.
// Special-use / missing addresses are marked private or unknown locally.
// Concurrency is bounded; provider errors leave the hop as unknown.
func EnrichHops(ctx context.Context, hops []HopASN, provider ASNProvider, concurrency int) []HopASN {
	if provider == nil || len(hops) == 0 {
		return hops
	}
	if concurrency < 1 {
		concurrency = 8
	}
	out := make([]HopASN, len(hops))
	copy(out, hops)

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := range out {
		h := &out[i]
		if !h.Address.IsValid() {
			h.Unknown = true
			continue
		}
		if !IsPublicRoutable(h.Address) {
			h.Private = true
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(hop *HopASN) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				hop.Unknown = true
				return
			}
			info, err := provider.LookupIP(ctx, hop.Address)
			if err != nil || info.ASN == 0 {
				hop.Unknown = true
				return
			}
			hop.ASN = info.ASN
			hop.Name = info.Name
			if hop.Name == "" {
				hop.Name = info.Organization
			}
		}(h)
	}
	wg.Wait()
	return out
}

// FormatObservedASNPath renders "AS7922 -> AS3356 -> AS13335".
func FormatObservedASNPath(path ObservedASNPath) string {
	if len(path.Labels) == 0 {
		return ""
	}
	return strings.Join(path.Labels, " -> ")
}

// FormatHopSummary builds a short human line for enriched hops + path.
func FormatHopSummary(hops []HopASN, path ObservedASNPath) string {
	if len(hops) == 0 {
		return ""
	}
	first := hopLabel(hops[0])
	last := hopLabel(hops[len(hops)-1])
	summary := first
	if len(hops) > 1 {
		summary = fmt.Sprintf("%s … %s (%d hops)", first, last, len(hops))
	}
	if p := FormatObservedASNPath(path); p != "" {
		summary = summary + "; observed ASN path: " + p
	}
	return summary
}

func hopLabel(h HopASN) string {
	switch {
	case h.Private:
		if h.Address.IsValid() {
			return h.Address.String() + " (private)"
		}
		return "private"
	case h.ASN != 0:
		label := fmt.Sprintf("AS%d", h.ASN)
		if h.Name != "" {
			// Keep short: first token before " - "
			name := h.Name
			if i := strings.Index(name, " - "); i > 0 {
				name = name[:i]
			}
			label += " " + name
		}
		if h.Address.IsValid() {
			return fmt.Sprintf("%s (%s)", h.Address.String(), label)
		}
		return label
	case h.Address.IsValid():
		return h.Address.String()
	default:
		return "*"
	}
}
