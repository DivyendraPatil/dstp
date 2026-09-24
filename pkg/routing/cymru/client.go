// Package cymru implements IP→ASN lookup via Team Cymru DNS zones
// (origin / origin6 / asn). Intended for traceroute hop enrichment.
package cymru

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/routing"
)

// Client performs Team Cymru DNS TXT lookups.
type Client struct {
	// LookupTXT overrides DNS (tests). Defaults to net.DefaultResolver.
	LookupTXT func(ctx context.Context, name string) ([]string, error)
	Timeout   time.Duration
}

// New returns a Client with defaults.
func New() *Client {
	return &Client{Timeout: 5 * time.Second}
}

var _ routing.ASNProvider = (*Client)(nil)

func (c *Client) lookupTXT(ctx context.Context, name string) ([]string, error) {
	if c.LookupTXT != nil {
		return c.LookupTXT(ctx, name)
	}
	r := net.DefaultResolver
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	return r.LookupTXT(ctx, name)
}

// LookupIP maps a public IP to origin ASN/prefix via Cymru DNS.
func (c *Client) LookupIP(ctx context.Context, ip netip.Addr) (routing.ASNInfo, error) {
	info := routing.ASNInfo{IP: ip, Source: "cymru-dns"}
	if !ip.IsValid() {
		return info, fmt.Errorf("invalid IP")
	}
	if !routing.IsPublicRoutable(ip) {
		info.Source = "local"
		return info, fmt.Errorf("special-use address (%s): not queried", routing.ClassifyAddr(ip))
	}

	zone, err := originZone(ip)
	if err != nil {
		return info, err
	}
	txts, err := c.lookupTXT(ctx, zone)
	if err != nil {
		return info, fmt.Errorf("cymru dns: %w", err)
	}
	if len(txts) == 0 {
		return info, fmt.Errorf("cymru dns: empty TXT for %s", ip)
	}
	asn, prefix, cc, rir, err := parseOriginTXT(txts[0])
	if err != nil {
		return info, err
	}
	info.ASN = asn
	info.Prefix = prefix
	info.Country = cc
	info.RIR = rir

	if name, nerr := c.lookupASName(ctx, asn); nerr == nil && name != "" {
		info.Name = name
		info.Organization = name
	}
	return info, nil
}

func (c *Client) lookupASName(ctx context.Context, asn uint32) (string, error) {
	name := fmt.Sprintf("AS%d.asn.cymru.com", asn)
	txts, err := c.lookupTXT(ctx, name)
	if err != nil || len(txts) == 0 {
		return "", err
	}
	// "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"
	parts := splitPipe(txts[0])
	if len(parts) >= 5 {
		return parts[4], nil
	}
	return "", nil
}

func originZone(ip netip.Addr) (string, error) {
	if ip.Is4() {
		a := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", a[3], a[2], a[1], a[0]), nil
	}
	if ip.Is6() {
		var b strings.Builder
		h := ip.As16()
		// full nibble-reversed form
		for i := 15; i >= 0; i-- {
			hi := h[i] >> 4
			lo := h[i] & 0x0f
			fmt.Fprintf(&b, "%x.%x.", lo, hi)
		}
		b.WriteString("origin6.asn.cymru.com")
		return b.String(), nil
	}
	return "", fmt.Errorf("unsupported address family")
}

func parseOriginTXT(s string) (asn uint32, prefix netip.Prefix, cc, rir string, err error) {
	parts := splitPipe(s)
	if len(parts) < 1 {
		return 0, prefix, "", "", fmt.Errorf("cymru: empty origin TXT")
	}
	// First field may be "13335" or "13335 15169" (multi-origin); take first.
	asnField := strings.Fields(parts[0])
	if len(asnField) == 0 {
		return 0, prefix, "", "", fmt.Errorf("cymru: no ASN in %q", s)
	}
	n, err := strconv.ParseUint(asnField[0], 10, 32)
	if err != nil {
		return 0, prefix, "", "", fmt.Errorf("cymru: bad ASN %q", asnField[0])
	}
	asn = uint32(n)
	if len(parts) >= 2 && parts[1] != "" {
		if p, perr := netip.ParsePrefix(parts[1]); perr == nil {
			prefix = p
		}
	}
	if len(parts) >= 3 {
		cc = parts[2]
	}
	if len(parts) >= 4 {
		rir = strings.ToUpper(parts[3])
	}
	return asn, prefix, cc, rir, nil
}

func splitPipe(s string) []string {
	s = strings.Trim(s, `"`)
	raw := strings.Split(s, "|")
	out := make([]string, len(raw))
	for i, p := range raw {
		out[i] = strings.TrimSpace(p)
	}
	return out
}
