package cymru

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestLookupIP(t *testing.T) {
	c := New()
	c.LookupTXT = func(_ context.Context, name string) ([]string, error) {
		switch {
		case strings.HasSuffix(name, ".origin.asn.cymru.com"):
			if !strings.HasPrefix(name, "1.1.1.1.") {
				t.Fatalf("zone=%s", name)
			}
			return []string{`"13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"`}, nil
		case strings.HasPrefix(name, "AS13335.asn.cymru.com"):
			return []string{`"13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"`}, nil
		default:
			t.Fatalf("unexpected lookup %s", name)
			return nil, nil
		}
	}

	info, err := c.LookupIP(context.Background(), netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if info.ASN != 13335 || info.Prefix.String() != "1.1.1.0/24" {
		t.Fatalf("%+v", info)
	}
	if info.Country != "AU" || !strings.EqualFold(info.RIR, "APNIC") {
		t.Fatalf("%+v", info)
	}
	if !strings.Contains(info.Name, "CLOUDFLARENET") {
		t.Fatalf("name=%q", info.Name)
	}
	if info.Source != "cymru-dns" {
		t.Fatalf("source=%q", info.Source)
	}
}

func TestLookupIPSpecialUse(t *testing.T) {
	called := false
	c := New()
	c.LookupTXT = func(context.Context, string) ([]string, error) {
		called = true
		return nil, nil
	}
	_, err := c.LookupIP(context.Background(), netip.MustParseAddr("10.1.2.3"))
	if err == nil || called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}

func TestOriginZoneIPv6(t *testing.T) {
	z, err := originZone(netip.MustParseAddr("2001:4860:b002::68"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(z, "8.6.") || !strings.HasSuffix(z, ".origin6.asn.cymru.com") {
		t.Fatalf("zone=%s", z)
	}
	// Ends with reversed leading nibbles of 2001 → ...1.0.0.2
	if !strings.Contains(z, "1.0.0.2.origin6.asn.cymru.com") {
		t.Fatalf("zone=%s", z)
	}
}

func TestParseOriginTXTMultiASN(t *testing.T) {
	asn, prefix, _, _, err := parseOriginTXT("13335 15169 | 1.1.1.0/24 | AU | apnic | 2011-08-11")
	if err != nil || asn != 13335 || prefix.String() != "1.1.1.0/24" {
		t.Fatalf("%d %s %v", asn, prefix, err)
	}
}
