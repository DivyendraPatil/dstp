package rdap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const sampleIPRDAP = `{
  "handle": "1.1.1.0 - 1.1.1.255",
  "name": "APNIC-LABS",
  "country": "AU",
  "startAddress": "1.1.1.0",
  "endAddress": "1.1.1.255",
  "cidr0_cidrs": [{"v4prefix": "1.1.1.0", "length": 24}],
  "events": [
    {"eventAction": "registration", "eventDate": "2011-08-10T23:12:35Z"},
    {"eventAction": "last changed", "eventDate": "2023-04-26T22:57:58Z"}
  ],
  "notices": [{"title": "Source", "description": ["Objects returned came from source", "APNIC"]}],
  "entities": [
    {
      "roles": ["registrant"],
      "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."], ["email", {}, "text", "admin@example.com"]]]
    },
    {
      "roles": ["abuse"],
      "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "abuse@example.com"]]]
    }
  ]
}`

func TestLookupIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/1.1.1.1") {
			t.Fatalf("path=%s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(sampleIPRDAP))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.IPBaseURL = srv.URL + "/ip/"
	c.HTTPClient = srv.Client()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := c.LookupIP(ctx, netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Kind != "ip" || info.Name != "APNIC-LABS" {
		t.Fatalf("%+v", info)
	}
	if info.CIDR != "1.1.1.0/24" {
		t.Fatalf("cidr=%q", info.CIDR)
	}
	if info.RIR != "APNIC" {
		t.Fatalf("rir=%q", info.RIR)
	}
	if info.Organization != "Cloudflare, Inc." {
		t.Fatalf("org=%q", info.Organization)
	}
	if info.AbuseContact != "abuse@example.com" {
		t.Fatalf("abuse=%q", info.AbuseContact)
	}
	if info.Registered == nil || info.LastChanged == nil {
		t.Fatalf("missing events: %+v", info)
	}
}

func TestLookupIPSpecialUseSkipped(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.IPBaseURL = srv.URL + "/ip/"
	c.HTTPClient = srv.Client()

	_, err := c.LookupIP(context.Background(), netip.MustParseAddr("192.168.0.1"))
	if err == nil {
		t.Fatal("expected error")
	}
	if called {
		t.Fatal("must not call RDAP for private IP")
	}
}

func TestLookupDomain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/example.com") {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ldhName":"EXAMPLE.COM","handle":"example","events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"}],"entities":[]}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.DomainBaseURL = srv.URL + "/domain/"
	c.HTTPClient = srv.Client()

	info, err := c.LookupDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if info.Kind != "domain" || info.Name != "EXAMPLE.COM" {
		t.Fatalf("%+v", info)
	}
}

func TestLookupDomainRejectsPath(t *testing.T) {
	c := New()
	_, err := c.LookupDomain(context.Background(), "example.com/foo")
	if err == nil {
		t.Fatal("expected invalid domain")
	}
}
