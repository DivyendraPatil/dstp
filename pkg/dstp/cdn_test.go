package dstp

import (
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestDetectCDNHintsCloudflare(t *testing.T) {
	h := http.Header{}
	h.Set("CF-RAY", "abc-EWR")
	h.Set("Server", "cloudflare")
	h.Set("Alt-Svc", `h3=":443"; ma=86400`)
	got := detectCDNHints(h)
	joined := strings.Join(got, ";")
	if !strings.Contains(joined, "cdn=cloudflare") || !strings.Contains(joined, "cf-ray=") {
		t.Fatalf("%v", got)
	}
}

func TestResolveUDPProbeNon53(t *testing.T) {
	got := resolveUDPProbeTarget(t.Context(), "example.com", "443", "", 0)
	if got.Host != "example.com" || got.Note != "" {
		t.Fatalf("%+v", got)
	}
}

func TestExpandIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	s := expandIPv6(ip)
	if len(s) != 32 {
		t.Fatalf("len=%d %q", len(s), s)
	}
}

func TestResolveUDPProbeLiteralIP(t *testing.T) {
	got := resolveUDPProbeTarget(t.Context(), "1.1.1.1", "53", "", 0)
	if got.Host != "1.1.1.1" {
		t.Fatalf("%+v", got)
	}
}
