package lookup

import (
	"testing"
)

func TestFormatAddrs(t *testing.T) {
	got := formatAddrs([]string{"1.2.3.4", "2001:db8::1", "not-an-ip"})
	if got != "IPv4=1.2.3.4 IPv6=2001:db8::1 other=not-an-ip" {
		t.Fatalf("got %q", got)
	}
}

func TestFormatDNSServer(t *testing.T) {
	if got := formatDNSServer("8.8.8.8"); got != "8.8.8.8:53" {
		t.Fatalf("got %q", got)
	}
	if got := formatDNSServer("8.8.8.8:5353"); got != "8.8.8.8:5353" {
		t.Fatalf("got %q", got)
	}
	if got := formatDNSServer("[2001:db8::1]"); got != "[2001:db8::1]:53" {
		t.Fatalf("got %q", got)
	}
	if got := formatDNSServer("2001:db8::1"); got != "[2001:db8::1]:53" {
		t.Fatalf("got %q", got)
	}
}
