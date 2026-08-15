package dstp

import (
	"testing"
)

func TestGetAddr(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"facebook.com", "facebook.com"},
		{"facebook.com:80", "facebook.com"},
		{"https://jvns.ca", "jvns.ca"},
		{"https://jvns.ca:443", "jvns.ca"},
		{"8.8.8.8", "8.8.8.8"},
		{"2606:4700:3031::ac43:b35a", "2606:4700:3031::ac43:b35a"},
		{"[2606:4700:3031::ac43:b35a]:443", "2606:4700:3031::ac43:b35a"},
		{"meta.stackoverflow.com:443", "meta.stackoverflow.com"},
		{"https://meta.stackoverflow.com/", "meta.stackoverflow.com"},
		{"https://user:pass@example.com/path", "example.com"},
		{"example.com/path?q=1", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got, err := getAddr(tt.addr)
			if err != nil {
				t.Fatalf("getAddr(%q) unexpected error: %v", tt.addr, err)
			}
			if got != tt.want {
				t.Fatalf("getAddr(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}
