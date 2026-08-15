package dstp

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// getAddr extracts a hostname or IP from a URL, host:port, or bare address.
func getAddr(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("failed to parse address: empty host")
	}

	// Bare IP (v4 or unbracketed v6)
	if ip := net.ParseIP(addr); ip != nil {
		return addr, nil
	}

	raw := addr
	if !strings.Contains(addr, "://") {
		raw = "https://" + addr
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("failed to parse address: %w", err)
	}

	if host := u.Hostname(); host != "" {
		return host, nil
	}

	// url.Parse can treat a bare hostname as a scheme when there is no slash.
	if !strings.Contains(addr, "://") {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			return host, nil
		}
		if u.Scheme != "" && u.Host == "" {
			return u.Scheme, nil
		}
	}

	return "", fmt.Errorf("failed to parse address: empty host")
}
