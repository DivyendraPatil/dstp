package dstp

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode"
)

// Target is a parsed destination retaining scheme, port, path, and query when supplied.
type Target struct {
	Raw      string
	Host     string
	Scheme   string // http, https, or empty
	Port     string // explicit port from input, if any
	Path     string
	RawQuery string
	IsIP     bool
}

func (t Target) String() string { return t.Host }

// parseTarget extracts host/IP and optional URL components from a CLI target.
func parseTarget(addr string) (Target, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return Target{}, fmt.Errorf("failed to parse address: empty host")
	}
	if err := validateOperand(addr); err != nil {
		return Target{}, err
	}

	t := Target{Raw: addr}

	// Bare IP (v4 or unbracketed v6)
	if ip := net.ParseIP(addr); ip != nil {
		t.Host = addr
		t.IsIP = true
		return t, nil
	}

	raw := addr
	hadScheme := strings.Contains(addr, "://")
	if !hadScheme {
		raw = "https://" + addr
	}

	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, fmt.Errorf("failed to parse address: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		if !hadScheme {
			if h, p, err := net.SplitHostPort(addr); err == nil {
				t.Host = h
				t.Port = p
				t.IsIP = net.ParseIP(h) != nil
				return t, nil
			}
			if u.Scheme != "" && u.Host == "" {
				t.Host = u.Scheme
				return t, nil
			}
		}
		return Target{}, fmt.Errorf("failed to parse address: empty host")
	}

	t.Host = host
	t.IsIP = net.ParseIP(host) != nil
	t.Port = u.Port()
	if hadScheme {
		t.Scheme = strings.ToLower(u.Scheme)
		if u.Path != "" && u.Path != "/" {
			t.Path = u.Path
		} else if u.Path == "/" && u.RawQuery != "" {
			t.Path = "/"
		} else if u.Path == "/" {
			t.Path = "/"
		}
		t.RawQuery = u.RawQuery
	} else if u.Path != "" && u.Path != "/" {
		// host/path without scheme — keep path for HTTP(S) probes
		t.Path = u.Path
		t.RawQuery = u.RawQuery
	}
	return t, nil
}

// getAddr extracts a hostname or IP (compat helper for tests).
func getAddr(addr string) (string, error) {
	t, err := parseTarget(addr)
	if err != nil {
		return "", err
	}
	return t.Host, nil
}

// validateOperand rejects values that look like option injection for external tools.
func validateOperand(s string) error {
	if s == "" {
		return fmt.Errorf("empty address")
	}
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("address %q looks like a flag; pass -- %s if intentional", s, s)
	}
	for _, r := range s {
		if r == 0 || (unicode.IsControl(r) && r != '\t') {
			return fmt.Errorf("address contains control characters")
		}
	}
	return nil
}
