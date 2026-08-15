package lookup

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Data string `json:"data"`
		Type int    `json:"type"`
	} `json:"Answer"`
}

// lookupDoH queries a provider JSON DoH endpoint (application/dns-json) for A and AAAA.
// This is not RFC 8484 dns-message; the CLI documents it as provider-specific JSON DoH.
// If bootstrapIP is set, connections dial that IP while TLS uses the URL hostname as ServerName.
func lookupDoH(ctx context.Context, endpoint, host, bootstrapIP string, timeout time.Duration) ([]string, error) {
	if endpoint == "" {
		endpoint = "https://cloudflare-dns.com/dns-query"
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("DoH URL: %w", err)
	}
	if u.Scheme != "https" {
		h := u.Hostname()
		if u.Scheme != "http" || (h != "127.0.0.1" && h != "localhost" && h != "::1") {
			return nil, fmt.Errorf("DoH URL must use https")
		}
	}
	if u.Host == "" {
		return nil, fmt.Errorf("DoH URL missing host")
	}
	if !u.IsAbs() {
		return nil, fmt.Errorf("DoH URL must be absolute")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 2
	if bootstrapIP != "" {
		if net.ParseIP(bootstrapIP) == nil {
			return nil, fmt.Errorf("DoH bootstrap must be an IP")
		}
		port := u.Port()
		if port == "" {
			if u.Scheme == "http" {
				port = "80"
			} else {
				port = "443"
			}
		}
		dialAddr := net.JoinHostPort(bootstrapIP, port)
		serverName := u.Hostname()
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, dialAddr)
		}
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		}
		transport.TLSClientConfig.ServerName = serverName
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many DoH redirects")
			}
			next := via[len(via)-1].URL
			if next.Scheme != "https" {
				h := next.Hostname()
				if next.Scheme != "http" || (h != "127.0.0.1" && h != "localhost" && h != "::1") {
					return fmt.Errorf("refusing non-https DoH redirect")
				}
			}
			return nil
		},
	}
	defer transport.CloseIdleConnections()

	fetch := func(qtype string) ([]string, error) {
		uu := *u
		q := uu.Query()
		q.Set("name", host)
		q.Set("type", qtype)
		uu.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, uu.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/dns-json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("DoH %s: %w", qtype, err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("DoH %s body: %w", qtype, err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("DoH %s HTTP %s", qtype, resp.Status)
		}
		ct := resp.Header.Get("Content-Type")
		if ct != "" && !strings.Contains(ct, "json") && !strings.Contains(ct, "dns-json") {
			return nil, fmt.Errorf("DoH %s unexpected content-type %q", qtype, ct)
		}
		var parsed dohResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("DoH %s JSON: %w", qtype, err)
		}
		if parsed.Status != 0 {
			return nil, fmt.Errorf("DoH %s DNS status %d", qtype, parsed.Status)
		}
		wantType := 1
		if qtype == "AAAA" {
			wantType = 28
		}
		var addrs []string
		for _, a := range parsed.Answer {
			if a.Type != wantType {
				continue
			}
			ip := net.ParseIP(a.Data)
			if ip == nil {
				continue
			}
			if qtype == "A" && ip.To4() == nil {
				continue
			}
			if qtype == "AAAA" && ip.To4() != nil {
				continue
			}
			addrs = append(addrs, a.Data)
		}
		return addrs, nil
	}

	var (
		mu    sync.Mutex
		addrs []string
		errs  []error
	)
	var wg sync.WaitGroup
	for _, qt := range []string{"A", "AAAA"} {
		wg.Add(1)
		go func(qtype string) {
			defer wg.Done()
			a, err := fetch(qtype)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			addrs = append(addrs, a...)
		}(qt)
	}
	wg.Wait()

	if len(addrs) == 0 {
		if len(errs) > 0 {
			return nil, fmt.Errorf("DoH returned no addresses: %v", errs)
		}
		return nil, fmt.Errorf("DoH returned no addresses")
	}
	return addrs, nil
}
