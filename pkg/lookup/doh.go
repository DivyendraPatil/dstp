package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Data string `json:"data"`
		Type int    `json:"type"`
	} `json:"Answer"`
}

// lookupDoH queries a DNS-over-HTTPS JSON endpoint for A and AAAA records.
func lookupDoH(ctx context.Context, endpoint, host string, timeout time.Duration) ([]string, error) {
	if endpoint == "" {
		endpoint = "https://cloudflare-dns.com/dns-query"
	}
	client := &http.Client{Timeout: timeout}

	fetch := func(qtype string) ([]string, error) {
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("name", host)
		q.Set("type", qtype)
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/dns-json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("DoH status %s", resp.Status)
		}
		var parsed dohResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, err
		}
		wantType := 1
		if qtype == "AAAA" {
			wantType = 28
		}
		var addrs []string
		for _, a := range parsed.Answer {
			if a.Type == wantType {
				addrs = append(addrs, a.Data)
			}
		}
		return addrs, nil
	}

	var addrs []string
	if a, err := fetch("A"); err == nil {
		addrs = append(addrs, a...)
	}
	if a, err := fetch("AAAA"); err == nil {
		addrs = append(addrs, a...)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("DoH returned no addresses")
	}
	return addrs, nil
}
