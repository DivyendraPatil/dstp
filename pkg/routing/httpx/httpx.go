// Package httpx provides a small shared HTTP client for routing providers
// (RIPEstat, RDAP) with timeouts, body limits, and a consistent User-Agent.
package httpx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// DefaultMaxBody is the response body cap for enrichment APIs.
	DefaultMaxBody = 1 << 20
	// DefaultUserAgent identifies dstp to registries and RIPEstat.
	DefaultUserAgent = "dstp (https://github.com/DivyendraPatil/dstp)"
)

// NewClient returns an HTTP client with proxy, timeouts, and connection limits
// suitable for short enrichment lookups.
func NewClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}
}

// NewRedirectClient is like NewClient but follows a bounded number of redirects.
func NewRedirectClient(timeout time.Duration, maxRedirects int) *http.Client {
	c := NewClient(timeout)
	if maxRedirects < 1 {
		maxRedirects = 5
	}
	c.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		return nil
	}
	return c
}

// GetLimited performs GET with Accept/User-Agent and reads at most maxBody bytes.
func GetLimited(ctx context.Context, hc *http.Client, rawURL, accept, userAgent string, maxBody int64) ([]byte, int, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}
