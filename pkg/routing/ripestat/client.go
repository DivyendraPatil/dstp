// Package ripestat implements ASN lookup via the RIPEstat Data API
// (https://stat.ripe.net) with no API key.
package ripestat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/routing"
)

const (
	defaultBaseURL = "https://stat.ripe.net"
	sourceApp      = "dstp"
	maxBody        = 1 << 20
)

// Client looks up IP → ASN/prefix via RIPEstat network-info + as-overview.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	SourceApp  string
}

// New returns a Client with sensible defaults.
func New() *Client {
	return &Client{
		BaseURL: defaultBaseURL,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				MaxIdleConns:          4,
				IdleConnTimeout:       30 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
			},
		},
		SourceApp: sourceApp,
	}
}

var _ routing.ASNProvider = (*Client)(nil)

// LookupIP returns origin ASN and announced prefix for a public IP.
// Special-use addresses return a zero ASNInfo and a descriptive error
// without contacting RIPEstat.
func (c *Client) LookupIP(ctx context.Context, ip netip.Addr) (routing.ASNInfo, error) {
	if !ip.IsValid() {
		return routing.ASNInfo{}, fmt.Errorf("invalid IP")
	}
	if !routing.IsPublicRoutable(ip) {
		return routing.ASNInfo{
			IP:     ip,
			Source: "local",
		}, fmt.Errorf("special-use address (%s): not queried", routing.ClassifyAddr(ip))
	}

	base := c.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	app := c.SourceApp
	if app == "" {
		app = sourceApp
	}

	ni, err := c.networkInfo(ctx, hc, base, app, ip)
	if err != nil {
		return routing.ASNInfo{IP: ip, Source: "ripestat"}, err
	}

	info := routing.ASNInfo{
		IP:     ip,
		Source: "ripestat",
	}
	if ni.Prefix != "" {
		if p, perr := netip.ParsePrefix(ni.Prefix); perr == nil {
			info.Prefix = p
		}
	}
	if len(ni.ASNs) == 0 {
		return info, fmt.Errorf("ripestat: no origin ASN for %s", ip)
	}
	asn, err := strconv.ParseUint(strings.TrimSpace(ni.ASNs[0]), 10, 32)
	if err != nil {
		return info, fmt.Errorf("ripestat: bad ASN %q: %w", ni.ASNs[0], err)
	}
	info.ASN = uint32(asn)

	if holder, rir, herr := c.asOverview(ctx, hc, base, app, info.ASN); herr == nil {
		info.Name = holder
		info.Organization = holder
		info.RIR = rir
	}
	return info, nil
}

type networkInfoData struct {
	ASNs   []string `json:"asns"`
	Prefix string   `json:"prefix"`
}

func (c *Client) networkInfo(ctx context.Context, hc *http.Client, base, app string, ip netip.Addr) (networkInfoData, error) {
	var out networkInfoData
	u, err := url.Parse(strings.TrimRight(base, "/") + "/data/network-info/data.json")
	if err != nil {
		return out, err
	}
	q := u.Query()
	q.Set("resource", ip.String())
	q.Set("sourceapp", app)
	u.RawQuery = q.Encode()

	body, err := getJSON(ctx, hc, u.String())
	if err != nil {
		return out, err
	}
	var wrap struct {
		Status string          `json:"status"`
		Data   networkInfoData `json:"data"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return out, fmt.Errorf("ripestat network-info: decode: %w", err)
	}
	if wrap.Status != "ok" {
		return out, fmt.Errorf("ripestat network-info: status %q", wrap.Status)
	}
	return wrap.Data, nil
}

func (c *Client) asOverview(ctx context.Context, hc *http.Client, base, app string, asn uint32) (holder, rir string, err error) {
	u, err := url.Parse(strings.TrimRight(base, "/") + "/data/as-overview/data.json")
	if err != nil {
		return "", "", err
	}
	q := u.Query()
	q.Set("resource", strconv.FormatUint(uint64(asn), 10))
	q.Set("sourceapp", app)
	u.RawQuery = q.Encode()

	body, err := getJSON(ctx, hc, u.String())
	if err != nil {
		return "", "", err
	}
	var wrap struct {
		Status string `json:"status"`
		Data   struct {
			Holder string `json:"holder"`
			Block  struct {
				Desc string `json:"desc"`
				Name string `json:"name"`
			} `json:"block"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return "", "", err
	}
	if wrap.Status != "ok" {
		return "", "", fmt.Errorf("status %q", wrap.Status)
	}
	holder = strings.TrimSpace(wrap.Data.Holder)
	rir = inferRIR(wrap.Data.Block.Desc, wrap.Data.Block.Name)
	return holder, rir, nil
}

func inferRIR(desc, name string) string {
	s := strings.ToUpper(desc + " " + name)
	for _, r := range []string{"ARIN", "RIPE", "APNIC", "AFRINIC", "LACNIC"} {
		if strings.Contains(s, r) {
			if r == "RIPE" {
				return "RIPE"
			}
			return r
		}
	}
	return ""
}

func getJSON(ctx context.Context, hc *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dstp/"+sourceApp+" (https://github.com/DivyendraPatil/dstp)")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	return body, nil
}
