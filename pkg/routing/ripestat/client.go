// Package ripestat implements ASN lookup via the RIPEstat Data API
// (https://stat.ripe.net) with no API key.
package ripestat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/routing"
	"github.com/DivyendraPatil/dstp/pkg/routing/httpx"
)

const (
	defaultBaseURL = "https://stat.ripe.net"
	sourceApp      = "dstp"
)

// Client looks up IP → ASN/prefix/RPKI via RIPEstat Data API.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	SourceApp  string
}

// New returns a Client with sensible defaults.
func New() *Client {
	return &Client{
		BaseURL:    defaultBaseURL,
		HTTPClient: httpx.NewClient(15 * time.Second),
		SourceApp:  sourceApp,
	}
}

var (
	_ routing.ASNProvider     = (*Client)(nil)
	_ routing.RPKIProvider    = (*Client)(nil)
	_ routing.RoutingProvider = (*Client)(nil)
)

func (c *Client) endpoints() (base string, hc *http.Client, app string) {
	base = c.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	hc = c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	app = c.SourceApp
	if app == "" {
		app = sourceApp
	}
	return base, hc, app
}

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

	base, hc, app := c.endpoints()
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

// Validate checks RPKI origin validity for prefix + ASN via RIPEstat.
// Transport/API failures return status unknown (never invalid).
func (c *Client) Validate(ctx context.Context, prefix netip.Prefix, asn uint32) (routing.RPKIResult, error) {
	out := routing.RPKIResult{
		Prefix:    prefix,
		OriginASN: asn,
		Source:    "ripestat",
		Status:    routing.RPKIUnknown,
	}
	if !prefix.IsValid() || asn == 0 {
		out.Description = "missing prefix or ASN"
		return out, fmt.Errorf("ripestat rpki: missing prefix or ASN")
	}

	base, hc, app := c.endpoints()
	u, err := url.Parse(strings.TrimRight(base, "/") + "/data/rpki-validation/data.json")
	if err != nil {
		return out, err
	}
	q := u.Query()
	q.Set("resource", strconv.FormatUint(uint64(asn), 10))
	q.Set("prefix", prefix.String())
	q.Set("sourceapp", app)
	u.RawQuery = q.Encode()

	body, err := getJSON(ctx, hc, u.String())
	if err != nil {
		out.Description = err.Error()
		return out, err
	}
	var wrap struct {
		Status string `json:"status"`
		Data   struct {
			Status         string `json:"status"`
			Prefix         string `json:"prefix"`
			Resource       string `json:"resource"`
			ValidatingROAs []struct {
				Origin    string `json:"origin"`
				Prefix    string `json:"prefix"`
				Validity  string `json:"validity"`
				MaxLength int    `json:"max_length"`
			} `json:"validating_roas"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		out.Description = "decode error"
		return out, fmt.Errorf("ripestat rpki: decode: %w", err)
	}
	if wrap.Status != "ok" {
		out.Description = "api status " + wrap.Status
		return out, fmt.Errorf("ripestat rpki: status %q", wrap.Status)
	}

	st, detail := routing.MapRIPERPKIStatus(wrap.Data.Status)
	out.Status = st
	out.Detail = detail
	out.Description = wrap.Data.Status
	if p, perr := netip.ParsePrefix(wrap.Data.Prefix); perr == nil {
		out.Prefix = p
	}

	// Prefer an ROA whose validity matches the overall status; else first ROA.
	for i := range wrap.Data.ValidatingROAs {
		roa := wrap.Data.ValidatingROAs[i]
		if detail != "" && roa.Validity != detail && roa.Validity != wrap.Data.Status {
			continue
		}
		matched := parseROA(roa.Origin, roa.Prefix, roa.MaxLength)
		if matched != nil {
			out.MatchedROA = matched
			break
		}
	}
	if out.MatchedROA == nil && len(wrap.Data.ValidatingROAs) > 0 {
		roa := wrap.Data.ValidatingROAs[0]
		out.MatchedROA = parseROA(roa.Origin, roa.Prefix, roa.MaxLength)
	}
	return out, nil
}

func parseROA(origin, prefix string, maxLen int) *routing.ROA {
	asn64, err := strconv.ParseUint(strings.TrimSpace(origin), 10, 32)
	if err != nil {
		return nil
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(prefix))
	if err != nil {
		return nil
	}
	return &routing.ROA{ASN: uint32(asn64), Prefix: p, MaxLength: maxLen}
}

// LookupRouting combines ASN/prefix lookup with RPKI validation.
// ASN lookup failure fails the call; RPKI failure yields status unknown
// and does not fail the overall result.
func (c *Client) LookupRouting(ctx context.Context, ip netip.Addr) (routing.RoutingInfo, error) {
	info := routing.RoutingInfo{IP: ip, Source: "ripestat"}
	asn, err := c.LookupIP(ctx, ip)
	if err != nil {
		info.ASN = asn
		info.RPKI = routing.RPKIResult{Status: routing.RPKIUnknown, Source: "ripestat", Description: "asn lookup failed"}
		return info, err
	}
	info.ASN = asn

	if !asn.Prefix.IsValid() || asn.ASN == 0 {
		info.RPKI = routing.RPKIResult{
			Status:      routing.RPKIUnknown,
			Source:      "ripestat",
			Description: "missing prefix or ASN for RPKI",
		}
		return info, nil
	}

	rpki, rerr := c.Validate(ctx, asn.Prefix, asn.ASN)
	if rerr != nil {
		// Provider unavailable → unknown, not invalid.
		info.RPKI = routing.RPKIResult{
			Status:      routing.RPKIUnknown,
			Prefix:      asn.Prefix,
			OriginASN:   asn.ASN,
			Source:      "ripestat",
			Description: rerr.Error(),
		}
		return info, nil
	}
	info.RPKI = rpki
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
	body, status, err := httpx.GetLimited(ctx, hc, rawURL, "application/json",
		"dstp/"+sourceApp+" (https://github.com/DivyendraPatil/dstp)", httpx.DefaultMaxBody)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("HTTP %d", status)
	}
	return body, nil
}
