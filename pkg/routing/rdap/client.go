// Package rdap implements IP and domain RDAP lookups via rdap.org bootstrap.
package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/routing"
)

const (
	defaultIPURL     = "https://rdap.org/ip/"
	defaultDomainURL = "https://rdap.org/domain/"
	maxBody          = 1 << 20
)

// Client performs RDAP lookups with timeouts and body limits.
type Client struct {
	IPBaseURL     string
	DomainBaseURL string
	HTTPClient    *http.Client
}

// New returns a Client with sensible defaults (follows redirects).
func New() *Client {
	return &Client{
		IPBaseURL:     defaultIPURL,
		DomainBaseURL: defaultDomainURL,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				MaxIdleConns:          4,
				IdleConnTimeout:       30 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
			},
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("stopped after 5 redirects")
				}
				return nil
			},
		},
	}
}

var _ routing.RDAPProvider = (*Client)(nil)

// LookupIP fetches registration data for a public IP.
func (c *Client) LookupIP(ctx context.Context, ip netip.Addr) (routing.RDAPInfo, error) {
	if !ip.IsValid() {
		return routing.RDAPInfo{}, fmt.Errorf("invalid IP")
	}
	if !routing.IsPublicRoutable(ip) {
		return routing.RDAPInfo{
			Kind:   "ip",
			Source: "local",
		}, fmt.Errorf("special-use address (%s): not queried", routing.ClassifyAddr(ip))
	}
	base := c.IPBaseURL
	if base == "" {
		base = defaultIPURL
	}
	return c.fetch(ctx, "ip", strings.TrimRight(base, "/")+"/"+ip.String())
}

// LookupDomain fetches registration data for a domain name.
func (c *Client) LookupDomain(ctx context.Context, domain string) (routing.RDAPInfo, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return routing.RDAPInfo{}, fmt.Errorf("empty domain")
	}
	if strings.ContainsAny(domain, "/?#") || strings.HasPrefix(domain, ".") {
		return routing.RDAPInfo{}, fmt.Errorf("invalid domain")
	}
	base := c.DomainBaseURL
	if base == "" {
		base = defaultDomainURL
	}
	return c.fetch(ctx, "domain", strings.TrimRight(base, "/")+"/"+domain)
}

func (c *Client) fetch(ctx context.Context, kind, rawURL string) (routing.RDAPInfo, error) {
	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return routing.RDAPInfo{}, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "dstp (https://github.com/DivyendraPatil/dstp)")

	resp, err := hc.Do(req)
	if err != nil {
		return routing.RDAPInfo{Kind: kind, Source: "rdap"}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return routing.RDAPInfo{Kind: kind, Source: "rdap"}, err
	}
	if resp.StatusCode >= 400 {
		return routing.RDAPInfo{Kind: kind, Source: "rdap"}, fmt.Errorf("rdap HTTP %s", resp.Status)
	}
	info, err := normalizeRDAP(kind, body)
	if err != nil {
		return routing.RDAPInfo{Kind: kind, Source: "rdap"}, err
	}
	info.Source = "rdap"
	return info, nil
}

type rdapDoc struct {
	Handle       string `json:"handle"`
	Name         string `json:"name"`
	Country      string `json:"country"`
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	LdhName      string `json:"ldhName"`
	Cidr0        []struct {
		V4Prefix string `json:"v4prefix"`
		V6Prefix string `json:"v6prefix"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs"`
	Events []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
	Entities []rdapEntity `json:"entities"`
	Notices  []struct {
		Title       string   `json:"title"`
		Description []string `json:"description"`
	} `json:"notices"`
}

type rdapEntity struct {
	Handle     string          `json:"handle"`
	Roles      []string        `json:"roles"`
	VCardArray json.RawMessage `json:"vcardArray"`
}

func normalizeRDAP(kind string, body []byte) (routing.RDAPInfo, error) {
	var doc rdapDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return routing.RDAPInfo{}, fmt.Errorf("rdap decode: %w", err)
	}
	info := routing.RDAPInfo{Kind: kind}
	info.Handle = strings.TrimSpace(doc.Handle)
	info.Name = strings.TrimSpace(doc.Name)
	if info.Name == "" {
		info.Name = strings.TrimSpace(doc.LdhName)
	}
	info.Country = strings.TrimSpace(doc.Country)
	info.StartAddress = strings.TrimSpace(doc.StartAddress)
	info.EndAddress = strings.TrimSpace(doc.EndAddress)
	info.CIDR = firstCIDR(doc.Cidr0)
	info.RIR = rirFromNotices(doc.Notices)

	for _, ev := range doc.Events {
		t, ok := parseRDAPTime(ev.EventDate)
		if !ok {
			continue
		}
		switch strings.ToLower(ev.EventAction) {
		case "registration":
			info.Registered = &t
		case "last changed", "last changed date", "last update of rdap database":
			info.LastChanged = &t
		}
	}

	for _, ent := range doc.Entities {
		fn, email := parseVCard(ent.VCardArray)
		roles := lowerRoles(ent.Roles)
		if contains(roles, "registrant") && info.Organization == "" && fn != "" {
			info.Organization = fn
		}
		if contains(roles, "abuse") && email != "" {
			info.AbuseContact = email
		}
		if info.Organization == "" && contains(roles, "administrative") && fn != "" {
			info.Organization = fn
		}
	}
	return info, nil
}

func firstCIDR(cidrs []struct {
	V4Prefix string `json:"v4prefix"`
	V6Prefix string `json:"v6prefix"`
	Length   int    `json:"length"`
}) string {
	if len(cidrs) == 0 {
		return ""
	}
	c := cidrs[0]
	if c.V4Prefix != "" && c.Length > 0 {
		return fmt.Sprintf("%s/%d", c.V4Prefix, c.Length)
	}
	if c.V6Prefix != "" && c.Length > 0 {
		return fmt.Sprintf("%s/%d", c.V6Prefix, c.Length)
	}
	return ""
}

func rirFromNotices(notices []struct {
	Title       string   `json:"title"`
	Description []string `json:"description"`
}) string {
	for _, n := range notices {
		if !strings.EqualFold(n.Title, "Source") {
			continue
		}
		for _, d := range n.Description {
			u := strings.ToUpper(strings.TrimSpace(d))
			for _, r := range []string{"ARIN", "RIPE", "APNIC", "AFRINIC", "LACNIC"} {
				if strings.Contains(u, r) {
					return r
				}
			}
		}
	}
	return ""
}

func parseRDAPTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func parseVCard(raw json.RawMessage) (fn, email string) {
	if len(raw) == 0 {
		return "", ""
	}
	// vcardArray: ["vcard", [ ["fn", {}, "text", "Name"], ["email", {}, "text", "a@b"], ... ]]
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) < 2 {
		return "", ""
	}
	var props [][]json.RawMessage
	if err := json.Unmarshal(arr[1], &props); err != nil {
		return "", ""
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var name string
		if err := json.Unmarshal(p[0], &name); err != nil {
			continue
		}
		var val string
		_ = json.Unmarshal(p[3], &val)
		switch strings.ToLower(name) {
		case "fn":
			if fn == "" {
				fn = val
			}
		case "email":
			if email == "" {
				email = val
			}
		}
	}
	return fn, email
}

func lowerRoles(roles []string) []string {
	out := make([]string, len(roles))
	for i, r := range roles {
		out[i] = strings.ToLower(r)
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
