package lookup

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DoHFormat selects the DoH wire format.
type DoHFormat string

const (
	DoHFormatRFC8484 DoHFormat = "rfc8484" // application/dns-message (RFC 8484)
	DoHFormatJSON    DoHFormat = "json"    // application/dns-json (provider-specific)
)

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Data string `json:"data"`
		Type int    `json:"type"`
	} `json:"Answer"`
}

// lookupDoH resolves A/AAAA via DoH. format defaults to RFC 8484 dns-message.
// If bootstrapIP is set, connections dial that IP while TLS uses the URL hostname as ServerName.
func lookupDoH(ctx context.Context, endpoint, host, bootstrapIP string, timeout time.Duration, format DoHFormat) ([]string, error) {
	if endpoint == "" {
		endpoint = "https://cloudflare-dns.com/dns-query"
	}
	if format == "" {
		format = DoHFormatRFC8484
	}
	u, err := parseDoHURL(endpoint)
	if err != nil {
		return nil, err
	}
	client, cleanup, err := newDoHClient(u, bootstrapIP, timeout)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	fetch := func(qtype dnsmessage.Type) ([]string, error) {
		switch format {
		case DoHFormatJSON:
			return fetchDoHJSON(ctx, client, u, host, qtype)
		default:
			return fetchDoHMessage(ctx, client, u, host, qtype)
		}
	}

	var (
		mu    sync.Mutex
		addrs []string
		errs  []error
	)
	var wg sync.WaitGroup
	for _, qt := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		wg.Add(1)
		go func(qtype dnsmessage.Type) {
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

func parseDoHURL(endpoint string) (*url.URL, error) {
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
	return u, nil
}

func newDoHClient(u *url.URL, bootstrapIP string, timeout time.Duration) (*http.Client, func(), error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 2
	if bootstrapIP != "" {
		if net.ParseIP(bootstrapIP) == nil {
			return nil, nil, fmt.Errorf("DoH bootstrap must be an IP")
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
	return client, transport.CloseIdleConnections, nil
}

func buildDNSQuery(host string, qtype dnsmessage.Type) ([]byte, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	return msg.Pack()
}

func fetchDoHMessage(ctx context.Context, client *http.Client, u *url.URL, host string, qtype dnsmessage.Type) ([]string, error) {
	payload, err := buildDNSQuery(host, qtype)
	if err != nil {
		return nil, fmt.Errorf("DoH pack: %w", err)
	}

	// Prefer POST (RFC 8484); fall back to GET with dns= base64url.
	addrs, err := dohMessagePOST(ctx, client, u, payload, qtype)
	if err == nil {
		return addrs, nil
	}
	addrs, gerr := dohMessageGET(ctx, client, u, payload, qtype)
	if gerr == nil {
		return addrs, nil
	}
	return nil, fmt.Errorf("DoH rfc8484 POST: %v; GET: %w", err, gerr)
}

func dohMessagePOST(ctx context.Context, client *http.Client, u *url.URL, payload []byte, qtype dnsmessage.Type) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	return dohMessageDo(client, req, qtype)
}

func dohMessageGET(ctx context.Context, client *http.Client, u *url.URL, payload []byte, qtype dnsmessage.Type) ([]string, error) {
	uu := *u
	q := uu.Query()
	q.Set("dns", base64.RawURLEncoding.EncodeToString(payload))
	uu.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uu.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	return dohMessageDo(client, req, qtype)
}

func dohMessageDo(client *http.Client, req *http.Request, qtype dnsmessage.Type) ([]string, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "" && strings.Contains(ct, "json") {
		return nil, fmt.Errorf("unexpected content-type %q (want dns-message)", ct)
	}
	return parseDNSMessageAnswers(body, qtype)
}

func parseDNSMessageAnswers(body []byte, want dnsmessage.Type) ([]string, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(body)
	if err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DNS rcode %v", hdr.RCode)
	}
	for {
		if _, err := p.Question(); err != nil {
			break
		}
	}
	var addrs []string
	for {
		rh, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch rh.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, err
			}
			if want == dnsmessage.TypeA {
				ip := net.IP(r.A[:])
				addrs = append(addrs, ip.String())
			}
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, err
			}
			if want == dnsmessage.TypeAAAA {
				ip := net.IP(r.AAAA[:])
				addrs = append(addrs, ip.String())
			}
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
		}
	}
	return addrs, nil
}

func fetchDoHJSON(ctx context.Context, client *http.Client, u *url.URL, host string, qtype dnsmessage.Type) ([]string, error) {
	uu := *u
	q := uu.Query()
	q.Set("name", host)
	switch qtype {
	case dnsmessage.TypeAAAA:
		q.Set("type", "AAAA")
	default:
		q.Set("type", "A")
	}
	uu.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uu.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH json: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("DoH json body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH json HTTP %s", resp.Status)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "json") && !strings.Contains(ct, "dns-json") {
		return nil, fmt.Errorf("DoH json unexpected content-type %q", ct)
	}
	var parsed dohResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("DoH json: %w", err)
	}
	if parsed.Status != 0 {
		return nil, fmt.Errorf("DoH json DNS status %d", parsed.Status)
	}
	wantType := 1
	if qtype == dnsmessage.TypeAAAA {
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
		if qtype == dnsmessage.TypeA && ip.To4() == nil {
			continue
		}
		if qtype == dnsmessage.TypeAAAA && ip.To4() != nil {
			continue
		}
		addrs = append(addrs, a.Data)
	}
	return addrs, nil
}
