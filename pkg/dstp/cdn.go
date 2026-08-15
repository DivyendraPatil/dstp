package dstp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

func testCDN(ctx context.Context, target Target, port string, timeout time.Duration, insecure bool, result *common.Result) error {
	ctx, cancel := withCheckTimeout(ctx, timeout)
	defer cancel()

	host := target.Host
	usePort := port
	if target.Scheme == "https" && target.Port != "" {
		usePort = target.Port
	}
	path := "/"
	if target.Path != "" {
		path = target.Path
	}

	var parts []string
	var warn bool

	// Resolve first address for ASN hint.
	ipHint := ""
	if ip := net.ParseIP(host); ip != nil {
		ipHint = ip.String()
	} else {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err == nil && len(addrs) > 0 {
			ipHint = addrs[0].IP.String()
		}
	}
	if ipHint != "" {
		parts = append(parts, "ip="+ipHint)
		if asn, org, err := lookupCymruASN(ctx, ipHint, timeout); err == nil {
			if asn != "" {
				parts = append(parts, "asn="+asn)
			}
			if org != "" {
				parts = append(parts, "cc="+org)
			}
		}
	}

	rawURL := buildURL("https", host, usePort, path, target.RawQuery)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		result.Store(&result.CDN, common.Fail(err))
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		// Fall back to GET if HEAD blocked.
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			result.Store(&result.CDN, common.Fail(err))
			return err
		}
		resp, err = client.Do(req)
	}
	if err != nil {
		if len(parts) > 0 {
			result.Store(&result.CDN, common.Warn(strings.Join(parts, "; ")+"; https probe failed: "+err.Error()))
			return nil
		}
		result.Store(&result.CDN, common.Fail(err))
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	hints := detectCDNHints(resp.Header)
	parts = append(parts, hints...)
	if len(hints) == 0 {
		parts = append(parts, "edge=unknown")
		warn = true
	}

	content := strings.Join(parts, "; ")
	if warn {
		result.Store(&result.CDN, common.Warn(content))
		return nil
	}
	result.Store(&result.CDN, common.OK(content))
	return nil
}

func detectCDNHints(h http.Header) []string {
	var out []string
	if v := h.Get("CF-RAY"); v != "" {
		out = append(out, "cdn=cloudflare", "cf-ray="+clipHeader(v, 40))
	}
	if v := h.Get("CF-Cache-Status"); v != "" {
		out = append(out, "cf-cache="+v)
	}
	if v := h.Get("X-Served-By"); v != "" && strings.Contains(strings.ToLower(v), "cache") {
		out = append(out, "cdn=fastly", "x-served-by="+clipHeader(v, 40))
	}
	if v := h.Get("X-Cache"); v != "" && strings.Contains(strings.ToLower(h.Get("Via")+v), "akamai") {
		out = append(out, "cdn=akamai", "x-cache="+clipHeader(v, 40))
	}
	if v := h.Get("X-Amz-Cf-Id"); v != "" || h.Get("X-Amz-Cf-Pop") != "" {
		out = append(out, "cdn=cloudfront")
		if id := h.Get("X-Amz-Cf-Id"); id != "" {
			out = append(out, "cf-id="+clipHeader(id, 24))
		}
	}
	if v := h.Get("X-Azure-Ref"); v != "" {
		out = append(out, "cdn=azure", "x-azure-ref="+clipHeader(v, 40))
	}
	if v := h.Get("Server"); v != "" {
		out = append(out, "server="+clipHeader(v, 40))
		low := strings.ToLower(v)
		if strings.Contains(low, "cloudflare") && !containsCDN(out, "cloudflare") {
			out = append([]string{"cdn=cloudflare"}, out...)
		}
	}
	if v := h.Get("Via"); v != "" {
		out = append(out, "via="+clipHeader(v, 60))
	}
	if v := h.Get("Alt-Svc"); v != "" && strings.Contains(strings.ToLower(v), "h3") {
		out = append(out, "alt-svc=h3")
	}
	return uniquePreserve(out)
}

func containsCDN(parts []string, name string) bool {
	want := "cdn=" + name
	for _, p := range parts {
		if p == want {
			return true
		}
	}
	return false
}

func uniquePreserve(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// lookupCymruASN uses Team Cymru DNS TXT (origin.asn.cymru.com / origin6).
// AS org names via asn.cymru.com are often DNSSEC-broken at public resolvers,
// so we only report the ASN from the origin record.
func lookupCymruASN(ctx context.Context, ipStr string, timeout time.Duration) (asn, org string, err error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", "", fmt.Errorf("bad ip")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var qname string
	if v4 := ip.To4(); v4 != nil {
		qname = fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	} else {
		exp := expandIPv6(ip)
		var nibbles []string
		for i := len(exp) - 1; i >= 0; i-- {
			nibbles = append(nibbles, string(exp[i]))
		}
		qname = strings.Join(nibbles, ".") + ".origin6.asn.cymru.com"
	}

	txts, err := net.DefaultResolver.LookupTXT(ctx, qname)
	if err != nil || len(txts) == 0 {
		return "", "", fmt.Errorf("cymru: %w", err)
	}
	// "13335 | 104.16.0.0/13 | US | arin | 2014-03-28"
	fields := strings.Split(txts[0], "|")
	if len(fields) > 0 {
		asn = "AS" + strings.TrimSpace(fields[0])
	}
	if len(fields) >= 3 {
		cc := strings.TrimSpace(fields[2])
		if cc != "" {
			org = cc // country code as light geo hint when AS name is unavailable
		}
	}
	return asn, org, nil
}

func expandIPv6(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	var b strings.Builder
	for i := 0; i < 16; i++ {
		fmt.Fprintf(&b, "%02x", ip[i])
	}
	return b.String()
}
