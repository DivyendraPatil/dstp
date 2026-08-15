package dstp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

func withCheckTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	return context.WithTimeout(ctx, timeout)
}

func testTCP(ctx context.Context, address common.Address, port string, timeout time.Duration, result *common.Result) error {
	ctx, cancel := withCheckTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(string(address), port))
	if err != nil {
		result.Store(&result.TCP, common.Fail(err))
		return err
	}
	_ = conn.Close()

	msg := fmt.Sprintf("connected to %s in %s", net.JoinHostPort(string(address), port), time.Since(start).Round(time.Millisecond))
	result.Store(&result.TCP, common.OK(msg))
	return nil
}

func testUDP(ctx context.Context, address common.Address, port string, timeout time.Duration, result *common.Result) error {
	ctx, cancel := withCheckTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(string(address), port))
	if err != nil {
		result.Store(&result.UDP, common.Fail(err))
		return err
	}
	defer func() { _ = conn.Close() }()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}
	_ = conn.SetDeadline(deadline)

	// DNS-shaped probe (works for port 53); other ports may not reply.
	payload := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if port == "53" {
		if q, qerr := buildUDP53Query("."); qerr == nil {
			payload = q
		}
	}
	if _, err := conn.Write(payload); err != nil {
		result.Store(&result.UDP, common.Fail(fmt.Errorf("udp write: %w", err)))
		return err
	}

	buf := make([]byte, 512)
	n, rerr := conn.Read(buf)
	elapsed := time.Since(start).Round(time.Millisecond)
	target := net.JoinHostPort(string(address), port)

	if rerr == nil {
		result.Store(&result.UDP, common.OK(fmt.Sprintf("udp %s replied %dB in %s", target, n, elapsed)))
		return nil
	}

	var netErr net.Error
	switch {
	case errors.As(rerr, &netErr) && netErr.Timeout():
		result.Store(&result.UDP, common.Inconclusive(fmt.Sprintf("udp %s: no reply within %s (inconclusive)", target, elapsed)))
		return nil
	case errors.Is(rerr, context.Canceled), errors.Is(rerr, context.DeadlineExceeded):
		result.Store(&result.UDP, common.Fail(rerr))
		return rerr
	default:
		// ECONNREFUSED / network unreachable = peer/path problem
		result.Store(&result.UDP, common.Fail(fmt.Errorf("udp %s: %w", target, rerr)))
		return rerr
	}
}

func testTLS(ctx context.Context, address common.Address, port string, timeout time.Duration, insecure bool, result *common.Result) error {
	ctx, cancel := withCheckTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(string(address), port))
	if err != nil {
		result.Store(&result.TLS, common.Fail(err))
		return err
	}

	serverName := string(address)
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	verifyNote := ""
	if insecure {
		cfg.InsecureSkipVerify = true
		verifyNote = "verify=skipped (--insecure)"
	} else {
		// Go verifies IP SANs when ServerName is an IP literal.
		cfg.ServerName = serverName
	}

	conn := tls.Client(rawConn, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		result.Store(&result.TLS, common.Fail(err))
		return err
	}
	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		err := fmt.Errorf("no peer certificates")
		result.Store(&result.TLS, common.Fail(err))
		return err
	}

	cert := state.PeerCertificates[0]
	now := time.Now()
	if now.Before(cert.NotBefore) {
		part := common.Fail(fmt.Errorf("certificate not yet valid (NotBefore=%s)", cert.NotBefore.Format(time.RFC3339)))
		result.Store(&result.TLS, part)
		return part.Error
	}
	if now.After(cert.NotAfter) {
		part := common.Fail(fmt.Errorf("certificate expired (NotAfter=%s)", cert.NotAfter.Format(time.RFC3339)))
		result.Store(&result.TLS, part)
		return part.Error
	}

	until := cert.NotAfter.Sub(now)
	sans := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	if len(sans) > 5 {
		sans = append(sans[:5], fmt.Sprintf("…(+%d)", len(sans)-5))
	}

	chainLen := len(state.PeerCertificates)
	ocsp := "ocsp=none"
	if len(state.OCSPResponse) > 0 {
		ocsp = fmt.Sprintf("ocsp=stapled(%dB)", len(state.OCSPResponse))
	}
	ct := "ct=none"
	if n := len(state.SignedCertificateTimestamps); n > 0 {
		ct = fmt.Sprintf("ct=scts:%d", n)
	} else if hasEmbeddedSCT(cert) {
		ct = "ct=embedded"
	}

	var parts []string
	switch {
	case until > 30*24*time.Hour:
		parts = append(parts, fmt.Sprintf("valid until %s", cert.NotAfter.Format("2006-01-02")))
	case until > 14*24*time.Hour:
		parts = append(parts, fmt.Sprintf("expires in %s (warn <30d)", until.Round(time.Hour)))
	case until > 24*time.Hour:
		parts = append(parts, fmt.Sprintf("expires in %s (warn <14d)", until.Round(time.Hour)))
	default:
		parts = append(parts, fmt.Sprintf("expires in %s (warn <1d)", until.Round(time.Minute)))
	}
	parts = append(parts,
		"issuer="+cert.Issuer.CommonName,
		fmt.Sprintf("chain=%d", chainLen),
		ocsp,
		ct,
		"proto="+tlsVersion(state.Version),
		"cipher="+tls.CipherSuiteName(state.CipherSuite),
	)
	if verifyNote != "" {
		parts = append(parts, verifyNote)
	}
	if len(sans) > 0 {
		parts = append(parts, "SANs="+strings.Join(sans, ","))
	}

	content := strings.Join(parts, "; ")
	if until <= 30*24*time.Hour {
		result.Store(&result.TLS, common.Warn(content))
		return nil
	}
	result.Store(&result.TLS, common.OK(content))
	return nil
}

// OID for embedded Signed Certificate Timestamps (RFC 6962).
var oidEmbeddedSCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

func hasEmbeddedSCT(cert *x509.Certificate) bool {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidEmbeddedSCT) {
			return true
		}
	}
	return false
}

func buildUDP53Query(name string) ([]byte, error) {
	if name == "" {
		name = "."
	}
	if name != "." && !strings.HasSuffix(name, ".") {
		name += "."
	}
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x4453, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  n,
			Type:  dnsmessage.TypeNS,
			Class: dnsmessage.ClassINET,
		}},
	}
	return msg.Pack()
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func testHTTPS(ctx context.Context, target Target, port string, timeout time.Duration, method string, followRedirects, insecure bool, result *common.Result) error {
	return testHTTPScheme(ctx, "https", target, port, timeout, method, followRedirects, insecure, &result.HTTPS, result)
}

func testHTTP(ctx context.Context, target Target, port string, timeout time.Duration, method string, followRedirects bool, result *common.Result) error {
	return testHTTPScheme(ctx, "http", target, port, timeout, method, followRedirects, false, &result.HTTP, result)
}

func testHTTPScheme(ctx context.Context, scheme string, target Target, port string, timeout time.Duration, method string, followRedirects, insecure bool, dst *common.ResultPart, result *common.Result) error {
	ctx, cancel := withCheckTimeout(ctx, timeout)
	defer cancel()

	host := target.Host
	usePort := port
	path := "/"
	if target.Path != "" {
		path = target.Path
	}
	if target.Scheme == scheme && target.Port != "" {
		usePort = target.Port
	}
	rawURL := buildURL(scheme, host, usePort, path, target.RawQuery)

	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		result.Store(dst, common.Fail(err))
		return err
	}

	redirects := 0
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure && scheme == "https" {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}
	client := http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			redirects = len(via)
			if !followRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}
	defer transport.CloseIdleConnections()

	start := time.Now()
	resp, err := client.Do(req)
	ttfb := time.Since(start)
	if err != nil {
		result.Store(dst, common.Fail(err))
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)); err != nil {
		result.Store(dst, common.Fail(fmt.Errorf("read body: %w", err)))
		return err
	}

	parts := []string{
		fmt.Sprintf("%s %s", method, resp.Status),
		fmt.Sprintf("TTFB=%s", ttfb.Round(time.Millisecond)),
		"url=" + rawURL,
	}
	if redirects > 0 {
		parts = append(parts, fmt.Sprintf("redirects=%d", redirects))
		if resp.Request != nil && resp.Request.URL != nil {
			parts = append(parts, "final="+resp.Request.URL.String())
		}
	}
	if loc := resp.Header.Get("Location"); loc != "" && !followRedirects {
		parts = append(parts, "location="+loc)
	}
	if resp.TLS != nil {
		parts = append(parts, "proto="+tlsVersion(resp.TLS.Version))
	}
	if resp.Proto != "" {
		parts = append(parts, "http="+resp.Proto)
	}

	content := strings.Join(parts, "; ")
	// Transport reachability vs application health: 4xx proves HTTP spoke.
	switch {
	case resp.StatusCode >= 500:
		part := common.Fail(fmt.Errorf("%s", content))
		result.Store(dst, part)
		return part.Error
	case resp.StatusCode >= 400:
		result.Store(dst, common.Warn(content+" (application error)"))
		return nil
	default:
		result.Store(dst, common.OK(content))
		return nil
	}
}

func buildURL(scheme, host, port, path, rawQuery string) string {
	defaultPort := "443"
	if scheme == "http" {
		defaultPort = "80"
	}
	if path == "" {
		path = "/"
	}
	var base string
	if port == "" || port == defaultPort {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			base = scheme + "://" + net.JoinHostPort(host, defaultPort)
		} else {
			base = scheme + "://" + host
		}
	} else {
		base = scheme + "://" + net.JoinHostPort(host, port)
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u := base + path
	if rawQuery != "" {
		u += "?" + rawQuery
	}
	return u
}
