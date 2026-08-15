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

	"github.com/ycd/dstp/pkg/common"
)

func testTCP(ctx context.Context, address common.Address, port string, timeout time.Duration, result *common.Result) error {
	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
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

func testTLS(ctx context.Context, address common.Address, port string, timeout time.Duration, result *common.Result) error {
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(string(address), port))
	if err != nil {
		result.Store(&result.TLS, common.Fail(err))
		return err
	}

	serverName := string(address)
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if net.ParseIP(serverName) != nil {
		// IP targets: cannot verify hostname against typical certs.
		cfg.InsecureSkipVerify = true
	} else {
		cfg.ServerName = serverName
	}

	conn := tls.Client(rawConn, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		result.Store(&result.TLS, common.Fail(err))
		return err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		err := fmt.Errorf("no peer certificates")
		result.Store(&result.TLS, common.Fail(err))
		return err
	}

	cert := state.PeerCertificates[0]
	days := int(time.Until(cert.NotAfter).Hours() / 24)

	sans := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	if len(sans) > 5 {
		sans = append(sans[:5], fmt.Sprintf("…(+%d)", len(sans)-5))
	}

	var parts []string
	switch {
	case days > 30:
		parts = append(parts, fmt.Sprintf("valid %d days", days))
	case days > 0:
		parts = append(parts, fmt.Sprintf("expires in %d days (warn)", days))
	default:
		parts = append(parts, fmt.Sprintf("expired %d days ago", -days))
	}
	parts = append(parts,
		"issuer="+cert.Issuer.CommonName,
		"proto="+tlsVersion(state.Version),
		"cipher="+tls.CipherSuiteName(state.CipherSuite),
	)
	if len(sans) > 0 {
		parts = append(parts, "SANs="+strings.Join(sans, ","))
	}

	content := strings.Join(parts, "; ")
	if days <= 0 {
		part := common.Fail(fmt.Errorf("%s", content))
		result.Store(&result.TLS, part)
		return part.Error
	}
	result.Store(&result.TLS, common.OK(content))
	return nil
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

func testHTTPS(ctx context.Context, address common.Address, port string, timeout time.Duration, method string, followRedirects bool, result *common.Result) error {
	rawURL := httpsURL(address.String(), port)

	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		result.Store(&result.HTTPS, common.Fail(err))
		return err
	}

	redirects := 0
	client := http.Client{
		Timeout: timeout,
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

	start := time.Now()
	resp, err := client.Do(req)
	ttfb := time.Since(start)
	if err != nil {
		result.Store(&result.HTTPS, common.Fail(err))
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	parts := []string{
		fmt.Sprintf("%s %s", method, resp.Status),
		fmt.Sprintf("TTFB=%s", ttfb.Round(time.Millisecond)),
	}
	if redirects > 0 {
		parts = append(parts, fmt.Sprintf("redirects=%d", redirects))
	}
	if loc := resp.Header.Get("Location"); loc != "" && !followRedirects {
		parts = append(parts, "location="+loc)
	}
	if resp.TLS != nil {
		parts = append(parts, "proto="+tlsVersion(resp.TLS.Version))
	}

	content := strings.Join(parts, "; ")
	if resp.StatusCode >= 400 {
		part := common.Fail(fmt.Errorf("%s", content))
		result.Store(&result.HTTPS, part)
		return part.Error
	}
	result.Store(&result.HTTPS, common.OK(content))
	return nil
}

func httpsURL(host, port string) string {
	if port == "" || port == "443" {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			return "https://" + net.JoinHostPort(host, "443")
		}
		return "https://" + host
	}
	return "https://" + net.JoinHostPort(host, port)
}
