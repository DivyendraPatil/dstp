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

	"github.com/quic-go/quic-go/http3"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

func testHTTP3(ctx context.Context, target Target, port string, timeout time.Duration, method string, insecure bool, result *common.Result) error {
	ctx, cancel := withCheckTimeout(ctx, timeout)
	defer cancel()

	host := target.Host
	usePort := port
	path := "/"
	if target.Path != "" {
		path = target.Path
	}
	if target.Scheme == "https" && target.Port != "" {
		usePort = target.Port
	}
	rawURL := buildURL("https", host, usePort, path, target.RawQuery)

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{http3.NextProtoH3},
	}
	if insecure {
		tlsCfg.InsecureSkipVerify = true
	} else if net.ParseIP(host) == nil {
		tlsCfg.ServerName = host
	}

	tr := &http3.Transport{TLSClientConfig: tlsCfg}
	defer func() { _ = tr.Close() }()

	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		result.Store(&result.HTTP3, common.Fail(err))
		return err
	}

	start := time.Now()
	resp, err := client.Do(req)
	ttfb := time.Since(start)
	if err != nil {
		result.Store(&result.HTTP3, common.Inconclusive(fmt.Sprintf("HTTP/3 unavailable: %v", err)))
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	parts := []string{
		fmt.Sprintf("%s %s", method, resp.Status),
		fmt.Sprintf("TTFB=%s", ttfb.Round(time.Millisecond)),
		"url=" + rawURL,
		"http=HTTP/3",
	}
	if alt := resp.Header.Get("Alt-Svc"); alt != "" {
		parts = append(parts, "alt-svc="+clipHeader(alt, 80))
	}

	content := strings.Join(parts, "; ")
	switch {
	case resp.StatusCode >= 500:
		part := common.Fail(fmt.Errorf("%s", content))
		result.Store(&result.HTTP3, part)
		return part.Error
	case resp.StatusCode >= 400:
		result.Store(&result.HTTP3, common.Warn(content+" (application error)"))
		return nil
	default:
		result.Store(&result.HTTP3, common.OK(content))
		return nil
	}
}

func clipHeader(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
