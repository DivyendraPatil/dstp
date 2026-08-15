//go:build integration

package dstp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DivyendraPatil/dstp/config"
)

func TestRunAllTestsSkipAll(t *testing.T) {
	err := RunAllTests(context.Background(), config.Config{
		Addr:      "example.com",
		Output:    "json",
		Quiet:     true,
		Timeout:   2,
		PingCount: 1,
		Skip:      []string{"ping", "dns", "configured_dns", "records", "tcp", "udp", "tls", "http", "https"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunAllTestsLocalHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	host, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	err = RunAllTests(context.Background(), config.Config{
		Addr:      "http://" + net.JoinHostPort(host, port) + "/health",
		Output:    "json",
		Quiet:     true,
		Timeout:   3,
		PingCount: 1,
		HTTPPort:  port,
		Skip:      []string{"ping", "dns", "configured_dns", "records", "udp", "tls", "https", "tcp"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunAllTestsLocalTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	err = RunAllTests(context.Background(), config.Config{
		Addr:      "127.0.0.1",
		Output:    "json",
		Quiet:     true,
		Timeout:   3,
		PingCount: 1,
		TCPPort:   port,
		Skip:      []string{"ping", "dns", "configured_dns", "records", "udp", "tls", "http", "https"},
	})
	if err != nil {
		t.Fatal(err)
	}
}
