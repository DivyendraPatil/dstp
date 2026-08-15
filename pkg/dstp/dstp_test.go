//go:build integration

package dstp

import (
	"context"
	"testing"

	"github.com/DivyendraPatil/dstp/config"
)

func TestRunAllTests(t *testing.T) {
	ctx := context.Background()

	configs := []config.Config{
		{Addr: "https://example.com", Output: "plaintext", Timeout: 8, PingCount: 1, Quiet: true, Skip: []string{"ping", "udp", "records"}},
		{Addr: "8.8.8.8", Output: "json", Timeout: 8, PingCount: 1, Quiet: true, Skip: []string{"ping", "https", "http", "tls"}},
		{Addr: "example.com", Output: "plaintext", Timeout: 8, PingCount: 1, Quiet: true, FollowRedirects: true, Skip: []string{"ping", "udp"}},
	}

	for _, conf := range configs {
		err := RunAllTests(ctx, conf)
		if err != nil {
			t.Fatalf("addr=%s: %v", conf.Addr, err)
		}
	}
}
