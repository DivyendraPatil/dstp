//go:build integration

package dstp

import (
	"context"
	"errors"
	"testing"

	"github.com/DivyendraPatil/dstp/config"
)

func TestRunAllTests(t *testing.T) {
	ctx := context.Background()

	configs := []config.Config{
		{Addr: "https://example.com", Output: "plaintext", Timeout: 5, PingCount: 1, Quiet: true, Skip: []string{"ping"}},
		{Addr: "8.8.8.8", Output: "json", Timeout: 5, PingCount: 1, Quiet: true, Skip: []string{"ping", "records", "https"}},
		{Addr: "example.com", Output: "plaintext", Timeout: 5, PingCount: 1, Quiet: true, FollowRedirects: true, Skip: []string{"ping"}},
	}

	for _, conf := range configs {
		err := RunAllTests(ctx, conf)
		if err != nil && !errors.Is(err, ErrChecksFailed) {
			t.Fatalf("addr=%s: %v", conf.Addr, err)
		}
	}
}
