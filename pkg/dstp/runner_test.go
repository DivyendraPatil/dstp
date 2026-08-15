package dstp

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/DivyendraPatil/dstp/config"
	"github.com/DivyendraPatil/dstp/pkg/common"
)

func TestRunnerWithFakePing(t *testing.T) {
	var buf bytes.Buffer
	rn := &Runner{
		Stdout: &buf,
		Stderr: ioDiscard{},
		PingFunc: func(ctx context.Context, addr common.Address, count int, timeout time.Duration, result *common.Result) error {
			result.Store(&result.Ping, common.OK("avg=1ms fake"))
			return nil
		},
	}
	cfg := config.Config{
		Addr:      "example.com",
		Output:    "json",
		Quiet:     true,
		Timeout:   2,
		PingCount: 1,
		Skip:      []string{"dns", "configured_dns", "records", "tcp", "udp", "tls", "http", "https"},
	}
	result, err := rn.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result.Ping.Status != common.StatusOK || result.Ping.Content != "avg=1ms fake" {
		t.Fatalf("%+v", result.Ping)
	}
	rn.Render(cfg, result)
	if !bytes.Contains(buf.Bytes(), []byte("avg=1ms fake")) {
		t.Fatalf("render=%s", buf.String())
	}
}

func TestCheckIDsComplete(t *testing.T) {
	ids := CheckIDs()
	if len(ids) < 9 {
		t.Fatalf("%v", ids)
	}
	if !isExtraCheck("traceroute") || isExtraCheck("ping") {
		t.Fatal("extra meta")
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
