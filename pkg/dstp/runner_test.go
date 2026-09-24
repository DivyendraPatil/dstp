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
			result.Store(common.KeyPing, common.OK("avg=1ms fake"))
			return nil
		},
	}
	cfg := config.Config{
		Addr:      "example.com",
		Output:    "json",
		Quiet:     true,
		Timeout:   2,
		PingCount: 1,
		Skip:      []string{"dns", "configured_dns", "records", "mail", "dnssec", "routing", "rdap", "tcp", "udp", "tls", "http", "https", "http3", "cdn"},
	}
	result, err := rn.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result.Get(common.KeyPing).Status != common.StatusOK || result.Get(common.KeyPing).Content != "avg=1ms fake" {
		t.Fatalf("%+v", result.Get(common.KeyPing))
	}
	rn.Render(cfg, result)
	if !bytes.Contains(buf.Bytes(), []byte("avg=1ms fake")) {
		t.Fatalf("render=%s", buf.String())
	}
}

func TestCheckIDsComplete(t *testing.T) {
	ids := CheckIDs()
	if len(ids) != len(Registry) {
		t.Fatalf("CheckIDs=%d Registry=%d %v", len(ids), len(Registry), ids)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate %s", id)
		}
		seen[id] = true
	}
	for _, want := range []string{"routing", "rdap", "ping", "traceroute"} {
		if !seen[want] {
			t.Fatalf("missing %s", want)
		}
	}
	if !isExtraCheck("traceroute") || isExtraCheck("routing") || isExtraCheck("ping") {
		t.Fatal("extra meta")
	}
}

func TestRegistryMatchesPartOrder(t *testing.T) {
	if len(Registry) != len(common.PartOrder) {
		t.Fatalf("Registry=%d PartOrder=%d", len(Registry), len(common.PartOrder))
	}
	for i, m := range Registry {
		if m.JSONKey != common.PartOrder[i].Key || string(m.ID) != common.PartOrder[i].Key {
			t.Fatalf("[%d] registry=%s/%s part=%s", i, m.ID, m.JSONKey, common.PartOrder[i].Key)
		}
		if m.Label != common.PartOrder[i].Name {
			t.Fatalf("[%d] label %q vs %q", i, m.Label, common.PartOrder[i].Name)
		}
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
