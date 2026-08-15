package config

import (
	"testing"
	"time"

	flag "github.com/spf13/pflag"
)

func TestConfigureOptions(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	opts, err := ConfigureOptions(fs, []string{"example.com", "-t", "5", "--skip", "ping,tls", "--method", "HEAD", "-q"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Addr != "example.com" {
		t.Fatalf("addr=%q", opts.Addr)
	}
	if opts.Timeout != 5 {
		t.Fatalf("timeout=%d", opts.Timeout)
	}
	if !opts.ShouldSkip("ping") || !opts.ShouldSkip("tls") {
		t.Fatalf("skip=%v", opts.Skip)
	}
	if opts.HTTPMethod != "HEAD" {
		t.Fatalf("method=%q", opts.HTTPMethod)
	}
	if !opts.Quiet {
		t.Fatal("expected quiet")
	}
	if opts.TimeoutDuration() != 5*time.Second {
		t.Fatalf("duration=%s", opts.TimeoutDuration())
	}
}

func TestConfigureOptionsRejectsBadMethod(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_, err := ConfigureOptions(fs, []string{"example.com", "--method", "POST"})
	if err == nil {
		t.Fatal("expected error")
	}
}
