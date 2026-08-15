package config

import (
	"errors"
	"os"
	"path/filepath"
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

func TestConfigureOptionsLoadsYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("quiet: true\ntimeout: 9\nskip: [ping]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	opts, err := ConfigureOptions(fs, []string{"--config", path, "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.Quiet || opts.Timeout != 9 || !opts.ShouldSkip("ping") {
		t.Fatalf("%+v", opts)
	}
}

func TestPositionalOverridesYAMLAddr(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("addr: production\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	opts, err := ConfigureOptions(fs, []string{"--config", path, "staging"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Addr != "staging" {
		t.Fatalf("addr=%q", opts.Addr)
	}
}

func TestSkipEmptyClearsYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("skip: [ping,tls]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	opts, err := ConfigureOptions(fs, []string{"--config", path, "--skip=", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.Skip) != 0 {
		t.Fatalf("skip=%v", opts.Skip)
	}
}

func TestMissingTargetIsUsage(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_, err := ConfigureOptions(fs, nil)
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("err=%v", err)
	}
}

func TestRejectZeroTimeout(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_, err := ConfigureOptions(fs, []string{"example.com", "-t", "0"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHelpBeforeConfig(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_, err := ConfigureOptions(fs, []string{"--help", "--config", "/no/such/file.yaml"})
	if !errors.Is(err, ErrHelp) {
		t.Fatalf("err=%v", err)
	}
}

func TestExplicitMissingConfigFails(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_, err := ConfigureOptions(fs, []string{"--config", filepath.Join(t.TempDir(), "missing.yaml"), "example.com"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSplitList(t *testing.T) {
	got := splitList(" a, b , ,c ")
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("%v", got)
	}
}
