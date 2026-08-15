package config

import (
	"testing"

	flag "github.com/spf13/pflag"
)

func TestDefaultProfileIsWeb(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	opts, err := ConfigureOptions(fs, []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Profile != ProfileWeb {
		t.Fatalf("profile=%q", opts.Profile)
	}
	if !opts.ShouldSkip("udp") || !opts.ShouldSkip("mail") || !opts.ShouldSkip("dnssec") {
		t.Fatalf("web skips=%v", opts.Skip)
	}
	if opts.ShouldSkip("https") || opts.ShouldSkip("tls") {
		t.Fatalf("web should run tls/https: %v", opts.Skip)
	}
}

func TestProfileMail(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	opts, err := ConfigureOptions(fs, []string{"example.com", "--profile", "mail"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.ShouldSkip("mail") || opts.ShouldSkip("dns") || opts.ShouldSkip("records") {
		t.Fatalf("mail profile skip=%v", opts.Skip)
	}
	if !opts.ShouldSkip("http3") || !opts.ShouldSkip("cdn") {
		t.Fatalf("expected http3/cdn skipped: %v", opts.Skip)
	}
}

func TestProfileFullPlusExtraSkip(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	opts, err := ConfigureOptions(fs, []string{"example.com", "--profile", "full", "--skip", "ping"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.ShouldSkip("udp") {
		t.Fatal("full should not skip udp")
	}
	if !opts.ShouldSkip("ping") {
		t.Fatal("expected ping skipped")
	}
}

func TestUnknownProfile(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_, err := ConfigureOptions(fs, []string{"example.com", "--profile", "nope"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNormalizeProfile(t *testing.T) {
	if NormalizeProfile("") != ProfileWeb {
		t.Fatal("empty -> web")
	}
	if NormalizeProfile("FULL") != ProfileFull {
		t.Fatal("FULL")
	}
	if NormalizeProfile("x") != "" {
		t.Fatal("unknown")
	}
}
