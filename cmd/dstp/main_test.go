package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestRunHelpExit0(t *testing.T) {
	var out, err bytes.Buffer
	code := run([]string{"--help"}, &out, &err)
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	if out.Len() == 0 {
		t.Fatal("expected help on stdout")
	}
}

func TestRunVersionExit0(t *testing.T) {
	var out, err bytes.Buffer
	code := run([]string{"--version"}, &out, &err)
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	if out.Len() == 0 {
		t.Fatal("expected version on stdout")
	}
}

func TestRunMissingTargetExit2(t *testing.T) {
	var out, errb bytes.Buffer
	code := run(nil, &out, &errb)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, errb.String())
	}
}

func TestRunPositionalWithSkipAll(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{
		"example.com", "-q", "-o", "json", "-t", "2", "-p", "1",
		"--skip", "ping,dns,configured_dns,records,mail,dnssec,tcp,udp,tls,http,https,http3,cdn",
	}, &out, &errb)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errb.String())
	}
}

func TestRunExplicitMissingConfigExit2(t *testing.T) {
	var out, errb bytes.Buffer
	path := filepath.Join(t.TempDir(), "missing.yaml")
	code := run([]string{"--config", path, "example.com"}, &out, &errb)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, errb.String())
	}
}
