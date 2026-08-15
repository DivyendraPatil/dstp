package common

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestResultOutputJSONIncludesErrors(t *testing.T) {
	r := &Result{
		Ping: ResultPart{Content: "14ms"},
		TLS:  ResultPart{Error: errors.New("connection refused")},
	}

	out := r.Output("json")

	var got map[string]string
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal: %v\noutput: %s", err, out)
	}

	if got["ping"] != "14ms" {
		t.Fatalf("ping = %q, want %q", got["ping"], "14ms")
	}
	if got["tls"] != "connection refused" {
		t.Fatalf("tls = %q, want %q", got["tls"], "connection refused")
	}
}

func TestResultOutputPlaintextIncludesErrors(t *testing.T) {
	r := &Result{
		HTTPS: ResultPart{Error: errors.New("timeout")},
		DNS:   ResultPart{Content: "resolving 1.2.3.4"},
	}

	out := r.Output("plaintext")

	if !strings.Contains(out, "timeout") {
		t.Fatalf("plaintext output missing error text:\n%s", out)
	}
	if !strings.Contains(out, "resolving 1.2.3.4") {
		t.Fatalf("plaintext output missing success content:\n%s", out)
	}
}
