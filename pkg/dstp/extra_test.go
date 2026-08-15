package dstp

import (
	"strings"
	"testing"
)

func TestTruncateAndWhoisExtract(t *testing.T) {
	if truncate("abc", 10) != "abc" {
		t.Fatal(truncate("abc", 10))
	}
	if got := truncate("abcdefghij", 5); !strings.HasSuffix(got, "…") {
		t.Fatalf("%q", got)
	}
	body := "OrgName: Example Org\nNetRange: 1.2.3.0 - 1.2.3.255\n"
	if got := extractWhoisField(body, []string{"OrgName"}); got != "Example Org" {
		t.Fatalf("%q", got)
	}
}

func TestBuildURL(t *testing.T) {
	if got := buildURL("http", "example.com", "80"); got != "http://example.com" {
		t.Fatal(got)
	}
	if got := buildURL("http", "example.com", "8080"); got != "http://example.com:8080" {
		t.Fatal(got)
	}
}

func TestIsExtraCheck(t *testing.T) {
	if !isExtraCheck("traceroute") || isExtraCheck("ping") {
		t.Fatal("extra check helper")
	}
}
