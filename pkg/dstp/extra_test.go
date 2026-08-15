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

func TestHopLines(t *testing.T) {
	out := `traceroute to example.com
 1  gateway 1 ms
 2  * * *
foo
 3  end 2 ms
`
	hops := hopLines(out)
	if len(hops) != 3 {
		t.Fatalf("%v", hops)
	}
}

func TestIsExtraCheck(t *testing.T) {
	if !isExtraCheck("traceroute") || isExtraCheck("ping") {
		t.Fatal("extra check helper")
	}
}
