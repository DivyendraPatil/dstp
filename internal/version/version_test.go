package version

import "testing"

func TestString(t *testing.T) {
	s := String()
	if s == "" || s[:4] != "dstp" {
		t.Fatalf("%q", s)
	}
}
