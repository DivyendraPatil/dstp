package ping

import (
	"testing"
)

func TestParsePingOutput(t *testing.T) {
	out := `PING example.com (93.184.216.34): 56 data bytes
64 bytes from 93.184.216.34: icmp_seq=0 ttl=54 time=14.450 ms

--- example.com ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 14.450/14.534/14.683/0.106 ms
`
	po, err := parsePingOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	if po.AvgRTT != "14.534" {
		t.Fatalf("avg=%q", po.AvgRTT)
	}
}

func TestPingArgsNoShell(t *testing.T) {
	args := pingArgs("example.com", 3, 0)
	if len(args) < 2 || args[0] != "ping" {
		t.Fatalf("args=%v", args)
	}
	for _, a := range args {
		if a == "/bin/bash" || a == "bash" || a == "cmd" {
			t.Fatalf("shell invocation in args: %v", args)
		}
	}
}
