package ping

import (
	"errors"
	"testing"
)

func TestParsePingOutputUnix(t *testing.T) {
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

func TestParsePingOutputWindowsCRLF(t *testing.T) {
	out := "\r\nPinging example.com [93.184.216.34] with 32 bytes of data:\r\n" +
		"Reply from 93.184.216.34: bytes=32 time=14ms TTL=54\r\n\r\n" +
		"Ping statistics for 93.184.216.34:\r\n" +
		"    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),\r\n" +
		"Approximate round trip times in milli-seconds:\r\n" +
		"    Minimum = 14ms, Maximum = 15ms, Average = 14ms\r\n"
	po, err := parsePingOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	if po.AvgRTT != "14" {
		t.Fatalf("avg=%q loss=%q", po.AvgRTT, po.PacketLoss)
	}
}

func TestParsePingOutputBusyBox(t *testing.T) {
	out := `PING example.com (93.184.216.34): 56 data bytes
64 bytes from 93.184.216.34: seq=0 ttl=54 time=14.450 ms
--- example.com ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 14.450/14.534/14.683 ms
`
	po, err := parsePingOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	if po.AvgRTT != "14.534" {
		t.Fatalf("avg=%q", po.AvgRTT)
	}
}

func TestParsePingOutputTotalLoss(t *testing.T) {
	out := `PING example.com (93.184.216.34): 56 data bytes
--- example.com ping statistics ---
3 packets transmitted, 0 packets received, 100% packet loss
`
	_, err := parsePingOutput(out)
	if !errors.Is(err, ErrPacketLoss) && !errors.Is(err, ErrRequestTimeout) {
		t.Fatalf("err=%v", err)
	}
}

func TestParsePingOutputPartialLossWithRTT(t *testing.T) {
	out := `--- example.com ping statistics ---
4 packets transmitted, 2 packets received, 50% packet loss
round-trip min/avg/max/stddev = 10.0/12.0/14.0/1.0 ms
`
	po, err := parsePingOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	if po.AvgRTT != "12.0" {
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
