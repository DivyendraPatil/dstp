package ping

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

const maxPingOutput = 64 << 10

func RunTest(ctx context.Context, addr common.Address, count int, timeout time.Duration, result *common.Result) error {
	return runPing(ctx, addr, count, timeout, result)
}

func runPing(ctx context.Context, addr common.Address, count int, timeout time.Duration, result *common.Result) error {
	var output common.ResultPart

	pinger, err := createPinger(addr.String())
	if err != nil {
		out, ferr := runPingFallback(ctx, addr, count, timeout)
		if ferr == nil {
			output = common.OK(out.Content)
		} else {
			output = common.Fail(errors.Join(fmt.Errorf("failed to create pinger: %w", err), ferr))
			result.Store(&result.Ping, output)
			return output.Error
		}
		result.Store(&result.Ping, output)
		return nil
	}

	pinger.Count = count
	pinger.Timeout = timeout
	pinger.ResolveTimeout = timeout
	if deadline, ok := ctx.Deadline(); ok {
		if rem := time.Until(deadline); rem > 0 && rem < pinger.Timeout {
			pinger.Timeout = rem
		}
	}

	err = pinger.RunWithContext(ctx)
	if err != nil {
		out, ferr := runPingFallback(ctx, addr, count, timeout)
		if ferr == nil {
			output = common.OK(out.Content)
		} else {
			output = common.Fail(errors.Join(fmt.Errorf("failed to run ping: %w", err), ferr))
			result.Store(&result.Ping, output)
			return output.Error
		}
	} else {
		stats := pinger.Statistics()
		ip := ""
		if stats.Addr != "" {
			ip = stats.Addr
		}
		if stats.PacketsRecv == 0 {
			out, ferr := runPingFallback(ctx, addr, count, timeout)
			if ferr == nil {
				output = common.OK(out.Content)
			} else {
				msg := fmt.Sprintf("sent=%d recv=0 loss=100%%", stats.PacketsSent)
				if ip != "" {
					msg += " addr=" + ip
				}
				output = common.Fail(fmt.Errorf("%s", msg))
			}
		} else {
			loss := 0.0
			if stats.PacketsSent > 0 {
				loss = float64(stats.PacketsSent-stats.PacketsRecv) / float64(stats.PacketsSent) * 100
			}
			msg := fmt.Sprintf("avg=%s min=%s max=%s stddev=%s sent=%d recv=%d loss=%.1f%%",
				stats.AvgRtt, stats.MinRtt, stats.MaxRtt, stats.StdDevRtt,
				stats.PacketsSent, stats.PacketsRecv, loss)
			if ip != "" {
				msg += " addr=" + ip
			}
			if ipParsed := net.ParseIP(ip); ipParsed != nil {
				if ipParsed.To4() != nil {
					msg += " family=IPv4"
				} else {
					msg += " family=IPv6"
				}
			}
			output = common.OK(msg)
		}
	}

	result.Store(&result.Ping, output)
	return output.Error
}

func runPingFallback(ctx context.Context, addr common.Address, count int, timeout time.Duration) (common.ResultPart, error) {
	args := pingArgs(addr.String(), count, timeout)
	out, err := executePing(ctx, args)
	if err != nil && out == "" {
		return common.Fail(err), err
	}

	po, perr := parsePingOutput(out)
	if perr != nil {
		if err != nil {
			return common.Fail(errors.Join(perr, err)), errors.Join(perr, err)
		}
		return common.Fail(perr), perr
	}
	if err != nil {
		// Nonzero exit with parseable stats — still report stats but surface exit.
		content := formatParsedPing(po) + fmt.Sprintf(" (exit: %v)", err)
		return common.Warn(content), nil
	}
	return common.OK(formatParsedPing(po)), nil
}

func formatParsedPing(po pingOutput) string {
	parts := []string{}
	if po.AvgRTT != "" {
		parts = append(parts, "avg="+po.AvgRTT+"ms")
	}
	if po.MinRTT != "" {
		parts = append(parts, "min="+po.MinRTT+"ms")
	}
	if po.MaxRTT != "" {
		parts = append(parts, "max="+po.MaxRTT+"ms")
	}
	if po.PacketTransmitted != "" || po.PacketReceived != "" || po.PacketLoss != "" {
		parts = append(parts, strings.TrimSpace(po.PacketTransmitted), strings.TrimSpace(po.PacketReceived), strings.TrimSpace(po.PacketLoss))
	}
	return strings.Join(parts, " ")
}

func pingArgs(host string, count int, timeout time.Duration) []string {
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	bin := "ping"
	if runtime.GOOS == "darwin" && net.ParseIP(host) != nil && net.ParseIP(host).To4() == nil {
		bin = "ping6"
	}
	switch runtime.GOOS {
	case "windows":
		return []string{"ping", "-n", strconv.Itoa(count), "-w", strconv.Itoa(secs * 1000), host}
	case "darwin":
		if bin == "ping6" {
			return []string{"ping6", "-c", strconv.Itoa(count), "-W", strconv.Itoa(secs * 1000), host}
		}
		return []string{"ping", "-c", strconv.Itoa(count), "-W", strconv.Itoa(secs * 1000), host}
	default:
		return []string{"ping", "-c", strconv.Itoa(count), "-W", strconv.Itoa(secs), host}
	}
}

func executePing(ctx context.Context, args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("empty ping args")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}

	var out strings.Builder
	scanner := bufio.NewScanner(io.LimitReader(stdout, maxPingOutput))
	for scanner.Scan() {
		out.WriteString(scanner.Text())
		out.WriteByte('\n')
	}
	scanErr := scanner.Err()

	waitErr := cmd.Wait()
	s := out.String()
	if scanErr != nil {
		return s, scanErr
	}
	if waitErr != nil && s == "" {
		return s, fmt.Errorf("ping failed: %w, stderr: %s", waitErr, errb.String())
	}
	return s, waitErr
}

type pingOutput struct {
	PacketLoss        string
	PacketReceived    string
	PacketTransmitted string
	MinRTT            string
	AvgRTT            string
	MaxRTT            string
}

var (
	ErrRequestTimeout = fmt.Errorf("requests timed out")
	ErrPacketLoss     = fmt.Errorf("timeout error: 100.0%% packet loss")
)

func parsePingOutput(out string) (pingOutput, error) {
	var po pingOutput

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.Contains(line, "packets transmitted"),
			strings.Contains(line, "Packets: Sent"),
			strings.Contains(line, "Packets: sent"):
			// Unix: "3 packets transmitted, 3 received, 0% packet loss"
			// Windows: "Packets: Sent = 3, Received = 3, Lost = 0 (0% loss)"
			if strings.Contains(line, "packets transmitted") {
				arr := strings.Split(line, ",")
				if len(arr) >= 3 {
					po.PacketTransmitted, po.PacketReceived, po.PacketLoss = arr[0], arr[1], arr[2]
				}
			} else {
				po.PacketLoss = line
			}

		case strings.Contains(line, "min/avg/max"),
			strings.Contains(line, "Minimum ="),
			strings.Contains(strings.ToLower(line), "round-trip"):
			l := strings.ReplaceAll(line, " = ", " ")
			arr := strings.Split(l, " ")
			for _, tok := range arr {
				tok = strings.TrimSuffix(tok, "ms")
				rttArr := strings.Split(tok, "/")
				if len(rttArr) >= 3 && looksLikeFloat(rttArr[0]) {
					po.MinRTT, po.AvgRTT, po.MaxRTT = rttArr[0], rttArr[1], rttArr[2]
					break
				}
			}
			// Windows "Average = 14ms"
			if po.AvgRTT == "" && strings.Contains(line, "Average") {
				for _, tok := range strings.Fields(line) {
					tok = strings.TrimSuffix(strings.TrimSuffix(tok, ","), "ms")
					if looksLikeFloat(tok) {
						po.AvgRTT = tok
						po.MinRTT = tok
						po.MaxRTT = tok
					}
				}
			}
		}
	}

	if strings.Contains(po.PacketLoss, "100") && strings.Contains(po.PacketLoss, "packet loss") {
		return po, ErrPacketLoss
	}
	if strings.Contains(po.PacketLoss, "100%") || strings.Contains(po.PacketLoss, "100 %") {
		return po, ErrPacketLoss
	}
	if po.MinRTT == "" && po.AvgRTT == "" && po.MaxRTT == "" {
		return po, ErrRequestTimeout
	}
	return po, nil
}

func looksLikeFloat(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}
