package ping

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

func RunTest(ctx context.Context, addr common.Address, count int, timeout time.Duration, result *common.Result) error {
	return runPing(ctx, addr, count, timeout, result)
}

func runPing(ctx context.Context, addr common.Address, count int, timeout time.Duration, result *common.Result) error {
	var output common.ResultPart

	pinger, err := createPinger(addr.String())
	if err != nil {
		if out, ferr := runPingFallback(ctx, addr, count, timeout); ferr == nil {
			output = common.OK(out.Content)
		} else {
			output = common.Fail(fmt.Errorf("failed to create pinger: %w", err))
			result.Store(&result.Ping, output)
			return output.Error
		}
		result.Store(&result.Ping, output)
		return nil
	}

	pinger.Count = count
	pinger.Timeout = timeout

	err = pinger.Run()
	if err != nil {
		if out, ferr := runPingFallback(ctx, addr, count, timeout); ferr == nil {
			output = common.OK(out.Content)
		} else {
			output = common.Fail(fmt.Errorf("failed to run ping: %w", err))
			result.Store(&result.Ping, output)
			return output.Error
		}
	} else {
		stats := pinger.Statistics()
		if stats.PacketsRecv == 0 {
			if out, ferr := runPingFallback(ctx, addr, count, timeout); ferr == nil {
				output = common.OK(out.Content)
			} else {
				output = common.Fail(fmt.Errorf("no response"))
			}
		} else {
			output = common.OK(stats.AvgRtt.String())
		}
	}

	result.Store(&result.Ping, output)
	return output.Error
}

// runPingFallback executes the system ping binary with argv (no shell).
func runPingFallback(ctx context.Context, addr common.Address, count int, timeout time.Duration) (common.ResultPart, error) {
	args := pingArgs(addr.String(), count, timeout)
	out, err := executePing(ctx, args)
	if err != nil && out == "" {
		return common.Fail(err), err
	}

	po, perr := parsePingOutput(out)
	if perr != nil {
		return common.Fail(perr), perr
	}

	return common.OK(po.AvgRTT + "ms"), nil
}

func pingArgs(host string, count int, timeout time.Duration) []string {
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	switch runtime.GOOS {
	case "windows":
		return []string{"ping", "-n", strconv.Itoa(count), "-w", strconv.Itoa(secs * 1000), host}
	case "darwin":
		return []string{"ping", "-c", strconv.Itoa(count), "-W", strconv.Itoa(secs * 1000), host}
	default:
		// Linux: -W is timeout per packet in seconds
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
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		out.WriteString(scanner.Text())
		out.WriteByte('\n')
	}

	waitErr := cmd.Wait()
	s := out.String()
	if waitErr != nil && s == "" {
		return s, fmt.Errorf("ping failed: %w, stderr: %s", waitErr, errb.String())
	}
	return s, nil
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
	RequestTimeoutError = fmt.Errorf("requests timed out")
	PacketLossError     = fmt.Errorf("timeout error: 100.0%% packet loss")
)

func parsePingOutput(out string) (pingOutput, error) {
	var po pingOutput

	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(line, "packets transmitted"):
			arr := strings.Split(line, ",")
			if len(arr) < 3 {
				continue
			}
			po.PacketTransmitted, po.PacketReceived, po.PacketLoss = arr[0], arr[1], arr[2]

		case strings.Contains(line, "min/avg/max"):
			l := strings.ReplaceAll(line, " = ", " ")
			arr := strings.Split(l, " ")
			if len(arr) < 3 {
				continue
			}
			// Find the token that looks like a/b/c[/d]
			for _, tok := range arr {
				rttArr := strings.Split(tok, "/")
				if len(rttArr) >= 3 && looksLikeFloat(rttArr[0]) {
					po.MinRTT, po.AvgRTT, po.MaxRTT = rttArr[0], rttArr[1], rttArr[2]
					break
				}
			}
		}
	}

	if po.MinRTT == "" && po.AvgRTT == "" && po.MaxRTT == "" {
		return po, RequestTimeoutError
	}
	if strings.Contains(po.PacketLoss, "100") && strings.Contains(po.PacketLoss, "packet loss") {
		return po, PacketLossError
	}
	return po, nil
}

func looksLikeFloat(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}
