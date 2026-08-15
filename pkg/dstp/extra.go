package dstp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

const maxCmdOutput = 256 << 10

func testTraceroute(ctx context.Context, address common.Address, timeout time.Duration, result *common.Result) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := tracerouteArgs(address.String())
	out, err := runCmd(ctx, args...)
	if err != nil {
		if out == "" {
			result.Store(&result.Traceroute, common.Fail(err))
			return err
		}
		// Preserve exit error with truncated output
		result.Store(&result.Traceroute, common.Fail(fmt.Errorf("%w; output: %s", err, truncate(out, 200))))
		return err
	}
	hops := hopLines(out)
	if len(hops) == 0 {
		err := fmt.Errorf("empty traceroute hops")
		result.Store(&result.Traceroute, common.Fail(err))
		return err
	}
	summary := hops[0]
	if len(hops) > 1 {
		summary = fmt.Sprintf("%s … %s (%d hops)", hops[0], hops[len(hops)-1], len(hops))
	}
	result.Store(&result.Traceroute, common.OK(summary))
	return nil
}

func testWhois(ctx context.Context, address common.Address, timeout time.Duration, result *common.Result) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if _, err := exec.LookPath("whois"); err != nil {
		msg := "whois not installed; install whois or use an RDAP client"
		if runtime.GOOS == "windows" {
			msg = "whois not available on this Windows host"
		}
		result.Store(&result.Whois, common.Fail(fmt.Errorf("%s", msg)))
		return fmt.Errorf("%s", msg)
	}

	out, err := runCmd(ctx, "whois", address.String())
	if err != nil {
		if out == "" {
			result.Store(&result.Whois, common.Fail(err))
			return err
		}
		result.Store(&result.Whois, common.Fail(fmt.Errorf("%w; output: %s", err, truncate(out, 200))))
		return err
	}
	org := extractWhoisField(out, []string{"OrgName", "org-name", "Organization", "Registrant Organization", "descr"})
	netRange := extractWhoisField(out, []string{"NetRange", "inetnum", "CIDR"})
	var parts []string
	if org != "" {
		parts = append(parts, "org="+org)
	}
	if netRange != "" {
		parts = append(parts, "range="+netRange)
	}
	if len(parts) == 0 {
		for _, line := range nonEmptyLines(out) {
			if !strings.HasPrefix(line, "%") && !strings.HasPrefix(line, "#") {
				parts = append(parts, truncate(line, 120))
				break
			}
		}
	}
	if len(parts) == 0 {
		err := fmt.Errorf("no whois data")
		result.Store(&result.Whois, common.Fail(err))
		return err
	}
	result.Store(&result.Whois, common.OK(strings.Join(parts, "; ")))
	return nil
}

func testMTU(ctx context.Context, address common.Address, timeout time.Duration, result *common.Result) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	overhead := 28 // IPv4 + ICMP
	if ip := net.ParseIP(address.String()); ip != nil && ip.To4() == nil {
		overhead = 48 // IPv6 + ICMPv6
	}

	// Binary-ish search over common payload sizes within one shared deadline.
	sizes := []int{1472, 1400, 1280, 1200, 1000, 576, 512}
	var best int
	for _, sz := range sizes {
		if ctx.Err() != nil {
			break
		}
		args := mtuPingArgs(address.String(), sz)
		if _, err := runCmd(ctx, args...); err == nil {
			best = sz + overhead
			break
		}
	}
	if best == 0 {
		err := fmt.Errorf("no DF ping size succeeded (may need privileges)")
		result.Store(&result.MTU, common.Fail(err))
		return err
	}
	result.Store(&result.MTU, common.OK(fmt.Sprintf("path MTU >= %d (payload probe, overhead=%d)", best, overhead)))
	return nil
}

func tracerouteArgs(host string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"traceroute", "-m", "20", "-w", "1", host}
	case "windows":
		return []string{"tracert", "-d", "-h", "20", "-w", "1000", host}
	default:
		return []string{"traceroute", "-m", "20", "-w", "1", "-n", host}
	}
}

func mtuPingArgs(host string, payload int) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"ping", "-c", "1", "-D", "-s", strconv.Itoa(payload), "-W", "1000", host}
	case "windows":
		return []string{"ping", "-n", "1", "-f", "-l", strconv.Itoa(payload), "-w", "1000", host}
	default:
		return []string{"ping", "-c", "1", "-M", "do", "-s", strconv.Itoa(payload), "-W", "1", host}
	}
}

func runCmd(ctx context.Context, args ...string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("empty command")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := stdout.String()
	if out == "" {
		out = stderr.String()
	}
	if len(out) > maxCmdOutput {
		out = out[:maxCmdOutput]
	}
	if err != nil {
		if out == "" {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return "", fmt.Errorf("%v: timed out", args[0])
			}
			return "", fmt.Errorf("%v: %w", args[0], err)
		}
		return out, fmt.Errorf("%v: %w", args[0], err)
	}
	return out, nil
}

func hopLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Numbered hop lines: " 1  …" or "1  …"
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		n := strings.TrimSuffix(fields[0], ".")
		if isAllDigits(n) {
			out = append(out, line)
		}
	}
	return out
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func extractWhoisField(body string, keys []string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		for _, key := range keys {
			prefix := key + ":"
			if strings.HasPrefix(strings.ToLower(line), strings.ToLower(prefix)) {
				return truncate(strings.TrimSpace(line[len(prefix):]), 80)
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
