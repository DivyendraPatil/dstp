package dstp

import (
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

func testTraceroute(ctx context.Context, address common.Address, timeout time.Duration, result *common.Result) error {
	args := tracerouteArgs(address.String())
	out, err := runCmd(ctx, timeout, args...)
	if err != nil && out == "" {
		result.Store(&result.Traceroute, common.Fail(err))
		return err
	}
	lines := nonEmptyLines(out)
	if len(lines) == 0 {
		err := fmt.Errorf("empty traceroute output")
		result.Store(&result.Traceroute, common.Fail(err))
		return err
	}
	// Keep output compact: first hop + last hop + count.
	summary := lines[0]
	if len(lines) > 1 {
		summary = fmt.Sprintf("%s … %s (%d hops)", lines[0], lines[len(lines)-1], len(lines))
	}
	result.Store(&result.Traceroute, common.OK(summary))
	return nil
}

func testWhois(ctx context.Context, address common.Address, timeout time.Duration, result *common.Result) error {
	out, err := runCmd(ctx, timeout, "whois", address.String())
	if err != nil && out == "" {
		result.Store(&result.Whois, common.Fail(err))
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
		// Fallback: first non-comment line
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
	// Probe with don't-fragment ping at common sizes; report largest that succeeds.
	sizes := []int{1472, 1400, 1200, 1000, 576}
	var best int
	for _, sz := range sizes {
		args := mtuPingArgs(address.String(), sz)
		if _, err := runCmd(ctx, timeout, args...); err == nil {
			best = sz + 28 // IP+ICMP headers approx for reported MTU
			break
		}
	}
	if best == 0 {
		err := fmt.Errorf("no DF ping size succeeded (may need privileges)")
		result.Store(&result.MTU, common.Fail(err))
		return err
	}
	result.Store(&result.MTU, common.OK(fmt.Sprintf("path MTU >= %d (payload probe)", best)))
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

func runCmd(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("empty command")
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := stdout.String()
	if out == "" {
		out = stderr.String()
	}
	if err != nil && out == "" {
		return "", fmt.Errorf("%v: %w", args[0], err)
	}
	return out, err
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
