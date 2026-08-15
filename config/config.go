package config

import (
	flag "github.com/spf13/pflag"

	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

type Config struct {
	Addr            string
	Output          string
	PingCount       int
	Timeout         int
	ShowHelp        bool
	Port            string
	CustomDnsServer string
	Quiet           bool
	Skip            []string
	HTTPMethod      string
	FollowRedirects bool
	DoH             bool
	DoHURL          string
	TCPPort         string
}

var usageStr = `Usage: dstp [OPTIONS] [ARGS]
Options:
	-a, --addr     <string>  The URL or the IP address to run tests against    [REQUIRED]
	-o, --out      <string>  Output type: json or plaintext                    [Default: plaintext]
	-p             <int>     Number of ping packets                            [Default: 3]
	-t             <int>     Timeout in seconds for each check                 [Default: 2s per ping packet]
	--port         <string>  Port for TLS/HTTPS                                [Default: 443]
	--tcp-port     <string>  Port for plain TCP connect                        [Default: same as --port or 443]
	--dns          <string>  Custom DNS server for configured DNS check        [Default: system resolver]
	--doh                  Use DNS-over-HTTPS for the default DNS check
	--doh-url      <string>  DoH endpoint                                      [Default: https://cloudflare-dns.com/dns-query]
	--method       <string>  HTTP method for HTTPS check: GET or HEAD          [Default: GET]
	--follow-redirects     Follow HTTPS redirects (off by default)
	--skip         <list>    Skip checks: ping,dns,configured_dns,records,tcp,tls,https
	-q, --quiet            Suppress progress output on stderr
	-h, --help             Show this message and exit.
`

// UsageAndExit prints usage and exits the program.
func UsageAndExit(err error) {
	color.Red(err.Error())
	fmt.Print(usageStr)
	os.Exit(1)
}

// HelpAndExit prints help and exits the program.
func HelpAndExit() {
	fmt.Print(usageStr)
	os.Exit(0)
}

// TimeoutDuration returns the per-check timeout.
func (c Config) TimeoutDuration() time.Duration {
	t := c.Timeout
	if t < 0 {
		t = 2 * c.PingCount
		if t <= 0 {
			t = 6
		}
	}
	return time.Duration(t) * time.Second
}

// ShouldSkip reports whether a named check should be skipped.
func (c Config) ShouldSkip(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, s := range c.Skip {
		if strings.ToLower(strings.TrimSpace(s)) == name {
			return true
		}
	}
	return false
}

// ConfigureOptions parses CLI options.
func ConfigureOptions(fs *flag.FlagSet, args []string) (*Config, error) {
	opts := &Config{}
	var skip string

	fs.StringVarP(&opts.Addr, "addr", "a", "", "The URL or the IP address to run tests against")
	fs.StringVarP(&opts.Output, "out", "o", "plaintext", "The type of the output")
	fs.StringVar(&opts.Port, "port", "", "Port for testing TLS and HTTPS connectivity")
	fs.StringVar(&opts.TCPPort, "tcp-port", "", "Port for plain TCP connect check")
	fs.IntVarP(&opts.PingCount, "p", "p", 3, "Number of ping packets")
	fs.IntVarP(&opts.Timeout, "t", "t", -1, "Timeout in seconds for each check")
	fs.StringVar(&opts.CustomDnsServer, "dns", "", "Custom DNS server for the configured DNS check")
	fs.BoolVar(&opts.DoH, "doh", false, "Use DNS-over-HTTPS for the default DNS check")
	fs.StringVar(&opts.DoHURL, "doh-url", "https://cloudflare-dns.com/dns-query", "DoH endpoint URL")
	fs.StringVar(&opts.HTTPMethod, "method", "GET", "HTTP method for HTTPS check")
	fs.BoolVar(&opts.FollowRedirects, "follow-redirects", false, "Follow HTTPS redirects")
	fs.StringVar(&skip, "skip", "", "Comma-separated checks to skip")
	fs.BoolVarP(&opts.Quiet, "quiet", "q", false, "Suppress progress output")
	fs.BoolVarP(&opts.ShowHelp, "help", "h", false, "Show help message")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	values := fs.Args()

	if opts.ShowHelp {
		HelpAndExit()
	}

	if !opts.ShowHelp && len(values) < 1 && opts.Addr == "" {
		HelpAndExit()
	}

	if opts.Addr == "" {
		if len(values) >= 1 {
			opts.Addr = values[0]
		} else {
			return nil, fmt.Errorf("address cannot be empty")
		}
	}

	if skip != "" {
		opts.Skip = strings.Split(skip, ",")
	}

	method := strings.ToUpper(strings.TrimSpace(opts.HTTPMethod))
	if method != "GET" && method != "HEAD" {
		return nil, fmt.Errorf("unsupported HTTP method %q (use GET or HEAD)", opts.HTTPMethod)
	}
	opts.HTTPMethod = method

	out := strings.ToLower(strings.TrimSpace(opts.Output))
	if out != "plaintext" && out != "json" {
		return nil, fmt.Errorf("unsupported output type %q (use json or plaintext)", opts.Output)
	}
	opts.Output = out

	return opts, nil
}
