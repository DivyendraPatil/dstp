// Package config parses dstp CLI flags, optional config file, and defaults.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	flag "github.com/spf13/pflag"
	"go.yaml.in/yaml/v3"

	"github.com/DivyendraPatil/dstp/internal/version"
)

// Sentinel errors for CLI exit mapping.
var (
	ErrHelp    = errors.New("help requested")
	ErrVersion = errors.New("version requested")
	ErrUsage   = errors.New("invalid usage")
)

// Config holds runtime options for dstp.
type Config struct {
	Addr            string   `yaml:"addr"`
	Output          string   `yaml:"out"`
	PingCount       int      `yaml:"ping_count"`
	Timeout         int      `yaml:"timeout"`
	ShowHelp        bool     `yaml:"-"`
	ShowVersion     bool     `yaml:"-"`
	Port            string   `yaml:"port"`
	CustomDnsServer string   `yaml:"dns"`
	Quiet           bool     `yaml:"quiet"`
	Skip            []string `yaml:"skip"`
	HTTPMethod      string   `yaml:"method"`
	FollowRedirects bool     `yaml:"follow_redirects"`
	DoH             bool     `yaml:"doh"`
	DoHURL          string   `yaml:"doh_url"`
	TCPPort         string   `yaml:"tcp_port"`
	UDPPort         string   `yaml:"udp_port"`
	HTTPPort        string   `yaml:"http_port"`
	Insecure        bool     `yaml:"insecure"`
	Extra           bool     `yaml:"extra"`
	ConfigPath      string   `yaml:"-"`
	ExplicitConfig  bool     `yaml:"-"`
}

var usageStr = `Usage: dstp [OPTIONS] [TARGET]
Options:
	-a, --addr     <string>  Target URL, hostname, or IP                       [REQUIRED]
	-o, --out      <string>  Output: json or plaintext                         [Default: plaintext]
	-p             <int>     Ping packet count                                 [Default: 3]
	-t             <int>     Per-check timeout (seconds)                       [Default: 2s * ping count]
	--port         <string>  TLS/HTTPS port                                    [Default: 443]
	--tcp-port     <string>  TCP connect port                                  [Default: --port or 443]
	--udp-port     <string>  UDP probe port                                    [Default: 53]
	--http-port    <string>  Cleartext HTTP port                               [Default: 80]
	--dns          <string>  Custom DNS for ConfiguredDNS check
	--doh                  Use DNS-over-HTTPS for DNS check
	--doh-url      <string>  DoH JSON endpoint (provider-specific dns-json)
	--method       <string>  HTTP(S) method: GET or HEAD                       [Default: GET]
	--follow-redirects     Follow HTTP(S) redirects
	--insecure             Skip TLS certificate verification (security risk)
	--extra                Also run traceroute, whois, and MTU probes
	--skip         <list>    Skip: ping,dns,configured_dns,records,tcp,udp,tls,http,https,traceroute,whois,mtu
	--config       <path>    Config file                                       [Default: $XDG config/dstp/config.yaml]
	-q, --quiet            Suppress progress on stderr
	-v, --version          Print version and exit
	-h, --help             Show help and exit.
`

func PrintUsage(w io.Writer) {
	fmt.Fprint(w, usageStr)
}

func PrintVersion(w io.Writer) {
	fmt.Fprintln(w, version.String())
}

func UsageError(w io.Writer, err error) {
	fmt.Fprintln(w, color.RedString("%s", err.Error()))
	PrintUsage(w)
}

func (c Config) TimeoutDuration() time.Duration {
	t := c.Timeout
	if t < 0 {
		t = 2 * c.PingCount
		if t <= 0 {
			t = 6
		}
	}
	if t > math.MaxInt64/int(time.Second) {
		t = math.MaxInt64 / int(time.Second)
	}
	return time.Duration(t) * time.Second
}

func (c Config) ShouldSkip(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, s := range c.Skip {
		if strings.ToLower(strings.TrimSpace(s)) == name {
			return true
		}
	}
	return false
}

// ConfigureOptions loads optional YAML defaults, then applies CLI flags (flags/positionals win).
func ConfigureOptions(fs *flag.FlagSet, args []string) (*Config, error) {
	if wantsHelp(args) {
		return nil, ErrHelp
	}
	if wantsVersion(args) {
		return nil, ErrVersion
	}

	opts := &Config{
		Output:     "plaintext",
		PingCount:  3,
		Timeout:    -1,
		DoHURL:     "https://cloudflare-dns.com/dns-query",
		HTTPMethod: "GET",
		UDPPort:    "53",
		HTTPPort:   "80",
	}

	cfgPath, explicit := findConfigFlag(args)
	opts.ExplicitConfig = explicit
	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	if cfgPath != "" {
		if err := loadYAML(cfgPath, opts); err != nil {
			if explicit || !os.IsNotExist(err) {
				return nil, fmt.Errorf("config file: %w", err)
			}
		} else {
			opts.ConfigPath = cfgPath
		}
	}

	yamlSkip := append([]string(nil), opts.Skip...)
	yamlAddr := opts.Addr

	var skip string
	fs.StringVarP(&opts.Addr, "addr", "a", opts.Addr, "Target URL, hostname, or IP")
	fs.StringVarP(&opts.Output, "out", "o", opts.Output, "Output type")
	fs.StringVar(&opts.Port, "port", opts.Port, "TLS/HTTPS port")
	fs.StringVar(&opts.TCPPort, "tcp-port", opts.TCPPort, "TCP connect port")
	fs.StringVar(&opts.UDPPort, "udp-port", opts.UDPPort, "UDP probe port")
	fs.StringVar(&opts.HTTPPort, "http-port", opts.HTTPPort, "Cleartext HTTP port")
	fs.IntVarP(&opts.PingCount, "p", "p", opts.PingCount, "Ping packet count")
	fs.IntVarP(&opts.Timeout, "t", "t", opts.Timeout, "Per-check timeout seconds")
	fs.StringVar(&opts.CustomDnsServer, "dns", opts.CustomDnsServer, "Custom DNS server")
	fs.BoolVar(&opts.DoH, "doh", opts.DoH, "Use DNS-over-HTTPS")
	fs.StringVar(&opts.DoHURL, "doh-url", opts.DoHURL, "DoH endpoint URL")
	fs.StringVar(&opts.HTTPMethod, "method", opts.HTTPMethod, "HTTP(S) method")
	fs.BoolVar(&opts.FollowRedirects, "follow-redirects", opts.FollowRedirects, "Follow redirects")
	fs.BoolVar(&opts.Insecure, "insecure", opts.Insecure, "Skip TLS verification")
	fs.BoolVar(&opts.Extra, "extra", opts.Extra, "Enable traceroute/whois/mtu")
	fs.StringVar(&skip, "skip", "", "Comma-separated checks to skip")
	fs.StringVar(&opts.ConfigPath, "config", opts.ConfigPath, "Path to config YAML")
	fs.BoolVarP(&opts.Quiet, "quiet", "q", opts.Quiet, "Suppress progress")
	fs.BoolVarP(&opts.ShowVersion, "version", "v", false, "Print version")
	fs.BoolVarP(&opts.ShowHelp, "help", "h", false, "Show help")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	values := fs.Args()

	if opts.ShowVersion {
		return nil, ErrVersion
	}
	if opts.ShowHelp {
		return nil, ErrHelp
	}

	// Positional target overrides YAML/flag addr when provided.
	if len(values) >= 1 {
		opts.Addr = values[0]
	} else if opts.Addr == "" {
		opts.Addr = yamlAddr
	}
	if len(values) > 1 {
		return nil, fmt.Errorf("%w: unexpected extra arguments %v", ErrUsage, values[1:])
	}
	if opts.Addr == "" {
		return nil, fmt.Errorf("%w: target address is required", ErrUsage)
	}

	if fs.Changed("skip") {
		opts.Skip = splitList(skip)
	} else {
		opts.Skip = yamlSkip
	}

	if opts.PingCount <= 0 {
		return nil, fmt.Errorf("%w: ping count (-p) must be positive", ErrUsage)
	}
	if opts.Timeout == 0 || opts.Timeout < -1 {
		return nil, fmt.Errorf("%w: timeout (-t) must be positive (or omit for default)", ErrUsage)
	}

	method := strings.ToUpper(strings.TrimSpace(opts.HTTPMethod))
	if method != "GET" && method != "HEAD" {
		return nil, fmt.Errorf("%w: unsupported HTTP method %q (use GET or HEAD)", ErrUsage, opts.HTTPMethod)
	}
	opts.HTTPMethod = method

	out := strings.ToLower(strings.TrimSpace(opts.Output))
	if out != "plaintext" && out != "json" {
		return nil, fmt.Errorf("%w: unsupported output type %q", ErrUsage, opts.Output)
	}
	opts.Output = out

	known := map[string]struct{}{
		"ping": {}, "dns": {}, "configured_dns": {}, "system_dns": {}, "records": {},
		"tcp": {}, "udp": {}, "tls": {}, "http": {}, "https": {},
		"traceroute": {}, "whois": {}, "mtu": {},
	}
	for _, s := range opts.Skip {
		if _, ok := known[strings.ToLower(strings.TrimSpace(s))]; !ok {
			return nil, fmt.Errorf("%w: unknown skip check %q", ErrUsage, s)
		}
	}

	if opts.DoHURL != "" {
		low := strings.ToLower(opts.DoHURL)
		if !strings.HasPrefix(low, "https://") && !strings.HasPrefix(low, "http://127.0.0.1") && !strings.HasPrefix(low, "http://localhost") {
			return nil, fmt.Errorf("%w: --doh-url must be https", ErrUsage)
		}
	}

	return opts, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func wantsHelp(args []string) bool {
	for _, a := range argsBeforeDashDash(args) {
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

func wantsVersion(args []string) bool {
	for _, a := range argsBeforeDashDash(args) {
		if a == "-v" || a == "--version" {
			return true
		}
	}
	return false
}

func argsBeforeDashDash(args []string) []string {
	for i, a := range args {
		if a == "--" {
			return args[:i]
		}
	}
	return args
}

func findConfigFlag(args []string) (path string, explicit bool) {
	args = argsBeforeDashDash(args)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config" && i+1 < len(args):
			path = args[i+1]
			explicit = true
		case strings.HasPrefix(a, "--config="):
			path = strings.TrimPrefix(a, "--config=")
			explicit = true
		}
	}
	return path, explicit
}

func defaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "dstp", "config.yaml")
}

func loadYAML(path string, opts *Config) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(opts); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF && err != nil {
		return fmt.Errorf("trailing YAML document: %w", err)
	} else if err == nil {
		return fmt.Errorf("trailing YAML document not allowed")
	}
	return nil
}
