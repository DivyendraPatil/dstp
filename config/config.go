// Package config parses dstp CLI flags, optional config file, and defaults.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	flag "github.com/spf13/pflag"
	"gopkg.in/yaml.v3"

	"github.com/DivyendraPatil/dstp/internal/version"
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
	Extra           bool     `yaml:"extra"` // enable traceroute/whois/mtu
	ConfigPath      string   `yaml:"-"`
}

var usageStr = `Usage: dstp [OPTIONS] [ARGS]
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
	--doh-url      <string>  DoH endpoint
	--method       <string>  HTTP(S) method: GET or HEAD                       [Default: GET]
	--follow-redirects     Follow HTTP(S) redirects
	--insecure             Skip TLS certificate verification
	--extra                Also run traceroute, whois, and MTU probes
	--skip         <list>    Skip: ping,dns,configured_dns,records,tcp,udp,tls,http,https,traceroute,whois,mtu
	--config       <path>    Config file                                       [Default: ~/.config/dstp/config.yaml]
	-q, --quiet            Suppress progress on stderr
	-v, --version          Print version and exit
	-h, --help             Show help and exit.
`

func UsageAndExit(err error) {
	color.Red(err.Error())
	fmt.Print(usageStr)
	os.Exit(1)
}

func HelpAndExit() {
	fmt.Print(usageStr)
	os.Exit(0)
}

func VersionAndExit() {
	fmt.Println(version.String())
	os.Exit(0)
}

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

func (c Config) ShouldSkip(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, s := range c.Skip {
		if strings.ToLower(strings.TrimSpace(s)) == name {
			return true
		}
	}
	return false
}

// ConfigureOptions loads optional YAML defaults, then applies CLI flags (flags win).
func ConfigureOptions(fs *flag.FlagSet, args []string) (*Config, error) {
	opts := &Config{
		Output:     "plaintext",
		PingCount:  3,
		Timeout:    -1,
		DoHURL:     "https://cloudflare-dns.com/dns-query",
		HTTPMethod: "GET",
		UDPPort:    "53",
		HTTPPort:   "80",
	}

	cfgPath := findConfigFlag(args)
	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	if cfgPath != "" {
		if err := loadYAML(cfgPath, opts); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("config file: %w", err)
		}
		opts.ConfigPath = cfgPath
	}

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
	fs.StringVar(&skip, "skip", strings.Join(opts.Skip, ","), "Comma-separated checks to skip")
	fs.StringVar(&opts.ConfigPath, "config", opts.ConfigPath, "Path to config YAML")
	fs.BoolVarP(&opts.Quiet, "quiet", "q", opts.Quiet, "Suppress progress")
	fs.BoolVarP(&opts.ShowVersion, "version", "v", false, "Print version")
	fs.BoolVarP(&opts.ShowHelp, "help", "h", false, "Show help")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	values := fs.Args()

	if opts.ShowVersion {
		VersionAndExit()
	}
	if opts.ShowHelp {
		HelpAndExit()
	}
	if len(values) < 1 && opts.Addr == "" {
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
		opts.Skip = splitList(skip)
	}

	method := strings.ToUpper(strings.TrimSpace(opts.HTTPMethod))
	if method != "GET" && method != "HEAD" {
		return nil, fmt.Errorf("unsupported HTTP method %q (use GET or HEAD)", opts.HTTPMethod)
	}
	opts.HTTPMethod = method

	out := strings.ToLower(strings.TrimSpace(opts.Output))
	if out != "plaintext" && out != "json" {
		return nil, fmt.Errorf("unsupported output type %q", opts.Output)
	}
	opts.Output = out

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

func findConfigFlag(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--config" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "--config=") {
			return strings.TrimPrefix(a, "--config=")
		}
	}
	return ""
}

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "dstp", "config.yaml")
}

func loadYAML(path string, opts *Config) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, opts)
}
