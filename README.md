# dstp

Run networking checks against a host — ping, DNS, TCP/UDP, TLS, HTTP/HTTPS — in one command.

```bash
go install github.com/DivyendraPatil/dstp/cmd/dstp@latest
dstp example.com
```

If `dstp` is “command not found” after install, your `GOBIN` may not be on `PATH`. Fix:

```bash
GOBIN="$(go env GOPATH)/bin" go install github.com/DivyendraPatil/dstp/cmd/dstp@latest
export PATH="$(go env GOPATH)/bin:$PATH"
```

Exit codes: `0` success (or help/version), `1` check failure, `2` bad usage, `130` interrupted.

## Install

Requires **Go 1.26.0+** (CI/toolchain uses **1.26.6**).

```bash
GOBIN="$(go env GOPATH)/bin" go install github.com/DivyendraPatil/dstp/cmd/dstp@latest
	# or from a clone:
make install
```

Binary releases (when published): download the archive for your OS from GitHub Releases, verify `checksums.txt`, and optionally verify the Cosign/Sigstore bundle (`checksums.txt.sigstore.json`) with `cosign verify-blob`. SBOMs ship alongside archives.

> `brew install dstp` still installs upstream [ycd/dstp](https://github.com/ycd/dstp). Use `go install` for **this** fork.

## Common options

| Flag | What it does |
|------|----------------|
| `-a, --addr` / positional | Target host/URL/IP. **Positional overrides** YAML `addr`. Full URLs keep scheme/port/path/query for HTTP(S). |
| `-o json` | JSON with `status` / `content` / `error` (`configured_dns` key) |
| `-t 5` | Per-check timeout seconds (must be positive; default `2 * ping count`) |
| `-p 3` | Ping count (must be positive) |
| `--dns 8.8.8.8` | Resolver for **ConfiguredDNS** / records |
| `--doh` | DNS-over-HTTPS for **DNS** (default RFC 8484 `dns-message`) |
| `--doh-url` | HTTPS DoH endpoint |
| `--doh-format` | `rfc8484` (default) or `json` (provider `dns-json`) |
| `--doh-bootstrap` | Dial this IP for DoH while keeping TLS server name (bootstrap without system DNS) |
| `--method HEAD` | HTTP(S) method |
| `--follow-redirects` | Follow redirects |
| `--insecure` | Skip TLS verify only when set (security risk) |
| `--extra` | traceroute, whois, MTU (requires local tools) |
| `--skip ping,http` | Skip named checks; `--skip=` clears YAML skips |
| `--config PATH` | YAML defaults (`os.UserConfigDir()/dstp/config.yaml`) |
| `-q` | Quiet (no progress) |
| `-v` / `-h` | Version / help (processed before config load) |

Check IDs: `ping`, `dns`, `configured_dns`, `records`, `tcp`, `udp`, `tls`, `http`, `https`, `traceroute`, `whois`, `mtu`.

Statuses: `ok`, `warning`, `inconclusive`, `error`, `skipped`. Exit `1` only on `error`.

```bash
dstp example.com -o json
dstp https://example.com:8443/health?q=1
dstp staging --config ./prod.yaml   # probes staging, not YAML addr
dstp example.com --extra -q
dstp 1.1.1.1 --insecure --skip http,https
```

### Config file

Default path: `$XDG_CONFIG_HOME/dstp/config.yaml` (or platform `UserConfigDir`). Missing default file is OK; missing **explicit** `--config` fails.

```yaml
out: plaintext
timeout: 5
ping_count: 3
dns: 1.1.1.1
doh: false
doh_url: https://cloudflare-dns.com/dns-query
method: GET
follow_redirects: false
insecure: false
extra: false
skip: [ping]
quiet: true
port: "443"
tcp_port: "443"
udp_port: "53"
http_port: "80"
```

Precedence: defaults → YAML → CLI flags → **positional target**. Unknown YAML keys are rejected.

## Completions & man page

```bash
source completions/dstp.zsh   # zsh
source completions/dstp.bash  # bash
man ./man/dstp.1
```

## Develop

```bash
make check          # fmt, vet, lint, test, race, release-check
make release-check  # goreleaser check + snapshot
```

## License

[MIT](LICENSE) — upstream copyright retained; fork modifications © 2026 Divyendra Patil.
