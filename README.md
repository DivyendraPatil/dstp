# dstp

Run networking checks against a host — ping, DNS, TCP/UDP, TLS, HTTP/HTTPS — in one command.

```bash
go install github.com/DivyendraPatil/dstp/cmd/dstp@latest
dstp example.com
```

If `dstp` is “command not found” after install, your `GOBIN` may not be on `PATH`. Fix:

```bash
# preferred: install into ~/go/bin (usually already on PATH)
GOBIN="$(go env GOPATH)/bin" go install github.com/DivyendraPatil/dstp/cmd/dstp@latest

# ensure PATH includes it
export PATH="$(go env GOPATH)/bin:$PATH"
```

Example output:

```text
Ping: 12ms
DNS: IPv4=… IPv6=…
ConfiguredDNS: IPv4=… IPv6=…
Records: A=…; AAAA=…; NS=…
TCP: connected to example.com:443 in 40ms
UDP: udp example.com:53 reachable (no reply in 12ms)
TLS: valid 73 days; issuer=…; proto=TLS1.3; …
HTTP: GET 301 Moved Permanently; TTFB=30ms; location=https://…
HTTPS: GET 200 OK; TTFB=90ms; proto=TLS1.3
```

Exit code is `1` if any check fails. `dstp -v` prints the build version.

## Install

```bash
GOBIN="$(go env GOPATH)/bin" go install github.com/DivyendraPatil/dstp/cmd/dstp@latest
# or from a clone:
make install
```

Requires **Go 1.26+**.

> `brew install dstp` still installs upstream [ycd/dstp](https://github.com/ycd/dstp). Use `go install` for **this** fork.

## Common options

| Flag | What it does |
|------|----------------|
| `-a, --addr` | Target host/URL/IP (or first argument) |
| `-o json` | JSON with `status` / `content` / `error` |
| `-t 5` | Per-check timeout (seconds) |
| `--dns 8.8.8.8` | Resolver for **ConfiguredDNS** |
| `--doh` | DNS-over-HTTPS for **DNS** |
| `--method HEAD` | HTTP(S) method |
| `--follow-redirects` | Follow redirects |
| `--insecure` | Skip TLS verify (also noted for IP targets) |
| `--extra` | Also run traceroute, whois, MTU |
| `--skip ping,http` | Skip named checks |
| `--config PATH` | YAML defaults (`~/.config/dstp/config.yaml`) |
| `-q` | Quiet (no progress) |
| `-v` | Version |

```bash
dstp example.com -o json
dstp example.com --dns 1.1.1.1 --doh
dstp example.com --extra -q
dstp 1.1.1.1 --insecure --skip http,https
```

### Config file example

`~/.config/dstp/config.yaml`:

```yaml
out: plaintext
timeout: 5
dns: 1.1.1.1
skip: [ping]
quiet: true
```

## Completions & man page

```bash
# zsh
source completions/dstp.zsh

# bash
source completions/dstp.bash

# man
man ./man/dstp.1
```

## License

[MIT](LICENSE)
