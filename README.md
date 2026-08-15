# dstp

Run common networking checks against a host — ping, DNS, TCP, TLS, and HTTPS — in one command.

```bash
dstp example.com
```

Example output:

```text
Ping: 12ms
DNS: IPv4=93.184.216.34 IPv6=2606:2800:220:1:248:1893:25c8:1946
ConfiguredDNS: IPv4=93.184.216.34 IPv6=2606:2800:220:1:248:1893:25c8:1946
Records: A=…; AAAA=…; NS=…
TCP: connected to example.com:443 in 40ms
TLS: valid 73 days; issuer=…; proto=TLS1.3; cipher=…
HTTPS: GET 200 OK; TTFB=90ms; proto=TLS1.3
```

Exit code is `1` if any check fails.

## Install

```bash
brew install dstp
# or
go install github.com/ycd/dstp/cmd/dstp@latest
```

Requires **Go 1.26+** to build from source.

> This fork: [DivyendraPatil/dstp](https://github.com/DivyendraPatil/dstp). Module path stays `github.com/ycd/dstp` for `go install` compatibility.

## Common options

| Flag | What it does |
|------|----------------|
| `-a, --addr` | Target host/URL/IP (or pass as the first argument) |
| `-o json` | Machine-readable output with `status` / `content` / `error` |
| `-t 5` | Per-check timeout in seconds |
| `--dns 8.8.8.8` | Resolver for the **ConfiguredDNS** check |
| `--doh` | Use DNS-over-HTTPS for the **DNS** check |
| `--method HEAD` | HTTPS request method (`GET` or `HEAD`) |
| `--follow-redirects` | Follow HTTPS redirects (off by default) |
| `--skip ping,records` | Skip named checks |
| `-q` | Quiet (no progress on stderr) |

```bash
dstp example.com -o json
dstp example.com --dns 1.1.1.1 --doh
dstp example.com --method HEAD --follow-redirects
dstp example.com --skip ping -q
```

## What each check means

| Name | Meaning |
|------|---------|
| **Ping** | ICMP latency |
| **DNS** | Default system resolver (or DoH with `--doh`) |
| **ConfiguredDNS** | System resolver, or `--dns` if set |
| **Records** | A / AAAA / CNAME / MX / NS / TXT |
| **TCP** | Plain TCP connect (`--tcp-port`, default 443) |
| **TLS** | Cert expiry, issuer, protocol, cipher, SANs |
| **HTTPS** | Status, TTFB, redirects |

## Build from source

```bash
git clone https://github.com/DivyendraPatil/dstp
cd dstp
make
./dstp example.com -q
```

## Also available via

- [Nix](https://search.nixos.org/packages?query=dstp): `nix shell nixpkgs#dstp`
- [AUR](https://aur.archlinux.org/packages/dstp)
- [GitHub Releases](https://github.com/ycd/dstp/releases) (upstream binaries)

## Note for oh-my-zsh + Docker

`dstp` may collide with the Docker plugin alias for `docker stop`. Add to `~/.zshrc`:

```zsh
unalias dstp
```

## License

[MIT](LICENSE)
