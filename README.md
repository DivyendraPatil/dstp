# dstp

Run networking checks against a host — ping, DNS, TCP/UDP, TLS, HTTP/HTTPS/HTTP3, CDN, mail auth, DNSSEC, and (with `--profile network`) ASN/RPKI/RDAP + traceroute — in one command.

```bash
GOBIN="$(go env GOPATH)/bin" go install github.com/DivyendraPatil/dstp/cmd/dstp@latest
export PATH="$(go env GOPATH)/bin:$PATH"
hash -r
dstp example.com
```

If you use **asdf** (or another Go toolchain manager), `go install` may write to the toolchain’s bin while an older `~/go/bin/dstp` stays first on `PATH`. Prefer the `GOBIN=…` form above so the binary lands where `which dstp` looks.

`go install @vX.Y.Z` reports `commit none, built unknown` unless you build with `-ldflags` (as `make install` / release binaries do). That is expected — version number is still correct.

Exit codes: `0` success (or help/version), `1` check failure, `2` bad usage, `130` interrupted.

## Install

Requires **Go 1.26.0+** (CI/toolchain uses **1.26.6**).

```bash
GOBIN="$(go env GOPATH)/bin" go install github.com/DivyendraPatil/dstp/cmd/dstp@latest
# pin a release:
GOBIN="$(go env GOPATH)/bin" go install github.com/DivyendraPatil/dstp/cmd/dstp@v0.9.0
# or from a clone (embeds version/commit/date):
make install
```

Binary releases (when published): download the archive for your OS from GitHub Releases, verify `checksums.txt`, and optionally verify the Cosign/Sigstore bundle (`checksums.txt.sigstore.json`) with `cosign verify-blob`. SBOMs ship alongside archives.

> `brew install dstp` still installs upstream [ycd/dstp](https://github.com/ycd/dstp). Use `go install` for **this** fork.

## Common options

| Flag | What it does |
|------|----------------|
| `-a, --addr` / positional | Target host/URL/IP. **Positional overrides** YAML `addr`. Full URLs keep scheme/port/path/query for HTTP(S). |
| `-o json` | JSON with `status` / `content` / `error` (`configured_dns` key); optional additive `network` object |
| `-t 5` | Per-check timeout seconds (must be positive; default `2 * ping count`) |
| `-p 3` | Ping count (must be positive) |
| `--port` / `--tcp-port` / `--udp-port` / `--http-port` | TLS/HTTPS, TCP, UDP, cleartext HTTP ports (defaults `443` / same as `--port` / `53` / `80`) |
| `--dns 8.8.8.8` | Resolver for **ConfiguredDNS** / records |
| `--doh` | DNS-over-HTTPS for **DNS** (default RFC 8484 `dns-message`) |
| `--doh-url` | HTTPS DoH endpoint |
| `--doh-format` | `rfc8484` (default) or `json` (provider `dns-json`) |
| `--doh-bootstrap` | Dial this IP for DoH while keeping TLS server name (bootstrap without system DNS) |
| `--method HEAD` | HTTP(S) method |
| `--follow-redirects` | Follow redirects |
| `--profile` | Preset: **`web`** (default), `mail`, `dns`, `api`, `network`, `full` |
| `--insecure` | Skip TLS verify only when set (security risk) |
| `--extra` | traceroute, whois, MTU (requires local tools; auto-on for `network`) |
| `--skip ping,http` | Extra skips merged with the profile; `--skip=` clears YAML skips |
| `--config PATH` | YAML defaults (`os.UserConfigDir()/dstp/config.yaml`) |
| `-q` | Quiet (no progress) |
| `-v` / `-h` | Version / help (processed before config load) |

Check IDs: `ping`, `dns`, `configured_dns`, `records`, `mail`, `dnssec`, `routing`, `rdap`, `tcp`, `udp`, `tls`, `http`, `https`, `http3`, `cdn`, `traceroute`, `whois`, `mtu`. Alias: `system_dns` → `configured_dns`.

Statuses: `ok`, `warning`, `inconclusive`, `error`, `skipped`. Exit `1` only on `error`. Skipped checks are omitted from plaintext (still present in JSON). HTTPS/HTTP3 **403** with Cloudflare/`cf-ray` is reported as a warning with an edge challenge/WAF note (transport still OK).

**Profiles**

| Profile | Focus | Skips |
|---------|--------|--------|
| `web` (default) | Site/CDN: DNS, TCP, TLS, HTTP(S), HTTP/3, CDN | `udp`, `mail`, `dnssec`, `routing`, `rdap` |
| `mail` | SPF / DMARC / DKIM (+ BIMI if present), records, DNSSEC | HTTP stack, ping, TCP/UDP/TLS, routing, rdap |
| `dns` | Resolvers, records, DNSSEC, smarter UDP→NS | HTTP stack, mail, ping, TCP/TLS, routing, rdap |
| `api` | TCP, TLS, HTTPS, HTTP/3, CDN, DNS | `udp`, `mail`, `dnssec`, cleartext `http`, `ping`, routing, rdap |
| `network` | ASN/prefix/RPKI, RDAP, ping/DNS, traceroute/MTU | HTTP/TLS stack, mail, dnssec, whois |
| `full` | Everything | — |

`network` auto-enables `--extra` (traceroute/MTU). Routing uses RIPEstat (no API key); hop ASN notes use Team Cymru DNS. JSON keeps per-check keys and may add a structured `network` object (primary IP plus optional `also`/`note` when v4 and v6 origin ASNs differ).

Default UDP `:53` (in `dns`/`full`) retargets to an NS host when the address is a web/CDN name. TLS warns when the cert expires in ≤30 days and reports chain length, OCSP stapling, and CT/SCT hints.

### Examples

```bash
# default web profile
dstp example.com
dstp example.com -o json -q

# URL keeps scheme/port/path/query for HTTP(S)
dstp https://example.com:8443/health?q=1

# profiles
dstp example.com --profile mail          # SPF/DMARC/DKIM
dstp example.com --profile dns           # resolvers + DNSSEC + UDP→NS
dstp example.com --profile api -q        # TLS/HTTPS/HTTP3/CDN (no cleartext HTTP)
dstp cloudflare.com --profile network -q # ASN/RPKI/RDAP + traceroute/MTU
dstp example.com --profile full -q

# routing detail in JSON (additive "network" object)
dstp cloudflare.com --profile network -o json -q

# DoH + custom resolver
dstp example.com --doh --dns 1.1.1.1
dstp example.com --doh --doh-format json --doh-bootstrap 1.1.1.1

# ports, skips, extra path probes
dstp example.com --port 8443 --tcp-port 8443
dstp 1.1.1.1 --insecure --skip http,https
dstp example.com --extra                 # traceroute/whois/mtu on top of profile
dstp staging --config ./prod.yaml        # probes staging, not YAML addr
```

### Config file

Default path: `$XDG_CONFIG_HOME/dstp/config.yaml` (or platform `UserConfigDir`). Missing default file is OK; missing **explicit** `--config` fails.

```yaml
out: plaintext
profile: web
timeout: 5
ping_count: 3
dns: 1.1.1.1
doh: false
doh_url: https://cloudflare-dns.com/dns-query
doh_format: rfc8484
method: GET
follow_redirects: false
insecure: false
extra: false
skip: []
quiet: true
port: "443"
tcp_port: "443"
udp_port: "53"
http_port: "80"
```

Precedence: defaults → YAML → CLI flags → **positional target**. Unknown YAML keys are rejected.

## Completions & man page

```bash
make completions              # regenerate from Registry / CheckIDs()
source completions/dstp.zsh   # zsh
source completions/dstp.bash  # bash
man ./man/dstp.1
```

## Develop

```bash
make check          # fmt, vet, lint, test, race, release-check
make release-check  # goreleaser check + snapshot
make completions    # sync shell completions with check IDs
```

## License

[MIT](LICENSE) — upstream copyright retained; fork modifications © 2026 Divyendra Patil.
