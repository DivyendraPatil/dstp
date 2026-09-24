# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| latest release on `main` / GitHub Releases | Yes |
| older tagged releases | Best-effort only |

Security fixes land on `main` and ship in the next patch release.

## Reporting a vulnerability

Please open a private [GitHub security advisory](https://github.com/DivyendraPatil/dstp/security/advisories/new).

If you cannot use advisories, contact the maintainer via the GitHub profile for `DivyendraPatil`.

- Acknowledgement target: within **3 business days**
- Coordinated disclosure: we aim to ship a fix or mitigation within **90 days** of a confirmed report (sooner for critical issues)

Do not open a public issue for undisclosed vulnerabilities.

## Notes

- `--insecure` disables TLS certificate verification by design; only use it deliberately. Prefer fixing trust/SANs instead.
- System tools (`ping`, `traceroute`, `whois`) are invoked with fixed argument vectors (no shell). Targets that look like flags are rejected.
- `whois` / `traceroute` may be absent on Windows or minimal Linux images; those checks fail with a clear message when tools are missing.

## External enrichment (routing profile)

When `--profile network` (or `full` with routing checks) is enabled, dstp may query third-party services with the **target IP / ASN / prefix only** — never full diagnostic dumps, cookies, or Authorization headers.

Planned defaults (no API key for the useful path):

| Purpose | Provider | What is sent |
|---------|----------|--------------|
| Target ASN / prefix / RPKI | [RIPEstat Data API](https://stat.ripe.net/docs/data_api) | IP, prefix, ASN |
| Traceroute hop ASN notes | [Team Cymru IP-to-ASN DNS](https://www.team-cymru.com/ip-asn-mapping) | Hop IP (public only) |
| Registration (RDAP) | RIR / rdap.org | IP or domain |
| Optional PeeringDB | PeeringDB API | ASN |

Special-use addresses (private, loopback, link-local, documentation, CGNAT, etc.) are classified locally and are **not** sent to these APIs. Provider failures are reported as `unknown` / skipped — never as RPKI `invalid`.
