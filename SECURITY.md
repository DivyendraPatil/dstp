# Security Policy

## Supported versions

Security fixes are applied to the latest release of this repository (`github.com/DivyendraPatil/dstp`).

## Reporting a vulnerability

Please open a private [GitHub security advisory](https://github.com/DivyendraPatil/dstp/security/advisories/new) or email the maintainer via the GitHub profile.

Do not open a public issue for undisclosed vulnerabilities.

## Notes

- `--insecure` disables TLS certificate verification by design; only use it deliberately.
- System tools (`ping`, `traceroute`, `whois`) are invoked with fixed argument vectors (no shell).
