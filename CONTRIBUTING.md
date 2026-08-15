# Contributing

Thanks for helping improve dstp.

## Development

```bash
git clone https://github.com/DivyendraPatil/dstp
cd dstp
make test
make build
./dstp example.com -q
```

Requires Go **1.26.0+** (toolchain `go1.26.6`). Prefer `make check` before opening a PR.

## Pull requests

- Keep changes focused and tested (`go test ./...`).
- Match existing style; prefer small commits with clear messages.
- Update the README when you change CLI behavior.

## Code of conduct

Be respectful. Hostile or abusive behavior will not be tolerated.
