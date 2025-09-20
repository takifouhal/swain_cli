# swaggen

swaggen is a zero-setup CLI that wraps OpenAPI Generator so you can generate SDKs without installing Java or the generator yourself. It bundles a pinned OpenAPI Generator JAR and lazily downloads a trimmed OpenJDK runtime on first use.

## Features

- Generate SDKs for multiple target languages in a single command
- Bundled OpenAPI Generator `7.6.0` for reproducible output
- Embedded OpenJDK 21 runtime download on demand, or use a system Java installation
- Helper commands to inspect environments and manage the embedded engine assets
- Zero external Python dependencies; works great with `pipx`

## Installation

```bash
pipx install swaggen
```

> Python 3.8 or newer is required. Installing via `pipx` keeps swaggen isolated from your global environment.

### Optional one-file binaries

Repository maintainers can produce PyInstaller one-file executables for platforms listed in the CI workflow. See `.github/workflows/release.yml` for details.

## Quickstart

```bash
# (optional) Pre-install the embedded runtime to avoid first-run download
swaggen engine install-jre

# Show available generators (uses the bundled OpenAPI Generator)
swaggen list-generators

# Generate Python and TypeScript SDKs into ./sdks/*
swaggen gen -i ./openapi.yaml -l python -l typescript -o ./sdks \
  -p packageName=my_api_client -p packageVersion=0.1.0

# Use custom generator config and templates
swaggen gen -i ./openapi.yaml -l python -o ./sdks \
  -c ./configs/python.yaml -t ./templates/python
```

## Commands

- `swaggen doctor` — print environment and engine status
- `swaggen list-generators [--engine embedded|system]` — list supported generators via OpenAPI Generator
- `swaggen gen` — generate SDKs for one or more target generators
- `swaggen engine <action>` — manage the embedded runtime and jar cache

Run `swaggen --help` or `swaggen <command> --help` for detailed usage.

## Caching and assets

The embedded JRE and generator JAR are cached in the per-user cache directory (`~/.cache/swaggen` on Linux, `%LOCALAPPDATA%\\swaggen\\cache` on Windows, `~/Library/Caches/swaggen` on macOS). Checksums are verified when SHA-256 values are available.

## Contributing

1. Create a virtual environment (`python -m venv .venv`) and activate it
2. Install the project in editable mode: `pip install -e .`
3. Run `python -m swaggen.cli --help` or invoke `swaggen` using the entry point script
4. Add or update tests (TODO) and run them

## Third-party notices

- OpenAPI Generator (Apache 2.0)
- Eclipse Temurin OpenJDK (GPLv2 with Classpath Exception)

## License

swaggen is released under the Apache 2.0 license. See `LICENSE` (TODO) for details. OpenAPI Generator is licensed under Apache 2.0 and the bundled OpenJDK is licensed under GPLv2 with Classpath Exception.
