# swaggen

`swaggen` is a zero-setup CLI that wraps OpenAPI Generator so you can generate SDKs without installing Java or the generator yourself. The package vendors the OpenAPI Generator JAR, fetches a trimmed Temurin JRE on demand, and keeps everything cached per-user for reproducible results.

## Why swaggen
- Generate SDKs for multiple target languages with one command
- Pinned OpenAPI Generator `7.6.0` for consistent output across machines
- Embedded OpenJDK 21 runtime download on first use (or opt into system Java)
- Zero runtime Python dependencies, ideal for `pipx`, CI, and ephemeral environments
- Helper commands to inspect and manage the embedded engine assets

## Install

```bash
pipx install swaggen
```

> Python 3.8 or newer is required. Installing via `pipx` keeps swaggen isolated from other tooling. You can also use `pip install swaggen` inside a virtual environment if you prefer.

## First run

```bash
# (optional) Pre-install the embedded runtime to skip the first-run download
swaggen engine install-jre

# (optional) Guided wizard that builds your swaggen gen command
swaggen interactive

# List all bundled generators (delegates to the pinned OpenAPI Generator)
swaggen list-generators

# Generate Python and TypeScript clients into ./sdks/<generator>
swaggen gen -i ./openapi.yaml -l python -l typescript -o ./sdks \
  -p packageName=my_api_client -p packageVersion=0.1.0
```

`swaggen` streams OpenAPI Generator output directly, so you see progress as the SDK is generated.

## Command overview
- `swaggen gen` — generate one or more SDKs; accepts the same configuration flags as OpenAPI Generator (`-c`, `-t`, `-p`, etc.) and repeatable `-l/--lang` options. By default swaggen pulls the CrudSQL dynamic swagger from `https://api.swain.technology`; override with `--crudsql-url` or provide `-i/--schema` to use a local file/URL instead.
- `swaggen interactive` — answer a short Q&A and swaggen assembles (and optionally runs) the matching `swaggen gen` command
- `swaggen list-generators` — enumerate supported generators; add `--engine system` to check a local Java installation
- `swaggen doctor` — print environment details, cache paths, installed JREs, and whether the vendor JAR is available
- `swaggen auth` — log in, log out, or inspect authentication state for future swaggen features
- `swaggen engine <action>` — manage the embedded runtime (`status`, `install-jre`, `update-jar`, `use-system`, `use-embedded`)

Run `swaggen --help` or `swaggen <command> --help` for complete usage.

## Authentication
Use the `auth` subcommands to prime swaggen with credentials for the hosted platform you will be integrating with.

- `swaggen auth login`: Supply an access token via `--token <value>`, pipe it with `--stdin`, or let swaggen prompt securely. The token is written to a per-user config file (`auth.json`) with user-only permissions where the OS supports it.
- `swaggen auth status`: Inspect the currently active token source and see where swaggen will read credentials from.
- `swaggen auth logout`: Delete the stored token if you need to rotate or clear credentials.
- Override the configuration root with `SWAGGEN_CONFIG_DIR=/custom/path`. The default lives under the platform’s standard config directory (for example `~/Library/Application Support/swaggen`).
- The `swaggen interactive` wizard begins by checking for an access token and will prompt you to add or replace one before continuing if none is available.

```
                               +--------------------+
                               | swaggen auth login |
                               +----------+---------+
                                          |
               +--------------------------+---------------------------+
               |                          |                           |
         --token flag            --stdin (piped input)          interactive prompt
               |                          |                           |
               +--------------------------+---------------------------+
                                          |
                                          v
                               +--------------------+
                               | write auth.json    |
                               | (user config dir)  |
                               +----------+---------+
                                          |
                                resolve_auth_token()
                                          |
                           +--------------+--------------+
                           |                             |
             SWAGGEN_AUTH_TOKEN set?          stored token available?
                           |                             |
                    use env token          use masked value from auth.json
                           |                             |
                           +--------------+--------------+
                                          |
                                          v
                               +--------------------+
                               | authenticated CLI  |
                               | requests (future)  |
                               +--------------------+
```

`SWAGGEN_AUTH_TOKEN` always takes precedence over anything written to disk, which is useful for one-off runs in CI. Pair `swaggen auth status` with `SWAGGEN_CONFIG_DIR` to verify exactly which file swaggen will read when the CLI gains authenticated commands.

### CrudSQL integration
- `swaggen gen` (with no schema flag) automatically downloads the CrudSQL schema document from `https://api.swain.technology` using the stored token as a `Bearer` credential before running OpenAPI Generator. The CLI first calls `/api/schema-location` to resolve the live schema URL, then falls back to the legacy `/api/dynamic_swagger` path if discovery fails. (The production endpoint is still being finalized; expect this URL to change.)
- Override the source with `--crudsql-url https://api.example.com` or bypass CrudSQL entirely by supplying `-i/--schema`.
- The retrieved schema is cached to a temp file for the duration of the command and removed afterwards.

```
                 +-----------------------------------+
                 | swaggen gen / interactive wizard  |
                 +----------------+------------------+
                                  |
                        schema flag provided?
                         (-i / --schema)
                     yes /                \ no
                    v                     v
        use provided path/URL     CrudSQL base selected?
                                           |
                         +-----------------+-----------------+
                         |                                   |
                 flag or wizard override?          default host (Swain)
                     (--crudsql-url)            https://api.swain.technology
                         |                                   |
                         v                                   v
                resolve schema location -> download document with stored token
                                  |
                                  v
                     run OpenAPI Generator for each language
```

## Generating clients effectively
- **Multiple targets**: Pass `-l`/`--lang` repeatedly (`swaggen gen ... -l python -l typescript`) and each generator gets its own subfolder beneath the output directory.
- **Custom generator config**: Provide OpenAPI Generator configuration with `-c ./configs/python.yaml` and template overrides via `-t ./templates/python`.
- **Additional properties**: Use `-p key=value` (repeatable) or `--generator-arg "--enable-post-process-file"` to forward advanced options.
- **TypeScript alias**: `typescript` automatically maps to `typescript-axios`; request `typescript-fetch` explicitly if you need the alternative runtime.

## Engine modes and caching
- **Embedded engine (default)**: On first use, swaggen downloads a platform-specific JRE archive from the project’s GitHub Releases and stores it with the vendor JAR under the user cache directory (see below).
- **System engine**: Add `--engine system` (or export `SWAGGEN_ENGINE=system`) to use whatever `java` is on `PATH`. This is handy on servers where the embedded download is blocked or not desired.
- **Cache location**: By default caches live under `~/.cache/swaggen` (Linux), `~/Library/Caches/swaggen` (macOS), or `%LOCALAPPDATA%\swaggen\cache` (Windows). Override the root with `SWAGGEN_CACHE_DIR=/custom/path`.
- **Offline use**: Prime the cache by running `swaggen engine install-jre` before going offline, or copy an existing cache directory to new machines.

## Running in CI
1. Install the CLI (for example `pipx install swaggen` or `pip install swaggen`).
2. Pre-install the embedded engine at build time (`swaggen engine install-jre`) to avoid downloading during critical steps.
3. Cache the swaggen cache directory between jobs to reuse the JRE and downloaded JARs.
4. Invoke `swaggen gen` with your schema and desired generators; capture the generated SDK directories as build artifacts.

## Troubleshooting
- **Download failures**: Check your proxy/firewall. You can download the JRE artifact manually from the GitHub release and place it under the cache path shown by `swaggen doctor`.
- **Missing generators**: `swaggen list-generators --engine system` verifies what your system Java installation provides. If you updated OpenAPI Generator via `swaggen engine update-jar`, rerun `list-generators` to ensure the new jar is active.
- **Cache cleanup**: Delete the cache directory printed by `swaggen doctor` to force a clean fetch of the runtime and JAR.

## Contributing
1. Create a virtual environment (`python -m venv .venv`) and activate it.
2. Install the project in editable mode with dev extras: `pip install -e .[dev]`.
3. Run the CLI locally via `python -m swaggen.cli --help` or the `swaggen` console script.
4. Update or add tests and run them with `python -m pytest`.

## Maintainers
- Use the `build-jre` GitHub Action (workflow dispatch) to produce trimmed JRE archives for Linux (x86_64 + arm64), macOS (Intel + Apple Silicon), and Windows. Optionally provide a `release_tag` to upload artifacts directly to a `jre-<version>` release.
- After the workflow finishes, copy the resulting `.sha256` values into `swaggen/cli.py` so the CLI can verify downloads, and adjust `ASSET_BASE` if you publish assets under a new release tag.
- Trigger the `release` workflow by pushing a `v*` tag once assets are in place. It builds the PyPI distributions and optional PyInstaller binaries. The full release runbook lives in `docs/RELEASING.md`.

## Third-party notices
- OpenAPI Generator (Apache 2.0)
- Eclipse Temurin OpenJDK (GPLv2 with Classpath Exception)

## License

swaggen is released under the Apache 2.0 license. See `LICENSE` for details.
