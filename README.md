# swain_cli

`swain_cli` is a zero-setup CLI that wraps OpenAPI Generator so you can generate SDKs without installing Java or the generator yourself. The package vendors the OpenAPI Generator JAR, fetches a trimmed Temurin JRE on demand, and keeps everything cached per-user for reproducible results.

## Why swain_cli
- Generate SDKs for multiple target languages with one command
- Pinned OpenAPI Generator `7.6.0` for consistent output across machines
- Embedded OpenJDK 21 runtime download on first use (or opt into system Java)
- Light Python dependency stack (Typer, httpx, questionary, platformdirs, keyring, pooch) that stays friendly for `pipx`, CI, and ephemeral environments
- Helper commands to inspect and manage the embedded engine assets

## Install

```bash
pipx install swain_cli
```

> Python 3.8 or newer is required. Installing via `pipx` keeps swain_cli isolated from other tooling. You can also use `pip install swain_cli` inside a virtual environment if you prefer.

## First run

```bash
# (optional) Pre-install the embedded runtime to skip the first-run download
swain_cli engine install-jre

# (optional) Guided wizard that builds your swain_cli gen command
swain_cli interactive

# List all bundled generators (delegates to the pinned OpenAPI Generator)
swain_cli list-generators

# Generate Python and TypeScript clients into ./sdks/<generator>
swain_cli gen -i ./openapi.yaml -l python -l typescript -o ./sdks \
  -p packageName=my_api_client -p packageVersion=0.2.1
```

`swain_cli` streams OpenAPI Generator output directly, so you see progress as the SDK is generated.

## Command overview
- `swain_cli gen` — generate one or more SDKs; accepts the same configuration flags as OpenAPI Generator (`-c`, `-t`, `-p`, etc.) and repeatable `-l/--lang` options. By default swain_cli pulls the CrudSQL dynamic swagger from `https://api.swain.technology`; override with `--crudsql-url` or provide `-i/--schema` to use a local file/URL instead.
- `swain_cli interactive` — answer a short Q&A and swain_cli assembles (and optionally runs) the matching `swain_cli gen` command
- `swain_cli list-generators` — enumerate supported generators; add `--engine system` to check a local Java installation
- `swain_cli doctor` — print environment details, cache paths, installed JREs, and whether the vendor JAR is available
- `swain_cli auth` — log in, log out, or inspect authentication state for future swain_cli features
- `swain_cli engine <action>` — manage the embedded runtime (`status`, `install-jre`, `update-jar`, `use-system`, `use-embedded`)

Run `swain_cli --help` or `swain_cli <command> --help` for complete usage.

## Authentication
Use the `auth` subcommands to prime swain_cli with credentials for the hosted platform you will be integrating with.

- `swain_cli auth login`: Supply an access token via `--token <value>`, pipe it with `--stdin`, or let swain_cli prompt securely. The token is stored in the system keyring (or use `SWAIN_CLI_AUTH_TOKEN` for ephemeral sessions).
- `swain_cli auth status`: Inspect the currently active token source and see where swain_cli will read credentials from.
- `swain_cli auth logout`: Delete the stored token if you need to rotate or clear credentials.
- Tokens live in the system keyring; use `SWAIN_CLI_AUTH_TOKEN` for ephemeral sessions or automation.
- The `swain_cli interactive` wizard begins by checking for an access token and will prompt you to add or replace one before continuing if none is available.

```
                               +--------------------+
                               | swain_cli auth login |
                               +----------+---------+
                                          |
               +--------------------------+---------------------------+
               |                          |                           |
         --token flag            --stdin (piped input)          interactive prompt
               |                          |                           |
               +--------------------------+---------------------------+
                                          |
                                          v
                               +------------------------------+
                               | store credential in keyring  |
                               +----------+-------------------+
                                          |
                                resolve_auth_token()
                                          |
                           +--------------+--------------+
                           |                             |
             SWAIN_CLI_AUTH_TOKEN set?          keyring credential?
                           |                             |
                    use env token          use masked value from keyring
                           |                             |
                           +--------------+--------------+
                                          |
                                          v
                               +--------------------+
                               | authenticated CLI  |
                               | requests (future)  |
                               +--------------------+
```

`SWAIN_CLI_AUTH_TOKEN` always takes precedence over anything written to disk, which is useful for one-off runs in CI. Pair `swain_cli auth status` with `SWAIN_CLI_CONFIG_DIR` to verify exactly which file swain_cli will read when the CLI gains authenticated commands.

### CrudSQL integration
- `swain_cli gen` (with no schema flag) automatically downloads the CrudSQL schema document from `https://api.swain.technology` using the stored token as a `Bearer` credential before running OpenAPI Generator. The CLI first calls `/api/schema-location` to resolve the live schema URL, then falls back to the legacy `/api/dynamic_swagger` path if discovery fails. (The production endpoint is still being finalized; expect this URL to change.)
- Override the source with `--crudsql-url https://api.example.com` or bypass CrudSQL entirely by supplying `-i/--schema`.
- The retrieved schema is cached to a temp file for the duration of the command and removed afterwards.

```
                 +-----------------------------------+
                 | swain_cli gen / interactive wizard  |
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
- **Multiple targets**: Pass `-l`/`--lang` repeatedly (`swain_cli gen ... -l python -l typescript`) and each generator gets its own subfolder beneath the output directory.
- **Custom generator config**: Provide OpenAPI Generator configuration with `-c ./configs/python.yaml` and template overrides via `-t ./templates/python`.
- **Additional properties**: Use `-p key=value` (repeatable) or `--generator-arg "--enable-post-process-file"` to forward advanced options.
- **TypeScript alias**: `typescript` automatically maps to `typescript-axios`; request `typescript-fetch` explicitly if you need the alternative runtime.

## Engine modes and caching
- **Embedded engine (default)**: On first use, swain_cli downloads a platform-specific JRE archive from the project’s GitHub Releases and stores it with the vendor JAR under the user cache directory (see below).
- **System engine**: Add `--engine system` (or export `SWAIN_CLI_ENGINE=system`) to use whatever `java` is on `PATH`. This is handy on servers where the embedded download is blocked or not desired.
- **Cache location**: By default caches live under `~/.cache/swain_cli` (Linux), `~/Library/Caches/swain_cli` (macOS), or `%LOCALAPPDATA%\swain_cli\cache` (Windows). Override the root with `SWAIN_CLI_CACHE_DIR=/custom/path`.
- **Offline use**: Prime the cache by running `swain_cli engine install-jre` before going offline, or copy an existing cache directory to new machines.

## Running in CI
1. Install the CLI (for example `pipx install swain_cli` or `pip install swain_cli`).
2. Pre-install the embedded engine at build time (`swain_cli engine install-jre`) to avoid downloading during critical steps.
3. Cache the swain_cli cache directory between jobs to reuse the JRE and downloaded JARs.
4. Invoke `swain_cli gen` with your schema and desired generators; capture the generated SDK directories as build artifacts.

## Troubleshooting
- **Download failures**: Check your proxy/firewall. You can download the JRE artifact manually from the GitHub release and place it under the cache path shown by `swain_cli doctor`.
- **Missing generators**: `swain_cli list-generators --engine system` verifies what your system Java installation provides. If you updated OpenAPI Generator via `swain_cli engine update-jar`, rerun `list-generators` to ensure the new jar is active.
- **Cache cleanup**: Delete the cache directory printed by `swain_cli doctor` to force a clean fetch of the runtime and JAR.

## Contributing
1. Create a virtual environment (`python -m venv .venv`) and activate it.
2. Install the project in editable mode with dev extras: `pip install -e .[dev]`.
3. Run the CLI locally via `python -m swain_cli.cli --help` or the `swain_cli` console script.
4. Update or add tests and run them with `python -m pytest`.

## Maintainers
- Use the `build-jre` GitHub Action (workflow dispatch) to produce trimmed JRE archives for Linux (x86_64 + arm64), macOS (Intel + Apple Silicon), and Windows. Optionally provide a `release_tag` to upload artifacts directly to a `jre-<version>` release.
- After the workflow finishes, copy the resulting `.sha256` values into `swain_cli/cli.py` so the CLI can verify downloads, and adjust `ASSET_BASE` if you publish assets under a new release tag.
- Trigger the `release` workflow by pushing a `v*` tag once assets are in place. It builds the PyPI distributions and optional PyInstaller binaries. The full release runbook lives in `docs/RELEASING.md`.

## Third-party notices
- OpenAPI Generator (Apache 2.0)
- Eclipse Temurin OpenJDK (GPLv2 with Classpath Exception)

## License

swain_cli is released under the Apache 2.0 license. See `LICENSE` for details.
