# swain_cli

`swain_cli` is a zero-setup CLI around OpenAPI Generator. It vendors the generator JAR, downloads a trimmed Temurin JRE on demand, and caches everything per user so you can build SDKs consistently without installing Java yourself.

## Highlights
- Generate SDKs for multiple languages with a single command or an interactive wizard
- Ship exactly what you test with OpenAPI Generator `7.6.0` pinned inside the toolchain
- Launch the bundled OpenJDK 21 runtime automatically (or opt into your own `java`)
- Keep dependencies light (Typer, httpx, questionary, platformdirs, keyring, pooch) so `pipx`, CI, and ephemeral environments stay happy
- Inspect and manage the embedded engine with helper commands (`engine`, `doctor`, `list-generators`)

## Installation
```bash
pipx install swain_cli
```

Python 3.8+ is required. Installing with `pipx` keeps `swain_cli` isolated; alternatively run `pip install swain_cli` in a virtual environment.

## Quick start
```bash
# Prime the embedded runtime so the first real run is instant
swain_cli engine install-jre

# Explore generators and craft a command via guided prompts
swain_cli interactive

# List all bundled generators (delegates to the pinned OpenAPI Generator)
swain_cli list-generators

# Generate Python and TypeScript clients into ./sdks/<generator>
swain_cli gen -i ./openapi.yaml -l python -l typescript -o ./sdks \
  -p packageName=my_api_client -p packageVersion=0.3.0
```
`swain_cli` streams generator output directly so you see progress in real time.

## Generating SDKs
- `swain_cli gen` accepts every OpenAPI Generator flag you already know (`-c`, `-t`, `-p`, etc.) and repeatable `-l/--lang` options.
- By default the CLI downloads the CrudSQL dynamic swagger from `https://api.swain.technology`. Override with `--crudsql-url`, point to a local spec via `-i/--schema`, or combine both for multi-source workflows.
- Swain project integration: provide `--swain-project-id` and `--swain-connection-id` to resolve the deployed connection swagger automatically after authenticating. The CLI will find the active build, fetch `/api/dynamic_swagger`, and feed it to the generator.
- JVM tuning: runs start with `-Xms2g -Xmx10g -XX:+UseG1GC`. If the build still runs out of memory the CLI retries at `-Xmx14g`. Supply extra options with `--java-opt` (repeatable) or export `SWAIN_CLI_JAVA_OPTS`.
- Docs/tests are disabled by default via `--global-property=apiDocs=false,apiTests=false,modelDocs=false,modelTests=false`; override with your own `--generator-arg` when you need them.
- To match modern OAS defaults the CLI automatically adds `-p disallowAdditionalPropertiesIfNotPresent=false`. Opt into stricter behaviour with `-p disallowAdditionalPropertiesIfNotPresent=true` or a generator config file.
- The `typescript` shortcut maps to `typescript-axios`; request `typescript-fetch` explicitly when you need that runtime.

## Command reference
- `swain_cli interactive` — ask a short set of questions, preview the matching `swain_cli gen` command, and optionally run it on the spot. Seed the wizard with `--java-opt` and pass raw OpenAPI Generator flags via `--generator-arg` so interactive runs match your scripts.
- `swain_cli list-generators` — enumerate all generators shipped in the embedded JAR. Add `--engine system` to validate a local Java installation instead.
- `swain_cli doctor` — print environment information, cache paths, installed JREs, and JAR availability to help diagnose setup issues.
- `swain_cli auth` — manage credentials for hosted Swain services (`login`, `logout`, `status`). Tokens live in the system keyring; use `SWAIN_CLI_AUTH_TOKEN` for ephemeral automation.
- `swain_cli engine <action>` — switch between the embedded runtime and your system Java, install the JRE ahead of time, or update the pinned JAR.

Run `swain_cli --help` or `swain_cli <command> --help` for full usage.

## Authentication
Use the `auth` subcommands to prepare credentials before generating SDKs against hosted Swain projects.

- `swain_cli auth login` — provide an access token via `--token <value>`, pipe it with `--stdin`, or let the CLI prompt securely. Tokens are stored in the system keyring unless you set `SWAIN_CLI_AUTH_TOKEN`.
- `swain_cli auth login --credentials --username you@example.com` — authenticate via username/password (`POST /auth/login`). Access and refresh tokens are stored automatically.
- `swain_cli auth status` — inspect the active token source and storage location.
- `swain_cli auth logout` — clear the stored token.
- The interactive wizard checks for a token before listing projects and will prompt you to add or replace one if missing.

## Engine modes and caching
- **Embedded engine (default)** — the first run downloads a platform-specific Temurin JRE and caches it alongside the vendor JAR under `~/.cache/swain_cli` (Linux), `~/Library/Caches/swain_cli` (macOS), or `%LOCALAPPDATA%\swain_cli\cache` (Windows). Override with `SWAIN_CLI_CACHE_DIR`.
- **System engine** — add `--engine system` (or export `SWAIN_CLI_ENGINE=system`) to run with whatever `java` is already on `PATH`.
- **Offline use** — prime the cache via `swain_cli engine install-jre` or copy an existing cache directory between machines.

## Running in CI
1. Install the package (`pipx install swain_cli` or `pip install swain_cli`).
2. Pre-install the embedded runtime during setup: `swain_cli engine install-jre`.
3. Cache the swain_cli cache directory between jobs to reuse downloads.
4. Invoke `swain_cli gen` with your schema and desired generators; capture `./sdks` (or your chosen output path) as build artefacts.

## Troubleshooting
- **Download failures** — check proxy/firewall configuration, or download the JRE asset manually from the GitHub release and place it under the cache path from `swain_cli doctor`.
- **Missing generators** — run `swain_cli list-generators --engine system` to validate your local Java installation or after updating the JAR with `engine update-jar`.
- **Cache cleanup** — delete the directory printed by `swain_cli doctor` to force a clean fetch of the runtime and JAR.
- **OutOfMemoryError** — the CLI already retries with a larger heap. For massive specs raise the ceiling with repeatable `--java-opt -Xmx16g` or set `SWAIN_CLI_JAVA_OPTS`.

## Contributing
1. Create a virtual environment (`python -m venv .venv`) and activate it.
2. Install the project with dev extras: `pip install -e .[dev]`.
3. Run the CLI locally via `python -m swain_cli.cli --help` or the `swain_cli` entry point.
4. Add or update tests and run `python -m pytest`.

## Maintainers
- Trigger the `build-jre` workflow (workflow dispatch) to build trimmed JRE archives for Linux (x86_64 + arm64), macOS (Intel + Apple Silicon), and Windows. Provide an optional `release_tag` to publish directly to a `jre-<version>` release.
- Copy the resulting `.sha256` values into `swain_cli/cli.py` so downloads can be verified, and update `ASSET_BASE` if you move assets to a new release tag.
- Tag releases (`git tag vX.Y.Z`) once assets are ready. The full release runbook lives in `docs/RELEASING.md`.

## Third-party notices
- OpenAPI Generator (Apache 2.0)
- Eclipse Temurin OpenJDK (GPLv2 with Classpath Exception)

## License
swain_cli is released under the Apache 2.0 license. See `LICENSE` for details.
