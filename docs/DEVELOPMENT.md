# Development

This document is a lightweight checklist for keeping `swain_cli` easy to change without breaking releases.

## Done looks like
- `python -m pytest` is green.
- `python -m mypy swain_cli` is green.
- `ruff check .` is green.

## One-command checks
- macOS/Linux: `./scripts/check.sh`
- Windows: `powershell -File scripts/check.ps1`

## Non-goals (for refactors)
- No CLI behavior changes unless explicitly called out.
- No network calls in unit tests (patch `httpx.Client`).

## Module boundaries (high level)
- `swain_cli/cli.py`: Typer commands + wiring (no prompt/HTTP details).
- `swain_cli/interactive.py`: interactive wizard UX (no HTTP details).
- `swain_cli/args.py`: typed argument models shared across modules.
- `swain_cli/generator.py`: orchestrates schema resolution + OpenAPI Generator invocation.
- `swain_cli/engine.py`: embedded JRE/JAR management + subprocess execution.
- `swain_cli/auth.py`: credential login + token storage (env/keyring) + tenant ID resolution.
- `swain_cli/swain_api.py`: Swain project/connection discovery over HTTP.
- `swain_cli/crudsql.py`: CrudSQL schema discovery + downloads over HTTP.
- `swain_cli/urls.py`: URL normalization + endpoint building.
- `swain_cli/http.py`: shared HTTP helpers (headers, error formatting).
