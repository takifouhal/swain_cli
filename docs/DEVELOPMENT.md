# Development

This document is a lightweight checklist for keeping `swain_cli` easy to change without breaking releases.

## Done looks like
- `python -m pytest` is green.
- `python -m mypy swain_cli` is green.
- `ruff check .` is green.
- `python -m build` is green (sanity-check packaging; install with `python -m pip install build`).

## One-command checks
- macOS/Linux: `./scripts/check.sh` (set `PYTHON=python3` when you need a specific interpreter)
- Windows: `powershell -File scripts/check.ps1`

Note: the `lint` extra only installs `ruff`/`mypy` on Python 3.9+.

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

## Target state (convergence checklist)
- Keep business logic testable: extract pure helpers and prefer dependency injection at module boundaries.
- Prefer status-code checks over string matching for HTTP fallbacks (e.g., 404 proxy vs platform routes).
- Centralize shared IO patterns (e.g., writing downloaded schemas to temp files) to keep error handling consistent.
- Bound memory use when streaming subprocess output; the CLI should print full output but only retain a small tail for retries.
- Keep docs in sync with code: update this file when module boundaries or invariants change.
