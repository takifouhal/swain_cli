$ErrorActionPreference = "Stop"

Write-Host "==> ruff"
python -m ruff check .

Write-Host "==> mypy"
python -m mypy swain_cli

Write-Host "==> pytest"
python -m pytest
