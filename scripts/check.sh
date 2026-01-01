#!/usr/bin/env bash
set -euo pipefail

python_bin="${PYTHON:-python3}"
if ! command -v "${python_bin}" >/dev/null 2>&1; then
  python_bin="python"
fi

if ! command -v ruff >/dev/null 2>&1; then
  echo "ruff not found; install dev deps with: ${python_bin} -m pip install -e '.[dev,lint]'" >&2
  exit 1
fi

echo "==> ruff"
ruff check .

echo "==> mypy"
"${python_bin}" -m mypy swain_cli

echo "==> pytest"
"${python_bin}" -m pytest

