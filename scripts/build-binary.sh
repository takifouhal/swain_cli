#!/usr/bin/env bash
set -euo pipefail

# Build a one-file swain_cli binary using PyInstaller.
# Requires Python 3.8+ and pyinstaller installed in the current environment.

if ! command -v pyinstaller >/dev/null 2>&1; then
  echo "pyinstaller is required. Install with: python -m pip install pyinstaller" >&2
  exit 1
fi

pyinstaller -n swain_cli --onefile swain_cli/cli.py

echo "Built binary at dist/swain_cli$( [[ $(uname -s | tr '[:upper:]' '[:lower:]') =~ msys|mingw|cygwin ]] && echo '.exe' )"

