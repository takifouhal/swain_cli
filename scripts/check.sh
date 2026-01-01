#!/usr/bin/env bash
set -euo pipefail

python_bin="${PYTHON:-python}"
if ! command -v "${python_bin}" >/dev/null 2>&1; then
  python_bin="python3"
fi
if ! command -v "${python_bin}" >/dev/null 2>&1; then
  echo "python not found; set PYTHON=/path/to/python" >&2
  exit 1
fi

install_hint="${python_bin} -m pip install -e '.[dev,lint]'"

python_version="$("${python_bin}" -c 'import sys; print(sys.version_info.major * 100 + sys.version_info.minor)')"

for module in ruff mypy pytest; do
  if ! "${python_bin}" -c "import ${module}" >/dev/null 2>&1; then
    note=""
    if [[ "${python_version}" -lt 309 && "${module}" != "pytest" ]]; then
      note=" (note: the lint toolchain requires Python 3.9+)"
    fi
    echo "${module} not found${note}; install dev deps with: ${install_hint}" >&2
    exit 1
  fi
done

echo "==> ruff"
"${python_bin}" -m ruff check .

echo "==> mypy"
"${python_bin}" -m mypy swain_cli

echo "==> pytest"
"${python_bin}" -m pytest
