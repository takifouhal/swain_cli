#!/usr/bin/env bash
set -euo pipefail

# Install swain_cli as a single, self-contained binary (no Python required).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/takifouhal/swain_cli/HEAD/scripts/install.sh | bash
# Optional:
#   INSTALL_DIR=/usr/local/bin VERSION=v0.3.6 bash install.sh

REPO="takifouhal/swain_cli"
INSTALL_DIR_DEFAULT="/usr/local/bin"
INSTALL_DIR="${INSTALL_DIR:-}"
VERSION="${VERSION:-latest}"

if [[ -z "${INSTALL_DIR}" ]]; then
  if [[ -w "${INSTALL_DIR_DEFAULT}" ]]; then
    INSTALL_DIR="${INSTALL_DIR_DEFAULT}"
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi

mkdir -p "${INSTALL_DIR}"

uname_s=$(uname -s | tr '[:upper:]' '[:lower:]')
uname_m=$(uname -m)

case "${uname_s}" in
  linux)  os="linux";;
  darwin) os="macos";;
  msys*|cygwin*|mingw*)
    echo "This script targets Unix shells. On Windows, use scripts/install.ps1" >&2
    exit 1
    ;;
  *)
    echo "Unsupported OS: ${uname_s}" >&2
    exit 1
    ;;
esac

case "${uname_m}" in
  x86_64|amd64) arch="x86_64";;
  arm64|aarch64) arch="arm64";;
  *)
    echo "Unsupported architecture: ${uname_m}" >&2
    exit 1
    ;;
esac

asset_name="swain_cli-${os}-${arch}"
download_url="https://github.com/${REPO}/releases/download/${VERSION}/${asset_name}"

echo "Installing swain_cli -> ${INSTALL_DIR}/${asset_name##*/}"
tmpfile=$(mktemp)
trap 'rm -f "${tmpfile}"' EXIT

if ! curl -fL "${download_url}" -o "${tmpfile}"; then
  if [[ "${VERSION}" == "latest" ]]; then
    # Fallback to the latest release redirect endpoint
    download_url="https://github.com/${REPO}/releases/latest/download/${asset_name}"
    echo "Retrying with latest release asset..."
    if ! curl -fL "${download_url}" -o "${tmpfile}"; then
      # Fallback to legacy generic names used by earlier releases
      legacy_name="swain_cli"
      echo "Falling back to legacy asset name: ${legacy_name}"
      legacy_url="https://github.com/${REPO}/releases/latest/download/${legacy_name}"
      curl -fL "${legacy_url}" -o "${tmpfile}"
    fi
  else
    echo "Failed to download ${download_url}" >&2
    exit 1
  fi
fi

chmod +x "${tmpfile}"
target="${INSTALL_DIR}/swain_cli"
mv "${tmpfile}" "${target}"

echo "Installed ${target}"
case :$PATH: in
  *:"${INSTALL_DIR}":*) :;;
  *)
    echo "WARNING: ${INSTALL_DIR} is not on your PATH." >&2
    echo "Add it (e.g., export PATH=\"${INSTALL_DIR}:\$PATH\") or move swain_cli to a directory on PATH." >&2
    ;;
esac

echo "Done. Run: swain_cli --help"
