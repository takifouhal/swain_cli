#!/usr/bin/env bash
set -euo pipefail

# Install swain_cli as a single, self-contained binary (no Python required).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/takifouhal/swain_cli/HEAD/scripts/install.sh | bash
#   # (or, once published as a release asset)
#   # curl -fsSL https://github.com/takifouhal/swain_cli/releases/latest/download/install.sh | bash
# Optional:
#   INSTALL_DIR=/usr/local/bin VERSION=vX.Y.Z SWAIN_CLI_INSTALL_REQUIRE_CHECKSUM=1 bash install.sh

REPO="takifouhal/swain_cli"
INSTALL_DIR_DEFAULT="/usr/local/bin"
INSTALL_DIR="${INSTALL_DIR:-}"
DEFAULT_VERSION="latest"
VERSION="${VERSION:-${DEFAULT_VERSION}}"
REQUIRE_CHECKSUM="${SWAIN_CLI_INSTALL_REQUIRE_CHECKSUM:-0}"

sha256_file() {
  local file="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print $2}'
    return
  fi
  echo "No SHA-256 tool found (need shasum/sha256sum/openssl)" >&2
  return 1
}

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
checksum_tmp=$(mktemp)
trap 'rm -f "${tmpfile}" "${checksum_tmp}"' EXIT

if ! curl -fL "${download_url}" -o "${tmpfile}"; then
  if [[ "${VERSION}" == "latest" ]]; then
    # Fallback to the latest release redirect endpoint
    download_url="https://github.com/${REPO}/releases/latest/download/${asset_name}"
    echo "Retrying with latest release asset..."
    curl -fL "${download_url}" -o "${tmpfile}"
  else
    echo "Failed to download ${download_url}" >&2
    exit 1
  fi
fi

checksum_url="${download_url}.sha256"
if curl -fL "${checksum_url}" -o "${checksum_tmp}"; then
  expected_sha=$(awk '{for (i=1;i<=NF;i++) if ($i ~ /^[A-Fa-f0-9]{64}$/) {print $i; exit}}' "${checksum_tmp}" | tr '[:upper:]' '[:lower:]')
  if [[ -z "${expected_sha}" ]]; then
    echo "Invalid checksum file (no SHA-256 found): ${checksum_url}" >&2
    exit 1
  fi
  actual_sha=$(sha256_file "${tmpfile}" | tr '[:upper:]' '[:lower:]')
  if [[ -z "${actual_sha}" ]]; then
    echo "Unable to compute SHA-256 for downloaded binary" >&2
    exit 1
  fi
  if [[ "${expected_sha}" != "${actual_sha}" ]]; then
    echo "Checksum mismatch for ${asset_name}: expected ${expected_sha}, got ${actual_sha}" >&2
    exit 1
  fi
  echo "Checksum verified (${expected_sha})"
else
  if [[ "${REQUIRE_CHECKSUM}" == "1" ]]; then
    echo "Checksum file missing (set SWAIN_CLI_INSTALL_REQUIRE_CHECKSUM=0 to bypass): ${checksum_url}" >&2
    exit 1
  fi
  echo "WARNING: checksum file not found; skipping verification (${checksum_url})" >&2
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
