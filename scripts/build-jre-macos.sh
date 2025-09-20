#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <temurin-jdk-tar.gz> <output-tar.gz>" >&2
  exit 1
fi

JDK_TAR=$1
OUTPUT=$2
WORKDIR=$(mktemp -d)
cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

mkdir -p "$WORKDIR/src" "$WORKDIR/out"
tar -xf "$JDK_TAR" -C "$WORKDIR/src"
JDK_DIR=$(find "$WORKDIR/src" -maxdepth 1 -type d -name 'jdk-*' -print -quit)
if [[ -z "$JDK_DIR" ]]; then
  echo "Could not locate extracted JDK directory" >&2
  exit 1
fi

"$JDK_DIR/Contents/Home/bin/jlink" \
  --compress=2 \
  --no-header-files \
  --no-man-pages \
  --strip-debug \
  --add-modules java.se,jdk.httpserver,jdk.unsupported \
  --output "$WORKDIR/out/jre"

tar -C "$WORKDIR/out" -czf "$OUTPUT" jre
if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$OUTPUT" | tee "$OUTPUT.sha256"
else
  sha256sum "$OUTPUT" | tee "$OUTPUT.sha256"
fi
