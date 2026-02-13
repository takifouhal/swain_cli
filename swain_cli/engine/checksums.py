"""Checksum helpers shared by JRE + generator jar management."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Optional

from ..errors import CLIError


def parse_checksum_file(path: Path) -> str:
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        raise CLIError(f"unable to read checksum file {path}: {exc}") from exc

    # Accept common formats:
    #  - "<hex>  filename" (GNU coreutils shasum/sha256sum)
    #  - "SHA256 (filename) = <hex>" (BSD shasum)
    #  - PowerShell Get-FileHash table output (second line contains algo, hash, path)
    #  - a bare 64-hex digest
    hex_pattern = re.compile(r"\b([A-Fa-f0-9]{64})\b")
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        match = hex_pattern.search(line)
        if match:
            return match.group(1).lower()
    raise CLIError(f"checksum file {path} did not contain a SHA-256 value")


def _sha256_digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _verify_sha256(path: Path, expected: Optional[str]) -> None:
    if not expected:
        return
    digest = _sha256_digest(path)
    if digest.lower() != expected.lower():
        raise CLIError(
            f"SHA-256 mismatch for {path.name}; expected {expected}, got {digest}"
        )


def _digest(path: Path, algorithm: str) -> str:
    algo = (algorithm or "").lower().strip()
    if algo not in {"sha256", "sha512"}:
        raise CLIError(f"unsupported checksum algorithm: {algorithm}")
    hasher = hashlib.new(algo)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _verify_digest(path: Path, algorithm: str, expected: Optional[str]) -> None:
    if not expected:
        return
    digest = _digest(path, algorithm)
    if digest.lower() != expected.lower():
        raise CLIError(
            f"{algorithm.upper()} mismatch for {path.name}; expected {expected}, got {digest}"
        )


def _parse_checksum_text(text: str, algorithm: str) -> str:
    algo = (algorithm or "").lower().strip()
    if algo == "sha256":
        pattern = re.compile(r"\b([A-Fa-f0-9]{64})\b")
    elif algo == "sha512":
        pattern = re.compile(r"\b([A-Fa-f0-9]{128})\b")
    else:
        raise CLIError(f"unsupported checksum algorithm: {algorithm}")
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        match = pattern.search(line)
        if match:
            return match.group(1).lower()
    raise CLIError(f"checksum text did not contain a valid {algo} digest")
