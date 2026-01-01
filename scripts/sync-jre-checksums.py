#!/usr/bin/env python3
"""Sync embedded JRE checksums in `swain_cli/constants.py`.

Usage:
  python scripts/sync-jre-checksums.py combined-checksums.txt
  python scripts/sync-jre-checksums.py combined-checksums.txt --write
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from swain_cli.constants import JRE_ASSETS

HEX_RE = re.compile(r"\b([A-Fa-f0-9]{64})\b")
BSD_RE = re.compile(r"SHA256\s*\(([^)]+)\)")


def _parse_combined_checksums(path: Path) -> Dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SystemExit(f"error: unable to read {path}: {exc}") from exc

    parsed: Dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        match = HEX_RE.search(line)
        if not match:
            continue
        digest = match.group(1).lower()

        filename: Optional[str] = None
        bsd = BSD_RE.search(line)
        if bsd:
            filename = bsd.group(1).strip()
        else:
            remainder = line[match.end() :].strip() if line.startswith(match.group(1)) else ""
            if remainder.startswith("*"):
                remainder = remainder[1:].lstrip()
            if remainder:
                filename = remainder.split()[0]

        if filename:
            parsed[filename] = digest

    return parsed


def _constants_path() -> Path:
    return Path(__file__).resolve().parents[1] / "swain_cli" / "constants.py"


def _update_constants_file(constants_path: Path, updates: Dict[str, str]) -> None:
    try:
        content = constants_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"error: unable to read {constants_path}: {exc}") from exc

    missing: List[str] = []
    for filename, digest in updates.items():
        pattern = re.compile(
            r'(JREAsset\(\s*\n\s*"'
            + re.escape(filename)
            + r'"\s*,\s*\n\s*")([A-Fa-f0-9]{64})(")',
            re.MULTILINE,
        )
        content, count = pattern.subn(rf"\1{digest}\3", content)
        if count == 0:
            missing.append(filename)

    if missing:
        formatted = "\n".join(f"- {name}" for name in missing)
        raise SystemExit(
            f"error: failed to locate JREAsset entries for:\n{formatted}\n"
            f"in {constants_path}"
        )

    try:
        constants_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"error: unable to write {constants_path}: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sync JRE_ASSETS checksums using a combined-checksums.txt file."
    )
    parser.add_argument("checksums_file", type=Path, help="Path to combined-checksums.txt")
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write updated checksums into swain_cli/constants.py",
    )
    args = parser.parse_args()

    parsed = _parse_combined_checksums(args.checksums_file)
    expected: Dict[str, Tuple[Tuple[str, str], str]] = {}
    for key, asset in JRE_ASSETS.items():
        expected[asset.filename] = (key, asset.sha256 or "")

    missing_files: List[str] = []
    mismatches: List[Tuple[Tuple[str, str], str, str, str]] = []
    updates: Dict[str, str] = {}

    for filename, (key, current_sha) in expected.items():
        observed = parsed.get(filename)
        if not observed:
            missing_files.append(filename)
            continue
        if current_sha.lower() != observed.lower():
            mismatches.append((key, filename, current_sha, observed))
        updates[filename] = observed

    if missing_files:
        formatted = "\n".join(f"- {name}" for name in missing_files)
        raise SystemExit(f"error: missing checksums for:\n{formatted}")

    if not mismatches:
        print("ok: JRE_ASSETS checksums already match")
        return 0

    print("checksum mismatches detected:")
    for key, filename, current_sha, observed in mismatches:
        print(f"- {key} {filename}: constants={current_sha} file={observed}")

    if not args.write:
        print("\nrerun with --write to update swain_cli/constants.py")
        return 1

    constants_path = _constants_path()
    _update_constants_file(constants_path, updates)
    print(f"\nupdated {constants_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
