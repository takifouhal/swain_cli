#!/usr/bin/env python3
"""Update Homebrew formula version + checksums for a GitHub release."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Dict, Tuple

import httpx

ASSET_NAMES: Dict[Tuple[str, str], str] = {
    ("macos", "arm64"): "swain_cli-macos-arm64",
    ("macos", "x86_64"): "swain_cli-macos-x86_64",
    ("linux", "arm64"): "swain_cli-linux-arm64",
    ("linux", "x86_64"): "swain_cli-linux-x86_64",
}


def normalize_tag(version: str) -> Tuple[str, str]:
    raw = (version or "").strip()
    if not raw:
        raise SystemExit("version is required (e.g. 0.3.14 or v0.3.14)")
    if raw.startswith("v"):
        return raw, raw[1:]
    return f"v{raw}", raw


def fetch_sha256(repo: str, tag: str, asset: str) -> str:
    url = f"{repo}/releases/download/{tag}/{asset}.sha256"
    with httpx.Client(follow_redirects=True, timeout=30.0) as client:
        resp = client.get(url)
        resp.raise_for_status()
        text = resp.text
    match = re.search(r"\b([a-fA-F0-9]{64})\b", text)
    if not match:
        raise SystemExit(f"failed to parse sha256 for {asset} from {url}")
    return match.group(1).lower()


def update_formula(text: str, *, repo: str, tag: str, version: str, checksums: Dict[str, str]) -> str:
    updated = re.sub(
        r'(?m)^(\s*version\s+")([^"]+)(")',
        rf'\g<1>{version}\3',
        text,
        count=1,
    )

    for asset, sha in checksums.items():
        asset_url = f"{repo}/releases/download/{tag}/{asset}"
        pattern = re.compile(
            rf'(?m)^(?P<indent>\s*)url\s+"[^"]+/{re.escape(asset)}"\s*\n(?P=indent)sha256\s+"[^"]+"'
        )
        replacement = rf'\g<indent>url "{asset_url}"' + "\n" + rf'\g<indent>sha256 "{sha}"'
        new, count = pattern.subn(replacement, updated, count=1)
        if count != 1:
            raise SystemExit(f"failed to locate url/sha256 block for {asset} in Formula/swain_cli.rb")
        updated = new
    return updated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="release version, e.g. 0.3.14 or v0.3.14")
    parser.add_argument(
        "--repo",
        default="https://github.com/takifouhal/swain_cli",
        help="GitHub repository base URL",
    )
    parser.add_argument(
        "--formula",
        default="Formula/swain_cli.rb",
        help="path to the Homebrew formula file",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="write changes to disk (default: print to stdout)",
    )
    args = parser.parse_args()

    tag, version = normalize_tag(args.version)

    checksums: Dict[str, str] = {}
    for _key, asset in ASSET_NAMES.items():
        checksums[asset] = fetch_sha256(args.repo, tag, asset)

    formula_path = Path(args.formula)
    original = formula_path.read_text(encoding="utf-8")
    updated = update_formula(
        original,
        repo=args.repo,
        tag=tag,
        version=version,
        checksums=checksums,
    )

    if args.write:
        formula_path.write_text(updated, encoding="utf-8")
    else:
        print(updated, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

