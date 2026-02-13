"""OpenAPI Generator jar management (download, verify, cache)."""

from __future__ import annotations

import os
from functools import partial
from pathlib import Path
from typing import List, Optional, Tuple

import pooch

from ..constants import (
    GENERATOR_VERSION_ENV_VAR,
    PINNED_GENERATOR_SHA256,
    PINNED_GENERATOR_VERSION,
)
from ..errors import CLIError
from ..signatures import verify_gpg_signature
from .checksums import _parse_checksum_text, _verify_digest
from .core import (
    _signature_verification_enabled,
    cache_lock,
    downloads_dir,
    jar_cache_dir,
)
from .downloads import HTTPX_DOWNLOADER


def fetch_maven_checksum(version: str) -> Tuple[str, str]:
    jar_name = f"openapi-generator-cli-{version}.jar"
    base_url = (
        "https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/"
        f"{version}/{jar_name}"
    )
    downloads = downloads_dir()
    for algorithm in ("sha512", "sha256"):
        suffix = f".{algorithm}"
        url = f"{base_url}{suffix}"
        filename = f"{jar_name}{suffix}"
        try:
            checksum_path = Path(
                pooch.retrieve(
                    url=url,
                    path=downloads,
                    fname=filename,
                    known_hash=None,
                    downloader=HTTPX_DOWNLOADER,
                )
            )
        except Exception:
            continue
        try:
            content = checksum_path.read_text(encoding="utf-8")
        except OSError:
            continue
        try:
            digest = _parse_checksum_text(content, algorithm)
        except CLIError:
            continue
        return algorithm, digest
    raise CLIError(
        f"unable to fetch checksum for OpenAPI Generator {version} from Maven Central; "
        "re-run with --no-verify to bypass verification"
    )


def resolve_generator_jar(version: Optional[str], *, allow_download: bool = True) -> Path:
    chosen = version or os.environ.get(GENERATOR_VERSION_ENV_VAR)
    if not chosen:
        chosen = PINNED_GENERATOR_VERSION
    jar_path = jar_cache_dir(create=False) / chosen / f"openapi-generator-cli-{chosen}.jar"
    if jar_path.exists():
        return jar_path
    if chosen == PINNED_GENERATOR_VERSION:
        if allow_download:
            return ensure_generator_jar(PINNED_GENERATOR_VERSION)
        raise CLIError(
            "OpenAPI Generator jar missing; run"
            f" 'swain_cli engine update-jar --version {PINNED_GENERATOR_VERSION}'"
        )
    raise CLIError(
        f"OpenAPI Generator {chosen} is not cached; run 'swain_cli engine update-jar --version {chosen}'"
    )


def ensure_generator_jar(version: str, *, verify: bool = True) -> Path:
    with cache_lock():
        jar_path = jar_cache_dir() / version / f"openapi-generator-cli-{version}.jar"
        jar_path.parent.mkdir(parents=True, exist_ok=True)
        expected_algo: Optional[str] = None
        expected_digest: Optional[str] = None

        if version == PINNED_GENERATOR_VERSION:
            expected_algo = "sha256"
            expected_digest = PINNED_GENERATOR_SHA256
        elif verify:
            expected_algo, expected_digest = fetch_maven_checksum(version)

        url = (
            "https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/"
            f"{version}/openapi-generator-cli-{version}.jar"
        )

        def verify_signature(path: Path) -> None:
            if not verify:
                return
            if not _signature_verification_enabled():
                return

            signature_name = f"{jar_path.name}.asc"
            signature_url = f"{url}.asc"
            downloads = downloads_dir()
            try:
                signature_path = Path(
                    pooch.retrieve(
                        url=signature_url,
                        path=downloads,
                        fname=signature_name,
                        known_hash=None,
                        downloader=HTTPX_DOWNLOADER,
                    )
                )
            except Exception as exc:
                raise CLIError(
                    f"signature verification enabled but failed to download {signature_name}: {exc}"
                ) from exc
            verify_gpg_signature(path, signature_path)

        if jar_path.exists():
            if verify and expected_algo and expected_digest:
                _verify_digest(jar_path, expected_algo, expected_digest)
            verify_signature(jar_path)
            return jar_path

        known_hash = None
        if verify and expected_algo and expected_digest:
            known_hash = f"{expected_algo}:{expected_digest}"
        target = Path(
            pooch.retrieve(
                url=url,
                path=jar_path.parent,
                fname=jar_path.name,
                known_hash=known_hash,
                downloader=partial(HTTPX_DOWNLOADER, progressbar=True),
            )
        )
        if verify and expected_algo and expected_digest:
            _verify_digest(target, expected_algo, expected_digest)
        verify_signature(target)
        return target


def list_cached_jars() -> List[str]:
    base = jar_cache_dir(create=False)
    if not base.exists():
        return []
    entries: List[str] = []
    for version_dir in sorted(base.iterdir()):
        if not version_dir.is_dir():
            continue
        jar = version_dir / f"openapi-generator-cli-{version_dir.name}.jar"
        if jar.exists():
            entries.append(f"{version_dir.name} -> {jar}")
    return entries
