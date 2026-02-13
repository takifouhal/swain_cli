"""Embedded JRE asset management (download, verify, extract)."""

from __future__ import annotations

import platform
import shutil
from functools import partial
from pathlib import Path
from typing import Optional

import pooch

from ..console import log
from ..constants import JRE_ASSETS, JRE_MARKER_FILENAME, JREAsset
from ..errors import CLIError
from ..signatures import verify_gpg_signature
from .archives import extract_archive
from .checksums import _verify_sha256, parse_checksum_file
from .core import (
    _signature_verification_enabled,
    asset_base_url,
    cache_lock,
    downloads_dir,
    get_platform_info,
    jre_install_dir,
    normalize_os,
)
from .downloads import HTTPX_DOWNLOADER


def get_jre_asset() -> JREAsset:
    info = get_platform_info()
    asset = JRE_ASSETS.get(info.key)
    if not asset:
        if info.os_name == "windows" and info.arch == "arm64":
            fallback = JRE_ASSETS.get(("windows", "x86_64"))
            if fallback:
                log("windows arm64 detected; using x86_64 embedded JRE under emulation")
                return fallback
        raise CLIError(
            f"unsupported platform {info.os_name}/{info.arch}; install Java and use --engine system"
        )
    return asset


def checksum_filename(asset: JREAsset) -> str:
    return asset.checksum_filename or f"{asset.filename}.sha256"


def resolve_asset_sha256(asset: JREAsset) -> str:
    if asset.sha256:
        return asset.sha256
    filename = checksum_filename(asset)
    base = asset_base_url()
    downloads = downloads_dir()
    checksum_path = Path(
        pooch.retrieve(
            url=f"{base}/{filename}",
            path=downloads,
            fname=filename,
            known_hash=None,
            downloader=HTTPX_DOWNLOADER,
        )
    )
    return parse_checksum_file(checksum_path)


def fetch_asset_file(asset_name: str, sha256: Optional[str], force: bool = False) -> Path:
    downloads = downloads_dir()
    target = downloads / asset_name

    def verify_signature(path: Path) -> None:
        if not _signature_verification_enabled():
            return
        base = asset_base_url()
        signature_name = f"{asset_name}.asc"
        try:
            signature_path = Path(
                pooch.retrieve(
                    url=f"{base}/{signature_name}",
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

    if force and target.exists():
        target.unlink()
    if target.exists() and not force:
        try:
            _verify_sha256(target, sha256)
        except CLIError:
            target.unlink()
        else:
            verify_signature(target)
            return target

    known_hash = f"sha256:{sha256}" if sha256 else None
    base = asset_base_url()
    try:
        downloaded = Path(
            pooch.retrieve(
                url=f"{base}/{asset_name}",
                path=downloads,
                fname=asset_name,
                known_hash=known_hash,
                downloader=partial(HTTPX_DOWNLOADER, progressbar=True),
            )
        )
        verify_signature(downloaded)
        return downloaded
    except (CLIError, ValueError, OSError) as exc:
        raise CLIError(f"failed to download embedded JRE asset {asset_name}: {exc}") from exc


def read_jre_marker(runtime_dir: Path) -> Optional[str]:
    marker = runtime_dir / JRE_MARKER_FILENAME
    try:
        value = marker.read_text().strip()
    except FileNotFoundError:
        return None
    except OSError:
        return None
    return value or None


def write_jre_marker(runtime_dir: Path, sha256: str) -> None:
    marker = runtime_dir / JRE_MARKER_FILENAME
    try:
        marker.write_text(sha256.strip() + "\n")
    except OSError as exc:
        raise CLIError(f"failed to write embedded JRE marker file {marker}: {exc}") from exc


def normalize_runtime_dir(root: Path) -> None:
    java_path = root / "bin" / java_binary_name()
    if java_path.exists():
        return
    subdirs = [item for item in root.iterdir() if item.is_dir()]
    if len(subdirs) != 1:
        return
    inner = subdirs[0]
    inner_java = inner / "bin" / java_binary_name()
    if not inner_java.exists():
        return
    for item in inner.iterdir():
        shutil.move(str(item), root)
    shutil.rmtree(inner)


def java_binary_name() -> str:
    return "java.exe" if normalize_os(platform.system()) == "windows" else "java"


def find_embedded_java(root: Path) -> Optional[Path]:
    if not root.exists():
        return None
    candidate = root / "bin" / java_binary_name()
    if candidate.exists():
        return candidate
    for path in root.rglob(java_binary_name()):
        if path.name == java_binary_name() and path.parent.name == "bin":
            return path
    return None


def ensure_embedded_jre(force: bool = False) -> Path:
    with cache_lock():
        asset = get_jre_asset()
        expected_sha = resolve_asset_sha256(asset)
        target_dir = jre_install_dir()

        if not force:
            java_exec = find_embedded_java(target_dir)
            marker_value = read_jre_marker(target_dir)
            if java_exec and marker_value == expected_sha:
                return target_dir

        archive_path = fetch_asset_file(asset.filename, expected_sha, force=force)

        if target_dir.exists():
            shutil.rmtree(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        extract_archive(archive_path, target_dir)
        normalize_runtime_dir(target_dir)
        java_path = find_embedded_java(target_dir)
        if not java_path:
            raise CLIError(
                "embedded JRE installation did not produce a usable java executable"
            )
        write_jre_marker(target_dir, expected_sha)
        return target_dir
