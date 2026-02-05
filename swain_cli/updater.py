"""Self-update helpers for binary installs."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

from .console import log
from .engine import HTTPX_DOWNLOADER, get_platform_info
from .errors import CLIError
from .signatures import verify_gpg_signature

GITHUB_REPO = "takifouhal/swain_cli"


@dataclass(frozen=True)
class UpdateAsset:
    tag: str
    asset_name: str
    asset_url: str
    checksum_url: str
    signature_url: str


def _is_frozen_binary() -> bool:
    return bool(getattr(sys, "frozen", False))


def _normalize_tag(value: str) -> str:
    raw = (value or "").strip()
    if not raw or raw.lower() == "latest":
        return "latest"
    return raw if raw.startswith("v") else f"v{raw}"


def _asset_name() -> str:
    info = get_platform_info()
    os_name = info.os_name
    arch = info.arch
    if os_name == "windows" and arch == "arm64":
        log("windows arm64 detected; using x86_64 binary under emulation")
        arch = "x86_64"
    suffix = ".exe" if os_name == "windows" else ""
    return f"swain_cli-{os_name}-{arch}{suffix}"


def _release_base(tag: str) -> str:
    if tag == "latest":
        return f"https://github.com/{GITHUB_REPO}/releases/latest/download"
    return f"https://github.com/{GITHUB_REPO}/releases/download/{tag}"


def build_update_asset(tag: str) -> UpdateAsset:
    normalized = _normalize_tag(tag)
    asset = _asset_name()
    base = _release_base(normalized)
    return UpdateAsset(
        tag=normalized,
        asset_name=asset,
        asset_url=f"{base}/{asset}",
        checksum_url=f"{base}/{asset}.sha256",
        signature_url=f"{base}/{asset}.asc",
    )


_HEX_PATTERN = re.compile(r"\b([A-Fa-f0-9]{64})\b")


def _parse_sha256_text(text: str) -> str:
    for raw in (text or "").splitlines():
        match = _HEX_PATTERN.search(raw)
        if match:
            return match.group(1).lower()
    raise CLIError("checksum file did not contain a SHA-256 digest")


def _sha256_digest(path: Path) -> str:
    import hashlib

    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _download_file(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    HTTPX_DOWNLOADER(url, str(dest), None, progressbar=True)


def _download_text(url: str) -> str:
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as handle:
        tmp = Path(handle.name)
    try:
        HTTPX_DOWNLOADER(url, str(tmp), None, progressbar=False)
        return tmp.read_text(encoding="utf-8", errors="replace")
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def _verify_sha256(path: Path, expected: str) -> None:
    digest = _sha256_digest(path)
    if digest.lower() != expected.lower():
        raise CLIError(
            f"SHA-256 mismatch for {path.name}; expected {expected}, got {digest}"
        )


def _replace_unix(executable: Path, new_binary: Path) -> None:
    try:
        mode = executable.stat().st_mode
    except OSError:
        mode = None
    if mode is not None:
        try:
            os.chmod(new_binary, mode)
        except OSError:
            pass
    os.replace(new_binary, executable)


def _replace_windows(executable: Path, new_binary: Path) -> None:
    pid = os.getpid()
    script_path = executable.with_name(f".swain_cli_self_update_{pid}.cmd")
    script_path.write_text(
        "\r\n".join(
            [
                "@echo off",
                "setlocal enabledelayedexpansion",
                f"set \"exe={executable}\"",
                f"set \"new={new_binary}\"",
                f"set \"pid={pid}\"",
                ":waitloop",
                "tasklist /FI \"PID eq %pid%\" | find \"%pid%\" >nul",
                "if %errorlevel%==0 (",
                "  timeout /t 1 /nobreak >nul",
                "  goto waitloop",
                ")",
                "move /Y \"%new%\" \"%exe%\" >nul",
                "set exitcode=%errorlevel%",
                "del \"%~f0\" >nul 2>&1",
                "exit /b %exitcode%",
            ]
        )
        + "\r\n",
        encoding="utf-8",
    )
    try:
        subprocess.Popen(
            ["cmd", "/c", str(script_path)],
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,  # type: ignore[attr-defined]
            close_fds=True,
        )
    except OSError as exc:
        raise CLIError(f"failed to spawn updater script: {exc}") from exc


def self_update(
    *,
    tag: str,
    verify: bool,
    verify_signatures: bool,
    dry_run: bool,
) -> Path:
    if not _is_frozen_binary():
        raise CLIError("self-update is only supported for binary installs (PyInstaller)")

    executable = Path(sys.executable).resolve()
    asset = build_update_asset(tag)
    log(f"self-update target: {asset.asset_name} ({asset.tag})")
    log(f"download: {asset.asset_url}")

    with tempfile.NamedTemporaryFile(
        prefix="swain_cli_update_",
        dir=str(executable.parent),
        delete=False,
    ) as handle:
        staging = Path(handle.name)
    try:
        _download_file(asset.asset_url, staging)

        signature_path: Optional[Path] = None
        if verify_signatures:
            with tempfile.NamedTemporaryFile(
                prefix="swain_cli_update_sig_",
                dir=str(executable.parent),
                delete=False,
                suffix=".asc",
            ) as handle:
                signature_path = Path(handle.name)
            _download_file(asset.signature_url, signature_path)
            verify_gpg_signature(staging, signature_path)
            log("signature verified")

        expected = ""
        if verify:
            checksum_text = _download_text(asset.checksum_url)
            expected = _parse_sha256_text(checksum_text)
            _verify_sha256(staging, expected)
            log(f"checksum verified: {expected}")
        else:
            log("checksum verification disabled")

        if dry_run:
            log("dry-run enabled; not replacing executable")
            return staging

        if os.name == "nt":
            replacement = executable.with_suffix(executable.suffix + ".new")
            if replacement.exists():
                replacement.unlink(missing_ok=True)
            os.replace(staging, replacement)
            log(f"staged update at {replacement}")
            _replace_windows(executable, replacement)
            log("update scheduled; restart swain_cli to use the new version")
            return executable

        _replace_unix(executable, staging)
        log(f"updated {executable}")
        return executable
    finally:
        # Best-effort cleanup of signature temp file.
        try:
            if "signature_path" in locals() and signature_path:
                signature_path.unlink(missing_ok=True)
        except Exception:
            pass
        if staging.exists() and dry_run:
            # Preserve staging file for inspection in dry-run mode.
            pass
        elif staging.exists() and not dry_run and os.name != "nt":
            # On Unix we replace in-place, so staging path no longer exists.
            pass
        elif staging.exists() and not dry_run and os.name == "nt":
            # Staging file was moved to .new.
            pass


def handle_self_update(args: SimpleNamespace) -> int:
    tag = getattr(args, "version", None) or "latest"
    verify = not bool(getattr(args, "no_verify", False))
    dry_run = bool(getattr(args, "dry_run", False))
    verify_signatures = bool(getattr(args, "verify_signatures", False))
    try:
        self_update(
            tag=tag,
            verify=verify,
            verify_signatures=verify_signatures,
            dry_run=dry_run,
        )
    except CLIError:
        raise
    except Exception as exc:
        raise CLIError(f"self-update failed: {exc}") from exc
    return 0
