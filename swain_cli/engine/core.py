"""Engine core helpers (platform detection, env flags, cache paths/locks)."""

from __future__ import annotations

import os
import platform
import time
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional, Tuple

from platformdirs import PlatformDirs

from ..constants import (
    ASSET_BASE,
    ASSET_BASE_ENV_VAR,
    CACHE_ENV_VAR,
    DEFAULT_CACHE_DIR_NAME,
    VERIFY_SIGNATURES_ENV_VAR,
)
from ..errors import CLIError


@dataclass(frozen=True)
class PlatformInfo:
    os_name: str
    arch: str

    @property
    def key(self) -> Tuple[str, str]:
        return (self.os_name, self.arch)


def asset_base_url() -> str:
    return (os.environ.get(ASSET_BASE_ENV_VAR) or ASSET_BASE).rstrip("/")


def _env_truthy(name: str) -> bool:
    value = (os.environ.get(name) or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _signature_verification_enabled() -> bool:
    return _env_truthy(VERIFY_SIGNATURES_ENV_VAR)


@lru_cache()
def get_platform_info() -> PlatformInfo:
    system = normalize_os(platform.system())
    arch = normalize_arch(platform.machine())
    return PlatformInfo(system, arch)


def normalize_os(system: str) -> str:
    system_lower = system.lower()
    if system_lower == "darwin":
        return "macos"
    if system_lower == "windows":
        return "windows"
    if system_lower == "linux":
        return "linux"
    return system_lower


def normalize_arch(machine: str) -> str:
    value = machine.lower()
    if value in {"x86_64", "amd64"}:
        return "x86_64"
    if value in {"arm64", "aarch64"}:
        return "arm64"
    return value


def cache_root(*, create: bool = True) -> Path:
    explicit = os.environ.get(CACHE_ENV_VAR)
    if explicit:
        root = Path(explicit).expanduser()
    else:
        dirs = PlatformDirs(appname=DEFAULT_CACHE_DIR_NAME, appauthor=False, roaming=True)
        root = Path(dirs.user_cache_path)
    if create:
        root.mkdir(parents=True, exist_ok=True)
    return root


_CACHE_LOCK_FILENAME = ".swain_cli_cache.lock"


def cache_lock_path() -> Path:
    return cache_root(create=True) / _CACHE_LOCK_FILENAME


@contextmanager
def cache_lock(
    *,
    timeout_seconds: float = 60.0,
    stale_after_seconds: float = 60.0 * 60.0 * 2,
) -> Any:
    """Coarse lock for cache mutations (JRE + jar downloads/extraction)."""

    lock_path = cache_lock_path()
    started = time.monotonic()
    fd: Optional[int] = None
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            try:
                age = time.time() - lock_path.stat().st_mtime
            except FileNotFoundError:
                continue
            if age >= stale_after_seconds:
                try:
                    lock_path.unlink()
                except OSError:
                    pass
                continue
            if (time.monotonic() - started) >= timeout_seconds:
                raise CLIError(
                    f"timed out waiting for cache lock: {lock_path} "
                    f"(waited {timeout_seconds:.1f}s)"
                ) from None
            time.sleep(0.2)

    try:
        assert fd is not None
        payload = f"pid={os.getpid()} started={time.time():.0f}\n".encode("utf-8")
        try:
            os.write(fd, payload)
        except OSError:
            pass
        yield
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def jre_install_dir(*, create: bool = True) -> Path:
    info = get_platform_info()
    path = cache_root(create=create) / "jre" / f"{info.os_name}-{info.arch}"
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def jar_cache_dir(*, create: bool = True) -> Path:
    path = cache_root(create=create) / "jars"
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def downloads_dir(*, create: bool = True) -> Path:
    path = cache_root(create=create) / "downloads"
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path
