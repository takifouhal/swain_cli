"""Embedded engine (JRE + OpenAPI Generator) management for swain_cli."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import textwrap
import time
import zipfile
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache, partial
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import httpx
import pooch
from platformdirs import PlatformDirs

from .console import log, log_error
from .constants import (
    ASSET_BASE,
    ASSET_BASE_ENV_VAR,
    CACHE_ENV_VAR,
    DEFAULT_CACHE_DIR_NAME,
    DEFAULT_JAVA_OPTS,
    ENGINE_ENV_VAR,
    EXIT_CODE_SUBPROCESS,
    GENERATOR_VERSION_ENV_VAR,
    HTTP_TIMEOUT_SECONDS,
    JAVA_OPTS_ENV_VAR,
    JRE_ASSETS,
    JRE_MARKER_FILENAME,
    PINNED_GENERATOR_SHA256,
    PINNED_GENERATOR_VERSION,
    VERIFY_SIGNATURES_ENV_VAR,
    JREAsset,
)
from .errors import CLIError
from .http import describe_http_error
from .signatures import verify_gpg_signature
from .utils import format_cli_command, redact


@dataclass(frozen=True)
class PlatformInfo:
    os_name: str
    arch: str

    @property
    def key(self) -> Tuple[str, str]:
        return (self.os_name, self.arch)


@dataclass
class EngineSnapshot:
    platform: PlatformInfo
    runtime_dir: Path
    embedded_java: Optional[Path]
    selected_generator: Optional[Path]
    selected_generator_error: Optional[str]
    cached_jars: List[str]
    system_java: Optional[str]


@dataclass(frozen=True)
class ResolvedJavaOptions:
    options: List[str]
    provided: bool


class HTTPXDownloader:
    """Pooch downloader that uses httpx for transfers."""

    def __init__(
        self,
        timeout: float,
        *,
        max_attempts: int = 5,
        backoff_initial: float = 0.5,
        backoff_max: float = 8.0,
        sleep: Callable[[float], None] = time.sleep,
        client_factory: Optional[Callable[[httpx.Timeout], httpx.Client]] = None,
    ) -> None:
        self.timeout = timeout
        self.max_attempts = max(1, int(max_attempts))
        self.backoff_initial = max(0.0, float(backoff_initial))
        self.backoff_max = max(self.backoff_initial, float(backoff_max))
        self.sleep = sleep
        self.client_factory = client_factory or self._default_client_factory

    def _default_client_factory(self, timeout: httpx.Timeout) -> httpx.Client:
        return httpx.Client(timeout=timeout, follow_redirects=True)

    def _retry_delay(self, attempt: int, exc: httpx.HTTPError) -> float:
        if isinstance(exc, httpx.HTTPStatusError):
            retry_after = exc.response.headers.get("Retry-After")
            if retry_after:
                try:
                    parsed = float(retry_after)
                except ValueError:
                    parsed = 0.0
                if parsed > 0:
                    return min(parsed, self.backoff_max)
        if attempt <= 0:
            return 0.0
        delay = self.backoff_initial * (2 ** (attempt - 1))
        return min(delay, self.backoff_max)

    def _should_retry(self, exc: httpx.HTTPError) -> bool:
        if isinstance(exc, httpx.TimeoutException):
            return True
        if isinstance(exc, httpx.RequestError):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code in {408, 429, 500, 502, 503, 504}
        return False

    def __call__(
        self,
        url: str,
        output_file: str,
        pooch_obj: pooch.Pooch,
        check_only: bool = False,
        progressbar: bool = False,
        **_: Any,
    ) -> None:
        _ = pooch_obj
        timeout = httpx.Timeout(self.timeout, connect=self.timeout)
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = Path(f"{output_file}.tmp")
        display_name = _download_name(url, output_path.name)

        attempt = 0
        while attempt < self.max_attempts:
            attempt += 1
            progress_enabled = bool(progressbar and sys.stderr.isatty() and not check_only)
            progress = _DownloadProgress(
                label=display_name,
                enabled=progress_enabled,
            )
            try:
                with self.client_factory(timeout) as client:
                    if check_only:
                        response = client.head(url)
                        response.raise_for_status()
                        return
                    try:
                        if tmp_path.exists():
                            tmp_path.unlink()
                    except OSError:
                        pass

                    with client.stream("GET", url) as response:
                        response.raise_for_status()
                        total_raw = response.headers.get("Content-Length")
                        if total_raw:
                            try:
                                total_value = int(total_raw)
                            except ValueError:
                                total_value = None
                        else:
                            total_value = None
                        progress.set_total(total_value)
                        with tmp_path.open("wb") as fh:
                            for chunk in response.iter_bytes(chunk_size=1024 * 64):
                                if not chunk:
                                    continue
                                fh.write(chunk)
                                progress.update(len(chunk))

                    progress.finish()
                    os.replace(tmp_path, output_file)
                    return
            except httpx.HTTPError as exc:
                progress.finish(success=False)
                try:
                    if tmp_path.exists():
                        tmp_path.unlink()
                except OSError:
                    pass

                retryable = self._should_retry(exc)
                if attempt >= self.max_attempts or not retryable:
                    detail = describe_http_error(exc)
                    hint = _download_error_hint(exc)
                    source = _download_source(url)
                    extra = f" Hint: {hint}" if hint else ""
                    raise CLIError(
                        f"download failed for {display_name} from {source} after {attempt} attempt(s): {detail}{extra}"
                    ) from exc

                delay = self._retry_delay(attempt, exc)
                detail = describe_http_error(exc)
                source = _download_source(url)
                log_error(
                    f"download error for {display_name} from {source}: {detail}; retrying in {delay:.1f}s"
                    f" ({attempt + 1}/{self.max_attempts})"
                )
                if delay > 0:
                    self.sleep(delay)
            except OSError as exc:
                progress.finish(success=False)
                raise CLIError(
                    f"failed to write download file {output_path}: {exc}"
                ) from exc


HTTPX_DOWNLOADER = HTTPXDownloader(timeout=HTTP_TIMEOUT_SECONDS)


def _format_bytes(value: float) -> str:
    if value < 0:
        value = 0
    units = ("B", "KB", "MB", "GB", "TB")
    unit_index = 0
    size = float(value)
    while size >= 1024 and unit_index + 1 < len(units):
        size /= 1024.0
        unit_index += 1
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    return f"{size:.1f} {units[unit_index]}"


def _download_source(url: str) -> str:
    try:
        parsed = httpx.URL(url)
    except Exception:
        return url
    if parsed.host:
        return str(parsed.host)
    return url


def _download_name(url: str, fallback: str) -> str:
    try:
        parsed = httpx.URL(url)
    except Exception:
        parsed = None
    if parsed is not None:
        candidate = Path(parsed.path).name
        if candidate:
            return candidate
    stripped = (url or "").split("?", 1)[0].rstrip("/")
    if "/" in stripped:
        candidate = stripped.rsplit("/", 1)[-1].strip()
        if candidate:
            return candidate
    return fallback


def _download_error_hint(exc: httpx.HTTPError) -> Optional[str]:
    if isinstance(exc, httpx.ProxyError):
        return "check HTTP_PROXY/HTTPS_PROXY/NO_PROXY environment variables"
    if isinstance(exc, httpx.TimeoutException):
        return "network timeout; try again or use a more reliable connection"
    if isinstance(exc, httpx.ConnectError):
        return "could not connect; check your internet/VPN/firewall"
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 429:
            return "rate limited; wait a bit and retry"
        if status >= 500:
            return "server error; try again later"
        if status == 404:
            return "resource not found; check the URL/version and try again"
    return None


class _DownloadProgress:
    def __init__(self, *, label: str, enabled: bool) -> None:
        self.label = label
        self.enabled = enabled
        self.total: Optional[int] = None
        self.downloaded = 0
        self.started_at = time.monotonic()
        self._last_render_at = 0.0
        self._last_line_len = 0
        if self.enabled:
            self._render(force=True)

    def set_total(self, total: Optional[int]) -> None:
        self.total = total if total and total > 0 else None
        self._render(force=True)

    def update(self, chunk_size: int) -> None:
        if chunk_size > 0:
            self.downloaded += chunk_size
        self._render()

    def finish(self, *, success: bool = True) -> None:
        if not self.enabled:
            return
        self._render(force=True, final=True)
        sys.stderr.write("\n")
        sys.stderr.flush()
        self._last_line_len = 0

    def _render(self, *, force: bool = False, final: bool = False) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        if not force and (now - self._last_render_at) < 0.1:
            return
        self._last_render_at = now

        elapsed = max(now - self.started_at, 0.001)
        speed = self.downloaded / elapsed
        speed_str = f"{_format_bytes(speed)}/s"
        downloaded_str = _format_bytes(self.downloaded)

        if self.total:
            total_str = _format_bytes(self.total)
            ratio = min(max(self.downloaded / max(self.total, 1), 0.0), 1.0)
            width = 24
            filled = int(ratio * width)
            bar = "#" * filled + "-" * (width - filled)
            percent = int(ratio * 100)
            suffix = f"{percent:3d}%"
            line = f"{self.label} [{bar}] {suffix} {downloaded_str}/{total_str} {speed_str}"
        else:
            line = f"{self.label} {downloaded_str} {speed_str}"

        if final and self.total and self.downloaded < self.total:
            line = f"{line} (incomplete)"

        pad = ""
        if len(line) < self._last_line_len:
            pad = " " * (self._last_line_len - len(line))
        self._last_line_len = len(line)
        sys.stderr.write(f"\r{line}{pad}")
        sys.stderr.flush()


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
def cache_lock(*, timeout_seconds: float = 60.0, stale_after_seconds: float = 60.0 * 60.0 * 2) -> Any:
    """
    Coarse lock for cache mutations (JRE + jar downloads/extraction).

    Uses an atomic create (O_EXCL). If a lock appears stale (mtime older than
    stale_after_seconds), it is removed.
    """
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
        raise CLIError(f"SHA-256 mismatch for {path.name}; expected {expected}, got {digest}")


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


def extract_archive(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)

    def normalize_member_path(member: str) -> str:
        normalized = (member or "").replace("\\", "/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        if not normalized:
            return ""
        if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
            raise CLIError(
                f"archive entry contains an absolute path: {member!r} ({archive.name})"
            )
        parts = [part for part in normalized.split("/") if part not in {"", "."}]
        if any(part == ".." for part in parts):
            raise CLIError(
                f"archive entry attempts path traversal: {member!r} ({archive.name})"
            )
        return "/".join(parts)

    def ensure_safe_parents(parts: List[str]) -> Path:
        current = dest
        for part in parts:
            current = current / part
            if current.exists():
                if current.is_symlink():
                    raise CLIError(
                        f"refusing to extract into symlinked directory {current} ({archive.name})"
                    )
                if not current.is_dir():
                    raise CLIError(
                        f"refusing to extract into non-directory {current} ({archive.name})"
                    )
                continue
            current.mkdir()
        return current

    def validate_within_dest(relative_posix: str) -> Path:
        rel_path = Path(*[p for p in relative_posix.split("/") if p])
        target = dest / rel_path
        dest_real = dest.resolve()
        try:
            target_real = target.resolve()
        except FileNotFoundError:
            # Resolve the parent that does exist (best-effort). Path traversal is
            # already prevented by normalize_member_path.
            target_real = (dest_real / rel_path)
        if dest_real != target_real and dest_real not in target_real.parents:
            raise CLIError(
                f"archive entry escapes destination: {relative_posix!r} ({archive.name})"
            )
        return target

    suffix = archive.name.lower()
    if suffix.endswith(".zip"):
        try:
            with zipfile.ZipFile(archive) as zf:
                for info in zf.infolist():
                    entry = normalize_member_path(info.filename)
                    if not entry:
                        continue
                    if info.is_dir() or info.filename.endswith("/"):
                        ensure_safe_parents(entry.split("/"))
                        continue
                    target = validate_within_dest(entry)
                    ensure_safe_parents(entry.split("/")[:-1])
                    if target.exists() and target.is_symlink():
                        raise CLIError(
                            f"refusing to overwrite symlink {target} ({archive.name})"
                        )
                    with zf.open(info, "r") as src, target.open("wb") as out:
                        shutil.copyfileobj(src, out)
                    mode = (info.external_attr >> 16) & 0o777
                    if mode:
                        try:
                            os.chmod(target, mode)
                        except OSError:
                            pass
            return
        except zipfile.BadZipFile as exc:
            raise CLIError(f"unsupported archive format for {archive.name}") from exc

    if any(suffix.endswith(ext) for ext in (".tar.gz", ".tgz", ".tar")):
        try:
            with tarfile.open(archive, mode="r:*") as tf:
                for member in tf.getmembers():
                    entry = normalize_member_path(member.name)
                    if not entry:
                        continue
                    target = validate_within_dest(entry)
                    parent_parts = entry.split("/")[:-1]
                    ensure_safe_parents(parent_parts)

                    if member.isdir():
                        ensure_safe_parents(entry.split("/"))
                        continue

                    if member.issym():
                        linkname = (member.linkname or "").replace("\\", "/").strip()
                        if not linkname:
                            continue
                        if linkname.startswith("/") or re.match(r"^[A-Za-z]:", linkname):
                            raise CLIError(
                                f"refusing to extract absolute symlink target {linkname!r} ({archive.name})"
                            )
                        combined = posixpath.normpath(
                            posixpath.join(posixpath.dirname(entry), linkname)
                        )
                        if combined.startswith("..") or combined == "..":
                            raise CLIError(
                                f"refusing to extract symlink escaping destination: {entry!r} -> {linkname!r} ({archive.name})"
                            )
                        if target.exists():
                            target.unlink()
                        try:
                            os.symlink(linkname, target)
                        except (NotImplementedError, OSError) as exc:
                            raise CLIError(
                                f"failed to create symlink for {entry!r}: {exc}"
                            ) from exc
                        continue

                    if member.islnk():
                        linkname = (member.linkname or "").replace("\\", "/").strip()
                        if not linkname:
                            continue
                        if linkname.startswith("/") or re.match(r"^[A-Za-z]:", linkname):
                            raise CLIError(
                                f"refusing to extract absolute hardlink target {linkname!r} ({archive.name})"
                            )
                        combined = posixpath.normpath(linkname)
                        if combined.startswith("..") or combined == "..":
                            raise CLIError(
                                f"refusing to extract hardlink escaping destination: {entry!r} -> {linkname!r} ({archive.name})"
                            )
                        source = validate_within_dest(combined)
                        if not source.exists():
                            raise CLIError(
                                f"hardlink target missing while extracting {entry!r} ({archive.name})"
                            )
                        if target.exists():
                            target.unlink()
                        try:
                            os.link(source, target)
                        except OSError as exc:
                            raise CLIError(
                                f"failed to create hardlink for {entry!r}: {exc}"
                            ) from exc
                        continue

                    if not member.isreg():
                        raise CLIError(
                            f"unsupported archive entry type for {entry!r} ({archive.name})"
                        )

                    if target.exists() and target.is_symlink():
                        raise CLIError(
                            f"refusing to overwrite symlink {target} ({archive.name})"
                        )
                    file_obj = tf.extractfile(member)
                    if file_obj is None:
                        continue
                    with file_obj as src, target.open("wb") as out:
                        shutil.copyfileobj(src, out)
                    if member.mode:
                        try:
                            os.chmod(target, member.mode & 0o777)
                        except OSError:
                            pass
            return
        except tarfile.TarError as exc:
            raise CLIError(f"unsupported archive format for {archive.name}") from exc

    raise CLIError(f"unsupported archive format for {archive.name}")


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


def resolve_generator_jar(version: Optional[str], *, allow_download: bool = True) -> Path:
    chosen = version or os.environ.get(GENERATOR_VERSION_ENV_VAR)
    if not chosen:
        chosen = PINNED_GENERATOR_VERSION
    jar_path = (
        jar_cache_dir(create=False)
        / chosen
        / f"openapi-generator-cli-{chosen}.jar"
    )
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

        if jar_path.exists():
            if verify and expected_algo and expected_digest:
                _verify_digest(jar_path, expected_algo, expected_digest)
            return jar_path
        url = (
            "https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/"
            f"{version}/openapi-generator-cli-{version}.jar"
        )
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


def collect_engine_snapshot(generator_version: Optional[str]) -> EngineSnapshot:
    info = get_platform_info()
    runtime_dir = jre_install_dir(create=False)
    embedded_java = find_embedded_java(runtime_dir)
    selected: Optional[Path] = None
    selected_error: Optional[str] = None
    try:
        selected = resolve_generator_jar(generator_version, allow_download=False)
    except CLIError as exc:
        selected_error = str(exc)
    cached = list_cached_jars()
    system_java = shutil.which("java")
    return EngineSnapshot(
        platform=info,
        runtime_dir=runtime_dir,
        embedded_java=embedded_java,
        selected_generator=selected,
        selected_generator_error=selected_error,
        cached_jars=cached,
        system_java=system_java,
    )


def emit_engine_snapshot(
    snapshot: EngineSnapshot,
    *,
    include_selected_generator: bool,
    include_cached_jars: bool,
) -> None:
    runtime_dir = snapshot.runtime_dir
    log(f"embedded jre dir: {runtime_dir if runtime_dir.exists() else 'not initialized'}")
    log(f"embedded java: {snapshot.embedded_java if snapshot.embedded_java else 'not installed'}")
    if include_selected_generator:
        if snapshot.selected_generator:
            log(f"selected generator jar: {snapshot.selected_generator}")
        elif snapshot.selected_generator_error:
            log_error(snapshot.selected_generator_error)
    if include_cached_jars:
        if snapshot.cached_jars:
            log("cached generator jars:")
            for entry in snapshot.cached_jars:
                log(f"  - {entry}")
        else:
            log("cached generator jars: none")
    log(f"system java: {snapshot.system_java if snapshot.system_java else 'not found'}")


def resolve_java_opts(cli_opts: Sequence[str]) -> ResolvedJavaOptions:
    result: List[str] = []
    env_opts = os.environ.get(JAVA_OPTS_ENV_VAR)
    env_provided = bool(env_opts)
    if env_opts:
        result.extend(shlex.split(env_opts))
    cli_provided = bool(cli_opts)
    result.extend(cli_opts)
    provided = env_provided or cli_provided
    if not result:
        result.extend(DEFAULT_JAVA_OPTS)
    return ResolvedJavaOptions(result, provided)


def run_openapi_generator(
    jar: Path,
    engine: str,
    generator_args: Sequence[str],
    java_opts: Sequence[str],
    *,
    stream: bool = True,
) -> Tuple[int, str]:
    if engine not in {"embedded", "system"}:
        raise CLIError(f"unknown engine '{engine}'")
    java_options = list(java_opts)
    java_cmd: str
    if engine == "embedded":
        runtime_dir = ensure_embedded_jre()
        java_exec_path = find_embedded_java(runtime_dir)
        if not java_exec_path:
            raise CLIError("embedded JRE is not installed; run 'swain_cli engine install-jre'")
        java_cmd = str(java_exec_path)
        env = os.environ.copy()
        env["JAVA_HOME"] = str(runtime_dir)
    else:
        java_exec = shutil.which("java")
        if not java_exec:
            raise CLIError("java executable not found in PATH; install Java or use embedded engine")
        java_cmd = java_exec
        env = os.environ.copy()
    cmd = [java_cmd, *java_options, "-jar", str(jar), *generator_args]
    log(f"exec {redact(format_cli_command(cmd))}")
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    max_capture_chars = 200_000
    captured: deque[str] = deque()
    captured_size = 0

    def capture(line: str) -> None:
        nonlocal captured_size
        if len(line) > max_capture_chars:
            captured.clear()
            line = line[-max_capture_chars:]
            captured_size = 0
        captured.append(line)
        captured_size += len(line)
        while captured and captured_size > max_capture_chars:
            removed = captured.popleft()
            captured_size -= len(removed)

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if stream:
                sys.stdout.write(line)
            capture(line)
        proc.stdout.close()
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        raise
    return proc.returncode, "".join(captured)


def handle_list_generators(args: SimpleNamespace) -> int:
    jar = resolve_generator_jar(args.generator_version)
    resolved_java_opts = resolve_java_opts(getattr(args, "java_opts", []))
    java_opts = resolved_java_opts.options
    log(f"java options: {redact(format_cli_command(java_opts))}")
    rc, _ = run_openapi_generator(jar, args.engine, ["list"], java_opts)
    if rc != 0:
        log_error("openapi-generator list failed")
        return rc if rc != 0 else EXIT_CODE_SUBPROCESS
    return 0


def handle_engine_status(_: SimpleNamespace) -> int:
    snapshot = collect_engine_snapshot(None)
    log("engine status")
    emit_engine_snapshot(snapshot, include_selected_generator=False, include_cached_jars=True)
    return 0


def handle_engine_install_jre(args: SimpleNamespace) -> int:
    ensure_embedded_jre(force=args.force)
    runtime_dir = jre_install_dir()
    java_exec = find_embedded_java(runtime_dir)
    log(f"embedded jre ready at {runtime_dir}")
    if java_exec:
        log(f"java executable: {java_exec}")
    return 0


def handle_engine_update_jar(args: SimpleNamespace) -> int:
    ensure_generator_jar(args.version, verify=not getattr(args, "no_verify", False))
    log(f"cached OpenAPI Generator {args.version}")
    return 0


def handle_engine_paths(args: SimpleNamespace) -> int:
    info = get_platform_info()
    payload = {
        "platform": {"os": info.os_name, "arch": info.arch},
        "cache_root": str(cache_root(create=False)),
        "downloads_dir": str(downloads_dir(create=False)),
        "jar_cache_dir": str(jar_cache_dir(create=False)),
        "jre_install_dir": str(jre_install_dir(create=False)),
        "schema_cache_dir": str(cache_root(create=False) / "schemas"),
    }
    if getattr(args, "json", False):
        indent = 2 if getattr(args, "pretty", False) else None
        print(json.dumps(payload, indent=indent, sort_keys=True))
        return 0
    print(f"cache_root: {payload['cache_root']}")
    print(f"downloads_dir: {payload['downloads_dir']}")
    print(f"jar_cache_dir: {payload['jar_cache_dir']}")
    print(f"jre_install_dir: {payload['jre_install_dir']}")
    print(f"schema_cache_dir: {payload['schema_cache_dir']}")
    return 0


def _delete_path(path: Path) -> Optional[str]:
    try:
        if not path.exists():
            return None
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    except OSError as exc:
        return str(exc)
    return None


def handle_engine_clean(args: SimpleNamespace) -> int:
    force = bool(getattr(args, "force", False))
    selected_any = any(
        bool(getattr(args, name, False))
        for name in ("downloads", "jars", "jre", "schemas", "all")
    )
    clean_downloads = bool(getattr(args, "all", False)) or bool(
        getattr(args, "downloads", False)
    )
    clean_jars = bool(getattr(args, "all", False)) or bool(getattr(args, "jars", False))
    clean_jre = bool(getattr(args, "all", False)) or bool(getattr(args, "jre", False))
    clean_schemas = bool(getattr(args, "all", False)) or bool(
        getattr(args, "schemas", False)
    )
    if not selected_any:
        clean_downloads = True

    targets: List[Path] = []
    if clean_downloads:
        targets.append(downloads_dir(create=False))
    if clean_jars:
        targets.append(jar_cache_dir(create=False))
    if clean_jre:
        targets.append(jre_install_dir(create=False))
    if clean_schemas:
        targets.append(cache_root(create=False) / "schemas")

    payload: Dict[str, Any] = {
        "dry_run": not force,
        "targets": [str(path) for path in targets],
        "deleted": [],
        "errors": [],
    }

    if not force:
        if getattr(args, "json", False):
            indent = 2 if getattr(args, "pretty", False) else None
            print(json.dumps(payload, indent=indent, sort_keys=True))
            return 0
        print("engine clean (dry-run):")
        for target in targets:
            print(f"- would delete: {target}")
        print("re-run with --force to apply")
        return 0

    for target in targets:
        err = _delete_path(target)
        if err:
            payload["errors"].append({"path": str(target), "error": err})
        else:
            payload["deleted"].append(str(target))

    if getattr(args, "json", False):
        indent = 2 if getattr(args, "pretty", False) else None
        print(json.dumps(payload, indent=indent, sort_keys=True))
    else:
        for deleted in payload["deleted"]:
            print(f"deleted: {deleted}")
        for record in payload["errors"]:
            log_error(f"failed to delete {record['path']}: {record['error']}")
    return 0 if not payload["errors"] else 1


def _version_key(value: str) -> Tuple[int, int, int, str]:
    parts = (value or "").split(".")
    nums: List[int] = []
    for part in parts[:3]:
        try:
            nums.append(int(part))
        except ValueError:
            nums.append(-1)
    while len(nums) < 3:
        nums.append(-1)
    return (nums[0], nums[1], nums[2], value)


def handle_engine_prune_jars(args: SimpleNamespace) -> int:
    keep = int(getattr(args, "keep", 3) or 0)
    if keep < 0:
        raise CLIError("--keep must be >= 0")
    force = bool(getattr(args, "force", False))

    root = jar_cache_dir(create=False)
    if not root.exists():
        print("no cached jars to prune")
        return 0

    entries: List[Tuple[str, Path]] = []
    for version_dir in root.iterdir():
        if not version_dir.is_dir():
            continue
        version = version_dir.name
        jar = version_dir / f"openapi-generator-cli-{version}.jar"
        if jar.exists():
            entries.append((version, version_dir))

    entries.sort(key=lambda item: _version_key(item[0]))
    keep_set = {version for version, _ in entries[-keep:]} if keep else set()
    prune = [path for version, path in entries if version not in keep_set]

    payload: Dict[str, Any] = {
        "dry_run": not force,
        "keep": keep,
        "kept_versions": sorted(keep_set, key=_version_key),
        "targets": [str(path) for path in prune],
        "deleted": [],
        "errors": [],
    }

    if not force:
        if getattr(args, "json", False):
            indent = 2 if getattr(args, "pretty", False) else None
            print(json.dumps(payload, indent=indent, sort_keys=True))
            return 0
        print("engine prune-jars (dry-run):")
        for target in prune:
            print(f"- would delete: {target}")
        print(f"kept versions: {', '.join(payload['kept_versions']) or 'none'}")
        print("re-run with --force to apply")
        return 0

    for target in prune:
        err = _delete_path(target)
        if err:
            payload["errors"].append({"path": str(target), "error": err})
        else:
            payload["deleted"].append(str(target))

    if getattr(args, "json", False):
        indent = 2 if getattr(args, "pretty", False) else None
        print(json.dumps(payload, indent=indent, sort_keys=True))
    else:
        for deleted in payload["deleted"]:
            print(f"deleted: {deleted}")
        for record in payload["errors"]:
            log_error(f"failed to delete {record['path']}: {record['error']}")
    return 0 if not payload["errors"] else 1


def handle_engine_use_system(_: SimpleNamespace) -> int:
    message = textwrap.dedent(
        f"""
        To use the system Java runtime, append '--engine system' to swain_cli commands
        (or export {ENGINE_ENV_VAR}=system).
        Example: swain_cli gen --engine system -i schema.yaml -l python -o sdks
        """
    ).strip()
    log(message)
    return 0


def handle_engine_use_embedded(_: SimpleNamespace) -> int:
    message = textwrap.dedent(
        """
        swain_cli uses the embedded runtime by default. To ensure it is ready, run:
          swain_cli engine install-jre
        You can explicitly select it with '--engine embedded'.
        """
    ).strip()
    log(message)
    return 0
