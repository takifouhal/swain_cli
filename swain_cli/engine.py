"""Embedded engine (JRE + OpenAPI Generator) management for swain_cli."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import textwrap
from collections import deque
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any, List, Optional, Sequence, Tuple

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
    JREAsset,
)
from .errors import CLIError
from .utils import format_cli_command


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

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    def __call__(
        self,
        url: str,
        output_file: str,
        pooch_obj: pooch.Pooch,
        check_only: bool = False,
        **_: Any,
    ) -> None:
        timeout = httpx.Timeout(self.timeout, connect=self.timeout)
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            if check_only:
                response = client.head(url)
                response.raise_for_status()
                return
            with client.stream("GET", url) as response:
                response.raise_for_status()
                with open(output_file, "wb") as fh:
                    for chunk in response.iter_bytes():
                        fh.write(chunk)


HTTPX_DOWNLOADER = HTTPXDownloader(timeout=HTTP_TIMEOUT_SECONDS)


def asset_base_url() -> str:
    return (os.environ.get(ASSET_BASE_ENV_VAR) or ASSET_BASE).rstrip("/")


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
            progressbar=False,
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


def fetch_asset_file(asset_name: str, sha256: Optional[str], force: bool = False) -> Path:
    downloads = downloads_dir()
    target = downloads / asset_name
    if force and target.exists():
        target.unlink()
    if target.exists() and not force:
        try:
            _verify_sha256(target, sha256)
        except CLIError:
            target.unlink()
        else:
            return target

    known_hash = f"sha256:{sha256}" if sha256 else None
    base = asset_base_url()
    try:
        return Path(
            pooch.retrieve(
                url=f"{base}/{asset_name}",
                path=downloads,
                fname=asset_name,
                known_hash=known_hash,
                downloader=HTTPX_DOWNLOADER,
                progressbar=False,
            )
        )
    except httpx.HTTPError as exc:
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
    try:
        shutil.unpack_archive(str(archive), str(dest))
    except (shutil.ReadError, ValueError) as exc:
        raise CLIError(f"unsupported archive format for {archive.name}") from exc


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
        raise CLIError("embedded JRE installation did not produce a usable java executable")
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
            "OpenAPI Generator jar missing; run 'swain_cli engine update-jar --version 7.6.0'"
        )
    raise CLIError(
        f"OpenAPI Generator {chosen} is not cached; run 'swain_cli engine update-jar --version {chosen}'"
    )


def ensure_generator_jar(version: str) -> Path:
    jar_path = jar_cache_dir() / version / f"openapi-generator-cli-{version}.jar"
    jar_path.parent.mkdir(parents=True, exist_ok=True)
    if jar_path.exists():
        return jar_path
    url = (
        "https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/"
        f"{version}/openapi-generator-cli-{version}.jar"
    )
    known_hash = (
        f"sha256:{PINNED_GENERATOR_SHA256}" if version == PINNED_GENERATOR_VERSION else None
    )
    target = Path(
        pooch.retrieve(
            url=url,
            path=jar_path.parent,
            fname=jar_path.name,
            known_hash=known_hash,
            downloader=HTTPX_DOWNLOADER,
            progressbar=False,
        )
    )
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
    log(f"exec {' '.join(cmd)}")
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
    log(f"java options: {format_cli_command(java_opts)}")
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
    ensure_generator_jar(args.version)
    log(f"cached OpenAPI Generator {args.version}")
    return 0


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
