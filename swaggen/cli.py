#!/usr/bin/env python3
"""swaggen CLI entry point."""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import string
import subprocess
import sys
import tempfile
import textwrap
import urllib.error
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

PINNED_GENERATOR_VERSION = "7.6.0"
JRE_VERSION = "21.0.4"
ASSET_BASE = "https://github.com/swain-labs/swaggen/releases/download/jre-21.0.4"
CACHE_ENV_VAR = "SWAGGEN_CACHE_DIR"
DEFAULT_CACHE_DIR_NAME = "swaggen"
EXIT_CODE_SUBPROCESS = 1
EXIT_CODE_USAGE = 2
LANGUAGE_ALIASES = {"typescript": "typescript-axios"}

VENDOR_JAR_NAME = f"openapi-generator-cli-{PINNED_GENERATOR_VERSION}.jar"


@dataclass(frozen=True)
class JREAsset:
    filename: str
    sha256: Optional[str]
    checksum_filename: Optional[str] = None


JRE_ASSETS: Dict[Tuple[str, str], JREAsset] = {
    ("linux", "x86_64"): JREAsset(
        "swaggen-jre-linux-x86_64.tar.gz", None, "swaggen-jre-linux-x86_64.tar.gz.sha256"
    ),
    ("linux", "arm64"): JREAsset(
        "swaggen-jre-linux-arm64.tar.gz", None, "swaggen-jre-linux-arm64.tar.gz.sha256"
    ),
    ("macos", "x86_64"): JREAsset(
        "swaggen-jre-macos-x86_64.tar.gz",
        "6574e6f5f20633ecfa95202d6e5a196936f90f300c0c99f00f34df8ad5e8aeb6",
        "swaggen-jre-macos-x86_64.tar.gz.sha256",
    ),
    ("macos", "arm64"): JREAsset(
        "swaggen-jre-macos-arm64.tar.gz",
        "f4bdfa2bd54a2257e8b9f77a50c61e4709ebbddb296b0370955de35d84c79964",
        "swaggen-jre-macos-arm64.tar.gz.sha256",
    ),
    ("windows", "x86_64"): JREAsset(
        "swaggen-jre-windows-x86_64.zip", None, "swaggen-jre-windows-x86_64.zip.sha256"
    ),
}


class CLIError(Exception):
    """Raised for user-facing CLI errors."""


@dataclass(frozen=True)
class PlatformInfo:
    os_name: str
    arch: str

    @classmethod
    def detect(cls) -> "PlatformInfo":
        return cls(normalize_os(platform.system()), normalize_arch(platform.machine()))

    @property
    def key(self) -> Tuple[str, str]:
        return (self.os_name, self.arch)


@dataclass(frozen=True)
class EnginePaths:
    cache_root: Path

    @classmethod
    def detect(cls) -> "EnginePaths":
        explicit = os.environ.get(CACHE_ENV_VAR)
        if explicit:
            root = Path(explicit).expanduser()
            root.mkdir(parents=True, exist_ok=True)
            return cls(root)

        info = PlatformInfo.detect()
        home = Path.home()
        if info.os_name == "windows":
            base = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        elif info.os_name == "macos":
            base = home / "Library" / "Caches"
        else:
            base = Path(os.environ.get("XDG_CACHE_HOME", home / ".cache"))

        root = base / DEFAULT_CACHE_DIR_NAME
        root.mkdir(parents=True, exist_ok=True)
        return cls(root)

    def jre_dir(self, info: PlatformInfo) -> Path:
        return self.cache_root / "jre" / f"{info.os_name}-{info.arch}"

    def jar_dir(self) -> Path:
        path = self.cache_root / "jars"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def downloads_dir(self) -> Path:
        path = self.cache_root / "downloads"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def vendor_jar(self) -> Path:
        return Path(__file__).resolve().parent / "vendor" / VENDOR_JAR_NAME


@dataclass
class EngineSnapshot:
    platform: PlatformInfo
    runtime_dir: Path
    embedded_java: Optional[Path]
    vendor_jar: Optional[Path]
    selected_generator: Optional[Path]
    selected_generator_error: Optional[str]
    cached_jars: List[str]
    system_java: Optional[str]


def log(message: str) -> None:
    print(f"[swaggen] {message}")


def log_error(message: str) -> None:
    print(f"[swaggen] {message}", file=sys.stderr)


@lru_cache()
def get_platform_info() -> PlatformInfo:
    return PlatformInfo.detect()


@lru_cache()
def get_engine_paths() -> EnginePaths:
    return EnginePaths.detect()


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
    m = machine.lower()
    if m in {"x86_64", "amd64"}:
        return "x86_64"
    if m in {"arm64", "aarch64"}:
        return "arm64"
    return m


def cache_root() -> Path:
    return get_engine_paths().cache_root


def jre_install_dir() -> Path:
    return get_engine_paths().jre_dir(get_platform_info())


def jar_cache_dir() -> Path:
    return get_engine_paths().jar_dir()


def downloads_dir() -> Path:
    return get_engine_paths().downloads_dir()


def vendor_jar_path() -> Path:
    return get_engine_paths().vendor_jar()


def find_vendor_jar() -> Optional[Path]:
    jar_path = vendor_jar_path()
    return jar_path if jar_path.exists() else None


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

    for line in lines:
        candidate = line.strip().split()
        if not candidate:
            continue
        digest = candidate[0].lower()
        if len(digest) == 64 and all(c in string.hexdigits for c in digest):
            return digest

    raise CLIError(f"checksum file {path} did not contain a SHA-256 value")


def resolve_asset_sha256(asset: JREAsset) -> str:
    if asset.sha256:
        return asset.sha256

    name = checksum_filename(asset)
    checksum_path = downloads_dir() / name
    url = f"{ASSET_BASE}/{name}"
    download_file(url, checksum_path, None)
    return parse_checksum_file(checksum_path)


def download_file(url: str, dest: Path, expected_sha256: Optional[str]) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and expected_sha256 and verify_sha256(dest, expected_sha256):
        return
    if dest.exists() and not expected_sha256:
        return

    log(f"downloading {url}")
    try:
        with urllib.request.urlopen(url) as response, tempfile.NamedTemporaryFile(
            delete=False
        ) as tmp:
            shutil.copyfileobj(response, tmp)
            tmp_path = Path(tmp.name)
    except urllib.error.URLError as exc:
        raise CLIError(f"failed to download {url}: {exc}") from exc

    if expected_sha256 and not verify_sha256(tmp_path, expected_sha256):
        tmp_path.unlink(missing_ok=True)
        raise CLIError("downloaded file does not match expected SHA-256")

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_path.replace(dest)


def verify_sha256(path: Path, expected: str) -> bool:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected:
        log_error(
            f"checksum mismatch for {path.name}: expected {expected}, got {actual}"
        )
        return False
    return True


def ensure_embedded_jre(force: bool = False) -> Path:
    asset = get_jre_asset()
    target_dir = jre_install_dir()
    java_path = find_embedded_java(target_dir)
    if java_path and not force:
        return target_dir

    archive_path = downloads_dir() / asset.filename
    checksum_path = downloads_dir() / checksum_filename(asset)
    if force:
        archive_path.unlink(missing_ok=True)
        checksum_path.unlink(missing_ok=True)
    url = f"{ASSET_BASE}/{asset.filename}"
    expected_sha = resolve_asset_sha256(asset)
    download_file(url, archive_path, expected_sha)

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
    return target_dir


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

    subdirs = [p for p in root.iterdir() if p.is_dir()]
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
    candidate = root / "bin" / java_binary_name()
    if candidate.exists():
        return candidate

    for path in root.rglob(java_binary_name()):
        if path.name == java_binary_name() and path.parent.name == "bin":
            return path
    return None


def collect_engine_snapshot(generator_version: Optional[str]) -> EngineSnapshot:
    info = get_platform_info()
    paths = get_engine_paths()
    runtime_dir = paths.jre_dir(info)
    embedded_java = find_embedded_java(runtime_dir)
    vendor = find_vendor_jar()
    selected: Optional[Path] = None
    selected_error: Optional[str] = None

    try:
        selected = resolve_generator_jar(generator_version)
    except CLIError as exc:
        selected_error = str(exc)

    cached = list_cached_jars()
    system_java = shutil.which("java")

    return EngineSnapshot(
        platform=info,
        runtime_dir=runtime_dir,
        embedded_java=embedded_java,
        vendor_jar=vendor,
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
    log(
        f"embedded jre dir: {runtime_dir if runtime_dir.exists() else 'not initialized'}"
    )
    log(
        f"embedded java: {snapshot.embedded_java if snapshot.embedded_java else 'not installed'}"
    )
    log(
        f"bundled generator jar: {snapshot.vendor_jar if snapshot.vendor_jar else 'missing'}"
    )

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

    log(
        f"system java: {snapshot.system_java if snapshot.system_java else 'not found'}"
    )


def resolve_generator_jar(version: Optional[str]) -> Path:
    chosen_version = version or os.environ.get("SWAGGEN_GENERATOR_VERSION")
    if not chosen_version:
        chosen_version = PINNED_GENERATOR_VERSION

    if chosen_version == PINNED_GENERATOR_VERSION:
        vendor = find_vendor_jar()
        if vendor:
            return vendor

    jar_path = jar_cache_dir() / chosen_version / f"openapi-generator-cli-{chosen_version}.jar"
    if jar_path.exists():
        return jar_path

    if chosen_version == PINNED_GENERATOR_VERSION:
        raise CLIError(
            "bundled OpenAPI Generator jar not found; reinstall or run engine update-jar"
        )

    raise CLIError(
        f"OpenAPI Generator {chosen_version} is not cached; run 'swaggen engine update-jar --version {chosen_version}'"
    )


def ensure_generator_jar(version: str) -> Path:
    jar_path = jar_cache_dir() / version / f"openapi-generator-cli-{version}.jar"
    if jar_path.exists():
        return jar_path

    url = (
        "https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/"
        f"{version}/openapi-generator-cli-{version}.jar"
    )
    download_file(url, jar_path, None)
    return jar_path


def run_openapi_generator(jar: Path, engine: str, generator_args: Sequence[str]) -> int:
    if engine not in {"embedded", "system"}:
        raise CLIError(f"unknown engine '{engine}'")

    if engine == "embedded":
        runtime_dir = ensure_embedded_jre()
        java_exec = find_embedded_java(runtime_dir)
        if not java_exec:
            raise CLIError("embedded JRE is not installed; run 'swaggen engine install-jre'")
        cmd = [str(java_exec), "-jar", str(jar), *generator_args]
        env = os.environ.copy()
        env["JAVA_HOME"] = str(runtime_dir)
    else:
        java_exec = shutil.which("java")
        if not java_exec:
            raise CLIError("java executable not found in PATH; install Java or use embedded engine")
        cmd = [java_exec, "-jar", str(jar), *generator_args]
        env = os.environ.copy()

    log(f"exec {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, env=env)
    try:
        proc.communicate()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        raise
    return proc.returncode


def handle_doctor(args: argparse.Namespace) -> int:
    system = platform.platform()
    python_version = sys.version.replace("\n", " ")
    snapshot = collect_engine_snapshot(args.generator_version)

    log("doctor report")
    log(f"python: {python_version}")
    log(f"platform: {system}")
    log(
        f"detected os/arch: {snapshot.platform.os_name}/{snapshot.platform.arch}"
    )

    emit_engine_snapshot(
        snapshot,
        include_selected_generator=True,
        include_cached_jars=False,
    )
    return 0


def handle_list_generators(args: argparse.Namespace) -> int:
    jar = resolve_generator_jar(args.generator_version)
    engine = args.engine
    rc = run_openapi_generator(jar, engine, ["list"])
    if rc != 0:
        log_error("openapi-generator list failed")
        return rc if rc != 0 else EXIT_CODE_SUBPROCESS
    return 0


def build_generate_command(
    schema: str, language: str, args: argparse.Namespace, out_dir: Path
) -> Tuple[str, Path, List[str]]:
    resolved_lang = LANGUAGE_ALIASES.get(language, language)
    target_dir = out_dir / resolved_lang
    target_dir.mkdir(parents=True, exist_ok=True)

    cmd: List[str] = [
        "generate",
        "-i",
        schema,
        "-g",
        resolved_lang,
        "-o",
        str(target_dir),
    ]

    if args.config:
        cmd.extend(["-c", args.config])
    if args.templates:
        cmd.extend(["-t", args.templates])
    for prop in args.additional_properties or []:
        cmd.extend(["-p", prop])
    for raw_arg in args.generator_arg or []:
        cmd.append(raw_arg)
    for var in getattr(args, "property", []) or []:
        cmd.extend(["-D", var])
    if args.skip_validate_spec:
        cmd.append("--skip-validate-spec")
    if args.verbose:
        cmd.append("-v")

    return resolved_lang, target_dir, cmd


def handle_gen(args: argparse.Namespace) -> int:
    jar = resolve_generator_jar(args.generator_version)
    engine = args.engine

    schema = args.schema
    if not is_url(schema):
        schema_path = Path(schema)
        if not schema_path.exists():
            raise CLIError(f"schema not found: {schema_path}")
        schema = str(schema_path)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    languages = args.languages
    if not languages:
        raise CLIError("at least one --lang is required")

    for lang in languages:
        resolved_lang, target_dir, cmd = build_generate_command(schema, lang, args, out_dir)

        log(f"generating {resolved_lang} into {target_dir}")
        rc = run_openapi_generator(jar, engine, cmd)
        if rc != 0:
            log_error(f"generation failed for {resolved_lang} (exit code {rc})")
            return rc if rc != 0 else EXIT_CODE_SUBPROCESS

    return 0


def handle_engine_status(args: argparse.Namespace) -> int:
    snapshot = collect_engine_snapshot(None)

    log("engine status")
    emit_engine_snapshot(
        snapshot,
        include_selected_generator=False,
        include_cached_jars=True,
    )
    return 0


def list_cached_jars() -> List[str]:
    base = jar_cache_dir()
    entries: List[str] = []
    for version_dir in sorted(base.iterdir()):
        if not version_dir.is_dir():
            continue
        jar = version_dir / f"openapi-generator-cli-{version_dir.name}.jar"
        if jar.exists():
            entries.append(f"{version_dir.name} -> {jar}")
    return entries


def handle_engine_install_jre(args: argparse.Namespace) -> int:
    ensure_embedded_jre(force=args.force)
    runtime_dir = jre_install_dir()
    java_exec = find_embedded_java(runtime_dir)
    log(f"embedded jre ready at {runtime_dir}")
    if java_exec:
        log(f"java executable: {java_exec}")
    return 0


def handle_engine_update_jar(args: argparse.Namespace) -> int:
    version = args.version
    ensure_generator_jar(version)
    log(f"cached OpenAPI Generator {version}")
    return 0


def handle_engine_use_system(args: argparse.Namespace) -> int:
    message = textwrap.dedent(
        """
        To use the system Java runtime, append '--engine system' to swaggen commands.
        Example: swaggen gen --engine system -i schema.yaml -l python -o sdks
        """
    ).strip()
    log(message)
    return 0


def handle_engine_use_embedded(args: argparse.Namespace) -> int:
    message = textwrap.dedent(
        """
        swaggen uses the embedded runtime by default. To ensure it is ready, run:
          swaggen engine install-jre
        You can explicitly select it with '--engine embedded'.
        """
    ).strip()
    log(message)
    return 0


def is_url(path: str) -> bool:
    return "://" in path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="swaggen CLI")
    parser.add_argument(
        "--generator-version",
        help="override the OpenAPI Generator version to use (must be cached)",
    )

    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    parser_doctor = subparsers.add_parser("doctor", help="show environment diagnostics")
    parser_doctor.set_defaults(func=handle_doctor)

    parser_list = subparsers.add_parser(
        "list-generators", help="list generators supported by OpenAPI Generator"
    )
    parser_list.add_argument(
        "--engine",
        choices=["embedded", "system"],
        default="embedded",
        help="select Java runtime (default: embedded)",
    )
    parser_list.set_defaults(func=handle_list_generators)

    parser_gen = subparsers.add_parser(
        "gen", help="generate SDKs using OpenAPI Generator"
    )
    parser_gen.add_argument("-i", "--schema", required=True, help="schema path or URL")
    parser_gen.add_argument(
        "-l",
        "--lang",
        dest="languages",
        action="append",
        default=[],
        help="target generator (repeat for multiple languages)",
    )
    parser_gen.add_argument("-o", "--out", required=True, help="output directory")
    parser_gen.add_argument("-c", "--config", help="generator config file")
    parser_gen.add_argument("-t", "--templates", help="custom templates directory")
    parser_gen.add_argument(
        "-p",
        "--additional-properties",
        dest="additional_properties",
        action="append",
        help="key=value additional properties (repeatable)",
    )
    parser_gen.add_argument(
        "--generator-arg",
        dest="generator_arg",
        action="append",
        help="raw OpenAPI Generator argument (repeatable)",
    )
    parser_gen.add_argument(
        "-D",
        dest="property",
        action="append",
        default=[],
        help="system properties passed to the generator",
    )
    parser_gen.add_argument(
        "--skip-validate-spec",
        action="store_true",
        help="skip OpenAPI spec validation",
    )
    parser_gen.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable verbose OpenAPI Generator output",
    )
    parser_gen.add_argument(
        "--engine",
        choices=["embedded", "system"],
        default="embedded",
        help="select Java runtime (default: embedded)",
    )
    parser_gen.set_defaults(func=handle_gen)

    parser_engine = subparsers.add_parser(
        "engine", help="manage the embedded engine assets"
    )
    engine_sub = parser_engine.add_subparsers(dest="engine_command")
    engine_sub.required = True

    parser_engine_status = engine_sub.add_parser(
        "status", help="show embedded engine status"
    )
    parser_engine_status.set_defaults(func=handle_engine_status)

    parser_engine_install = engine_sub.add_parser(
        "install-jre", help="download and install the embedded JRE"
    )
    parser_engine_install.add_argument(
        "--force", action="store_true", help="reinstall even if already present"
    )
    parser_engine_install.set_defaults(func=handle_engine_install_jre)

    parser_engine_update = engine_sub.add_parser(
        "update-jar", help="download and cache a different OpenAPI Generator version"
    )
    parser_engine_update.add_argument(
        "--version", required=True, help="OpenAPI Generator version to download"
    )
    parser_engine_update.set_defaults(func=handle_engine_update_jar)

    parser_engine_use_system = engine_sub.add_parser(
        "use-system", help="instructions for using the system Java runtime"
    )
    parser_engine_use_system.set_defaults(func=handle_engine_use_system)

    parser_engine_use_embedded = engine_sub.add_parser(
        "use-embedded", help="instructions for using the embedded runtime"
    )
    parser_engine_use_embedded.set_defaults(func=handle_engine_use_embedded)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    handler = getattr(args, "func", None)
    if handler is None:
        parser.print_help()
        return EXIT_CODE_USAGE

    try:
        return handler(args) or 0
    except CLIError as exc:
        log_error(f"error: {exc}")
        return EXIT_CODE_USAGE


if __name__ == "__main__":
    sys.exit(main())
