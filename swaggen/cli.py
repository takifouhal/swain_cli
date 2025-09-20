#!/usr/bin/env python3
"""swaggen CLI entry point."""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
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


# Asset filenames are placeholders until official trimmed runtimes are published.
JRE_ASSETS: Dict[Tuple[str, str], JREAsset] = {
    ("linux", "x86_64"): JREAsset("swaggen-jre-linux-x86_64.tar.gz", None),
    ("linux", "arm64"): JREAsset("swaggen-jre-linux-arm64.tar.gz", None),
    ("macos", "x86_64"): JREAsset("swaggen-jre-macos-x86_64.tar.gz", "6574e6f5f20633ecfa95202d6e5a196936f90f300c0c99f00f34df8ad5e8aeb6"),
    ("macos", "arm64"): JREAsset("swaggen-jre-macos-arm64.tar.gz", "f4bdfa2bd54a2257e8b9f77a50c61e4709ebbddb296b0370955de35d84c79964"),
    ("windows", "x86_64"): JREAsset("swaggen-jre-windows-x86_64.zip", None),
}


class CLIError(Exception):
    """Raised for user-facing CLI errors."""


def log(message: str) -> None:
    print(f"[swaggen] {message}")


def log_error(message: str) -> None:
    print(f"[swaggen] {message}", file=sys.stderr)


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
    explicit = os.environ.get(CACHE_ENV_VAR)
    if explicit:
        path = Path(explicit).expanduser()
        path.mkdir(parents=True, exist_ok=True)
        return path

    system = normalize_os(platform.system())
    home = Path.home()
    if system == "windows":
        base = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
    elif system == "macos":
        base = home / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", home / ".cache"))

    path = base / DEFAULT_CACHE_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def jre_install_dir() -> Path:
    os_name = normalize_os(platform.system())
    arch = normalize_arch(platform.machine())
    return cache_root() / "jre" / f"{os_name}-{arch}"


def jar_cache_dir() -> Path:
    path = cache_root() / "jars"
    path.mkdir(parents=True, exist_ok=True)
    return path


def downloads_dir() -> Path:
    path = cache_root() / "downloads"
    path.mkdir(parents=True, exist_ok=True)
    return path


def vendor_jar_path() -> Path:
    return Path(__file__).resolve().parent / "vendor" / VENDOR_JAR_NAME


def find_vendor_jar() -> Optional[Path]:
    jar_path = vendor_jar_path()
    return jar_path if jar_path.exists() else None


def get_jre_asset() -> JREAsset:
    os_name = normalize_os(platform.system())
    arch = normalize_arch(platform.machine())
    asset = JRE_ASSETS.get((os_name, arch))
    if not asset:
        raise CLIError(
            f"unsupported platform {os_name}/{arch}; install Java and use --engine system"
        )
    return asset


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
    if force and archive_path.exists():
        archive_path.unlink()
    url = f"{ASSET_BASE}/{asset.filename}"
    download_file(url, archive_path, asset.sha256)

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
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
        return

    if archive.suffixes[-2:] == [".tar", ".gz"] or archive.suffixes[-1:] == [".tgz"]:
        with tarfile.open(archive, mode="r:gz") as tf:
            tf.extractall(dest)
        return

    if archive.suffixes[-2:] == [".tar", ".xz"]:
        with tarfile.open(archive, mode="r:xz") as tf:
            tf.extractall(dest)
        return

    raise CLIError(f"unsupported archive format for {archive.name}")


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
    os_name = normalize_os(platform.system())
    arch = normalize_arch(platform.machine())

    log("doctor report")
    log(f"python: {python_version}")
    log(f"platform: {system}")
    log(f"detected os/arch: {os_name}/{arch}")

    vendor = find_vendor_jar()
    log(f"bundled generator jar: {'present' if vendor else 'missing'}")

    try:
        jar_path = resolve_generator_jar(args.generator_version)
        log(f"selected generator jar: {jar_path}")
    except CLIError as exc:
        log_error(str(exc))

    runtime_dir = jre_install_dir()
    java_exec = find_embedded_java(runtime_dir)
    if java_exec:
        log(f"embedded java: {java_exec}")
    else:
        log("embedded java: not installed")

    system_java = shutil.which("java")
    log(f"system java: {system_java if system_java else 'not found'}")
    return 0


def handle_list_generators(args: argparse.Namespace) -> int:
    jar = resolve_generator_jar(args.generator_version)
    engine = args.engine
    rc = run_openapi_generator(jar, engine, ["list"])
    if rc != 0:
        log_error("openapi-generator list failed")
        return rc if rc != 0 else EXIT_CODE_SUBPROCESS
    return 0


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
        resolved_lang = LANGUAGE_ALIASES.get(lang, lang)
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
        for var in args.property:
            cmd.extend(["-D", var])
        if args.skip_validate_spec:
            cmd.append("--skip-validate-spec")
        if args.verbose:
            cmd.append("-v")

        log(f"generating {resolved_lang} into {target_dir}")
        rc = run_openapi_generator(jar, engine, cmd)
        if rc != 0:
            log_error(f"generation failed for {resolved_lang} (exit code {rc})")
            return rc if rc != 0 else EXIT_CODE_SUBPROCESS

    return 0


def handle_engine_status(args: argparse.Namespace) -> int:
    runtime_dir = jre_install_dir()
    java_exec = find_embedded_java(runtime_dir)
    vendor = find_vendor_jar()

    log("engine status")
    log(f"embedded jre dir: {runtime_dir if runtime_dir.exists() else 'not initialized'}")
    log(f"embedded java: {java_exec if java_exec else 'not installed'}")
    log(f"bundled generator jar: {vendor if vendor else 'missing'}")

    cached = list_cached_jars()
    if cached:
        log("cached generator jars:")
        for entry in cached:
            log(f"  - {entry}")
    else:
        log("cached generator jars: none")

    system_java = shutil.which("java")
    log(f"system java: {system_java if system_java else 'not found'}")
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
