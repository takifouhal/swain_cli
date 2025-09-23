#!/usr/bin/env python3
"""swain_cli CLI entry point."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
import shutil
import string
import subprocess
import sys
import tempfile
import textwrap
from getpass import getpass
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

PINNED_GENERATOR_VERSION = "7.6.0"
JRE_VERSION = "21.0.4"
# Location of the published JRE archives and checksums. Maintain in lockstep with
# the release workflow assets so downloads resolve correctly.
ASSET_BASE = "https://github.com/takifouhal/swain_cli/releases/download/v0.1.0"
CACHE_ENV_VAR = "SWAIN_CLI_CACHE_DIR"
DEFAULT_CACHE_DIR_NAME = "swain_cli"
EXIT_CODE_SUBPROCESS = 1
EXIT_CODE_USAGE = 2
EXIT_CODE_INTERRUPT = 130
LANGUAGE_ALIASES = {"typescript": "typescript-axios"}

CONFIG_ENV_VAR = "SWAIN_CLI_CONFIG_DIR"
AUTH_TOKEN_ENV_VAR = "SWAIN_CLI_AUTH_TOKEN"
AUTH_FILE_NAME = "auth.json"
DEFAULT_CONFIG_DIR_NAME = "swain_cli"
DEFAULT_CRUDSQL_BASE_URL = "https://api.swain.technology"

COMMON_LANGUAGES = [
    "python",
    "typescript",
    "go",
    "java",
    "csharp",
    "ruby",
    "kotlin",
    "swift",
]

VENDOR_JAR_NAME = f"openapi-generator-cli-{PINNED_GENERATOR_VERSION}.jar"


@dataclass(frozen=True)
class JREAsset:
    filename: str
    sha256: Optional[str]
    checksum_filename: Optional[str] = None


JRE_ASSETS: Dict[Tuple[str, str], JREAsset] = {
    ("linux", "x86_64"): JREAsset(
        "swain_cli-jre-linux-x86_64.tar.gz", None, "swain_cli-jre-linux-x86_64.tar.gz.sha256"
    ),
    ("linux", "arm64"): JREAsset(
        "swain_cli-jre-linux-arm64.tar.gz", None, "swain_cli-jre-linux-arm64.tar.gz.sha256"
    ),
    ("macos", "x86_64"): JREAsset(
        "swain_cli-jre-macos-x86_64.tar.gz",
        "eaf80148765e13e846371eac654fbc8c109f8cf5d369114fd90d944c384e0535",
        "swain_cli-jre-macos-x86_64.tar.gz.sha256",
    ),
    ("macos", "arm64"): JREAsset(
        "swain_cli-jre-macos-arm64.tar.gz",
        "48ae1d63c47e9ade617e2d321889b2675b755c1d2b7db465601b47c0823cff9d",
        "swain_cli-jre-macos-arm64.tar.gz.sha256",
    ),
    ("windows", "x86_64"): JREAsset(
        "swain_cli-jre-windows-x86_64.zip", None, "swain_cli-jre-windows-x86_64.zip.sha256"
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


@dataclass(frozen=True)
class ConfigPaths:
    root: Path

    @classmethod
    def detect(cls) -> "ConfigPaths":
        explicit = os.environ.get(CONFIG_ENV_VAR)
        if explicit:
            root = Path(explicit).expanduser()
            root.mkdir(parents=True, exist_ok=True)
            return cls(root)

        info = get_platform_info()
        home = Path.home()
        if info.os_name == "windows":
            base = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        elif info.os_name == "macos":
            base = home / "Library" / "Application Support"
        else:
            base = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))

        root = base / DEFAULT_CONFIG_DIR_NAME
        root.mkdir(parents=True, exist_ok=True)
        return cls(root)

    def auth_file(self) -> Path:
        return self.root / AUTH_FILE_NAME


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


@dataclass
class AuthState:
    access_token: Optional[str] = None


def log(message: str) -> None:
    print(f"[swain_cli] {message}")


def log_error(message: str) -> None:
    print(f"[swain_cli] {message}", file=sys.stderr)


@lru_cache()
def get_platform_info() -> PlatformInfo:
    return PlatformInfo.detect()


@lru_cache()
def get_engine_paths() -> EnginePaths:
    return EnginePaths.detect()


@lru_cache()
def get_config_paths() -> ConfigPaths:
    return ConfigPaths.detect()


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


def config_root() -> Path:
    return get_config_paths().root


def jre_install_dir() -> Path:
    return get_engine_paths().jre_dir(get_platform_info())


def jar_cache_dir() -> Path:
    return get_engine_paths().jar_dir()


def auth_config_path() -> Path:
    return get_config_paths().auth_file()


def downloads_dir() -> Path:
    return get_engine_paths().downloads_dir()


def vendor_jar_path() -> Path:
    return get_engine_paths().vendor_jar()


def find_vendor_jar() -> Optional[Path]:
    jar_path = vendor_jar_path()
    return jar_path if jar_path.exists() else None


def load_auth_state() -> AuthState:
    path = auth_config_path()
    if not path.exists():
        return AuthState()

    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CLIError(f"unable to read auth configuration {path}: {exc}") from exc

    if not content.strip():
        return AuthState()

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise CLIError(
            f"auth configuration {path} contains invalid JSON: {exc}"
        ) from exc

    token = data.get("access_token")
    if token is not None and not isinstance(token, str):
        raise CLIError(
            f"auth configuration {path} has a non-string access_token value"
        )

    normalized = token.strip() if token else None
    return AuthState(normalized)


def save_auth_state(state: AuthState) -> None:
    if not state.access_token:
        raise CLIError("attempted to save empty auth state")

    path = auth_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {"access_token": state.access_token}

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=path.parent,
        ) as tmp:
            json.dump(payload, tmp, indent=2)
            tmp.write("\n")
            temp_path = Path(tmp.name)
    except OSError as exc:
        raise CLIError(f"unable to write auth configuration {path}: {exc}") from exc

    try:
        os.replace(temp_path, path)
        if os.name != "nt":
            path.chmod(0o600)
    except OSError as exc:
        temp_path.unlink(missing_ok=True)
        raise CLIError(f"unable to finalize auth configuration {path}: {exc}") from exc


def clear_auth_state() -> None:
    path = auth_config_path()
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise CLIError(f"unable to remove auth configuration {path}: {exc}") from exc


def mask_token(token: str) -> str:
    if len(token) <= 8:
        return "*" * len(token)
    return f"{token[:4]}...{token[-4:]}"


def resolve_auth_token() -> Optional[str]:
    env_token = os.environ.get(AUTH_TOKEN_ENV_VAR)
    if env_token:
        stripped = env_token.strip()
        if stripped:
            return stripped

    state = load_auth_state()
    return state.access_token


def persist_auth_token(token: str) -> None:
    normalized = token.strip()
    if not normalized:
        raise CLIError("attempted to persist empty auth token")

    save_auth_state(AuthState(normalized))
    log(f"stored access token ({mask_token(normalized)}) at {auth_config_path()}")


def require_auth_token(purpose: str = "perform this action") -> str:
    token = resolve_auth_token()
    if not token:
        raise CLIError(
            f"authentication token required to {purpose}; run 'swain_cli auth login'"
        )
    return token


def crudsql_dynamic_swagger_url(base_url: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    if not parsed.scheme or not parsed.netloc:
        raise CLIError(
            f"invalid CrudSQL base URL '{base_url}'; include scheme and host (e.g. https://api.example.com)"
        )

    normalized_base = base_url.rstrip("/") + "/"
    return urllib.parse.urljoin(normalized_base, "api/dynamic_swagger")


def crudsql_discover_schema_url(base_url: str, token: str) -> str:
    normalized_base = base_url.rstrip("/") + "/"
    discovery_url = urllib.parse.urljoin(normalized_base, "api/schema-location")

    headers = {
        "Accept": "application/json",
        "User-Agent": f"swain_cli/{PINNED_GENERATOR_VERSION}",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(discovery_url, headers=headers)

    try:
        with urllib.request.urlopen(request) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return crudsql_dynamic_swagger_url(base_url)
        detail = f"{exc.code} {exc.reason}".strip()
        raise CLIError(
            f"failed to resolve CrudSQL schema location from {discovery_url}: {detail}"
        ) from exc
    except urllib.error.URLError as exc:
        raise CLIError(
            f"failed to contact CrudSQL discovery endpoint {discovery_url}: {exc}"
        ) from exc

    if not payload or not payload.strip():
        return crudsql_dynamic_swagger_url(base_url)

    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return crudsql_dynamic_swagger_url(base_url)

    schema_url = data.get("schema_url") or data.get("schemaUrl")
    if not isinstance(schema_url, str) or not schema_url.strip():
        return crudsql_dynamic_swagger_url(base_url)

    return urllib.parse.urljoin(normalized_base, schema_url.strip())


def fetch_crudsql_schema(base_url: str, token: str) -> Path:
    schema_url = crudsql_discover_schema_url(base_url, token)
    log(f"fetching CrudSQL schema from {schema_url}")

    headers = {
        "Accept": "application/json",
        "User-Agent": f"swain_cli/{PINNED_GENERATOR_VERSION}",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(schema_url, headers=headers)

    try:
        with urllib.request.urlopen(request) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        detail = f"{exc.code} {exc.reason}".strip()
        body = ""
        try:
            body_bytes = exc.read()
            if body_bytes:
                body = body_bytes.decode("utf-8", "replace").strip()
        except Exception:  # pragma: no cover - defensive best effort
            body = ""
        if body:
            first_line = body.splitlines()[0]
            detail = f"{detail}: {first_line}" if detail else first_line
        raise CLIError(
            f"failed to fetch CrudSQL schema from {schema_url}: {detail}"
        ) from exc
    except urllib.error.URLError as exc:
        raise CLIError(
            f"failed to reach CrudSQL backend at {schema_url}: {exc}"
        ) from exc

    if not payload or not payload.strip():
        raise CLIError("CrudSQL dynamic swagger response was empty")

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", delete=False, suffix=".json"
        ) as handle:
            handle.write(payload)
            temp_path = Path(handle.name)
    except OSError as exc:
        raise CLIError(f"failed to persist CrudSQL schema locally: {exc}") from exc

    return temp_path


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
    chosen_version = version or os.environ.get("SWAIN_CLI_GENERATOR_VERSION")
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
        f"OpenAPI Generator {chosen_version} is not cached; run 'swain_cli engine update-jar --version {chosen_version}'"
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
            raise CLIError("embedded JRE is not installed; run 'swain_cli engine install-jre'")
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


def read_login_token(args: argparse.Namespace) -> str:
    if getattr(args, "token", None):
        token = args.token.strip()
        if not token:
            raise CLIError("--token was provided but is empty")
        return token

    if getattr(args, "stdin", False):
        data = sys.stdin.read().strip()
        if not data:
            raise CLIError("no token received on stdin")
        return data

    env_token = os.environ.get(AUTH_TOKEN_ENV_VAR, "").strip()
    if env_token:
        return env_token

    if getattr(args, "no_prompt", False):
        raise CLIError(
            "no token provided; supply --token, --stdin, or set SWAIN_CLI_AUTH_TOKEN"
        )

    try:
        return obtain_token_from_user(allow_reuse=False)
    except InteractionAborted as exc:
        raise CLIError("login cancelled") from exc


def obtain_token_from_user(*, allow_reuse: bool) -> str:
    existing = resolve_auth_token()
    if existing and allow_reuse:
        log(f"authentication token detected ({mask_token(existing)})")
        if prompt_yes_no("Reuse this token?", default=True):
            return existing
        log("Enter a replacement token.")

    while True:
        try:
            token = getpass("Access token: ")
        except (EOFError, KeyboardInterrupt):
            print()
            raise InteractionAborted()

        token = token.strip()
        if not token:
            log_error("access token cannot be empty")
            continue
        return token


def handle_auth_login(args: argparse.Namespace) -> int:
    token = read_login_token(args)
    persist_auth_token(token)
    return 0


def handle_auth_logout(args: argparse.Namespace) -> int:
    clear_auth_state()
    log("removed stored access token")
    return 0


def handle_auth_status(args: argparse.Namespace) -> int:
    env_token = os.environ.get(AUTH_TOKEN_ENV_VAR, "").strip()
    config_path = auth_config_path()

    if env_token:
        log("auth token source: environment variable")
        log(f"effective token: {mask_token(env_token)}")
        return 0

    state = load_auth_state()
    if state.access_token:
        log("auth token source: stored credential")
        log(f"effective token: {mask_token(state.access_token)}")
        log(f"config file: {config_path}")
    else:
        log("auth token: not configured")
        log(f"config file: {config_path}")
    return 0


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

    schema_arg = getattr(args, "schema", None)
    crudsql_url = getattr(args, "crudsql_url", None)
    temp_schema: Optional[Path] = None

    try:
        if schema_arg:
            schema = schema_arg
            if not is_url(schema):
                schema_path = Path(schema)
                if not schema_path.exists():
                    raise CLIError(f"schema not found: {schema_path}")
                schema = str(schema_path)
        else:
            base_url = (crudsql_url or "").strip() or DEFAULT_CRUDSQL_BASE_URL
            token = require_auth_token("fetch the CrudSQL swagger document")
            temp_schema = fetch_crudsql_schema(base_url, token)
            schema = str(temp_schema)

        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)

        languages = args.languages
        if not languages:
            raise CLIError("at least one --lang is required")

        for lang in languages:
            resolved_lang, target_dir, cmd = build_generate_command(
                schema, lang, args, out_dir
            )

            log(f"generating {resolved_lang} into {target_dir}")
            rc = run_openapi_generator(jar, engine, cmd)
            if rc != 0:
                log_error(
                    f"generation failed for {resolved_lang} (exit code {rc})"
                )
                return rc if rc != 0 else EXIT_CODE_SUBPROCESS
    finally:
        if temp_schema:
            temp_schema.unlink(missing_ok=True)

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
        To use the system Java runtime, append '--engine system' to swain_cli commands.
        Example: swain_cli gen --engine system -i schema.yaml -l python -o sdks
        """
    ).strip()
    log(message)
    return 0


def handle_engine_use_embedded(args: argparse.Namespace) -> int:
    message = textwrap.dedent(
        """
        swain_cli uses the embedded runtime by default. To ensure it is ready, run:
          swain_cli engine install-jre
        You can explicitly select it with '--engine embedded'.
        """
    ).strip()
    log(message)
    return 0


def is_url(path: str) -> bool:
    return "://" in path


class InteractionAborted(Exception):
    """Raised when the interactive session is cancelled."""


def safe_input(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError as exc:
        raise InteractionAborted() from exc
    except KeyboardInterrupt as exc:
        print()
        raise InteractionAborted() from exc


def prompt_loop(
    prompt: str,
    *,
    default: Optional[str] = None,
    allow_empty: bool = False,
    validator: Optional[Callable[[str], Optional[str]]] = None,
) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        response = safe_input(f"{prompt}{suffix}: ").strip()
        if not response and default is not None:
            response = default
        if not response and not allow_empty:
            log_error("please enter a value")
            continue
        if validator:
            error = validator(response)
            if error:
                log_error(error)
                continue
        return response


def prompt_yes_no(prompt: str, *, default: bool) -> bool:
    default_str = "Y/n" if default else "y/N"
    while True:
        response = safe_input(f"{prompt} [{default_str}]: ").strip().lower()
        if not response:
            return default
        if response in {"y", "yes"}:
            return True
        if response in {"n", "no"}:
            return False
        log_error("please answer with 'y' or 'n'")


def interactive_auth_setup() -> None:
    existing = resolve_auth_token()
    if existing:
        if prompt_yes_no("Reuse the existing authentication token?", default=True):
            return
    else:
        log("no authentication token configured.")
        if not prompt_yes_no("Add an access token before continuing?", default=True):
            raise CLIError("authentication token required; run 'swain_cli auth login'")

    token = obtain_token_from_user(allow_reuse=False)
    persist_auth_token(token)


def guess_default_schema() -> Optional[Path]:
    for candidate in (
        Path("openapi.yaml"),
        Path("openapi.yml"),
        Path("swagger.yaml"),
        Path("swagger.yml"),
    ):
        if candidate.exists():
            return candidate
    return None


def format_cli_command(argv: Sequence[str]) -> str:
    return shlex.join(str(part) for part in argv)


def handle_interactive(args: argparse.Namespace) -> int:
    log("interactive SDK generation wizard")
    log("press Ctrl+C at any time to cancel")

    interactive_auth_setup()

    schema_default = guess_default_schema()

    def validate_schema(value: str) -> Optional[str]:
        if is_url(value):
            return None
        path = Path(value).expanduser()
        if not path.exists():
            return f"schema not found at {path}"
        return None

    schema_input: Optional[str] = None
    crudsql_base: Optional[str] = None

    try:
        if prompt_yes_no("Fetch schema from a CrudSQL backend?", default=True):
            def validate_crudsql_base(value: str) -> Optional[str]:
                try:
                    crudsql_dynamic_swagger_url(value)
                except CLIError as exc:
                    return str(exc)
                return None

            crudsql_base = prompt_loop(
                "CrudSQL base URL",
                default=DEFAULT_CRUDSQL_BASE_URL,
                validator=validate_crudsql_base,
            )
        else:
            schema_input = prompt_loop(
                "Schema path or URL",
                default=str(schema_default) if schema_default else None,
                validator=validate_schema,
            )

        out_default = "sdks"

        def validate_out_dir(value: str) -> Optional[str]:
            path = Path(value).expanduser()
            if path.exists() and not path.is_dir():
                return "output path exists and is not a directory"
            return None

        out_dir_input = prompt_loop(
            "Output directory",
            default=out_default,
            validator=validate_out_dir,
        )

        language_hint = ", ".join(COMMON_LANGUAGES)

        def parse_languages(raw: str) -> List[str]:
            entries = [
                item.strip()
                for item in raw.replace(";", ",").split(",")
                if item.strip()
            ]
            return entries

        def validate_languages(raw: str) -> Optional[str]:
            parsed = parse_languages(raw)
            if not parsed:
                return "please provide at least one language"
            return None

        languages_raw = prompt_loop(
            f"Target languages (comma separated, e.g. {language_hint})",
            default="python,typescript",
            validator=validate_languages,
        )
        languages = [lang.lower() for lang in parse_languages(languages_raw)]

        def validate_optional_file(value: str) -> Optional[str]:
            if not value:
                return None
            path = Path(value).expanduser()
            if not path.exists():
                return f"config file {path} does not exist"
            if not path.is_file():
                return f"config path {path} is not a file"
            return None

        config_input = prompt_loop(
            "Generator config file (optional)",
            allow_empty=True,
            validator=validate_optional_file,
        )
        config_value = str(Path(config_input).expanduser()) if config_input else None

        def validate_optional_dir(value: str) -> Optional[str]:
            if not value:
                return None
            path = Path(value).expanduser()
            if not path.exists():
                return f"templates directory {path} does not exist"
            if not path.is_dir():
                return f"templates path {path} is not a directory"
            return None

        templates_input = prompt_loop(
            "Custom templates directory (optional)",
            allow_empty=True,
            validator=validate_optional_dir,
        )
        templates_value = (
            str(Path(templates_input).expanduser()) if templates_input else None
        )

        additional_properties: List[str] = []
        if prompt_yes_no("Add additional properties (-p key=value) ?", default=False):
            log("enter key=value pairs; leave blank when finished")
            while True:
                entry = prompt_loop(
                    "Additional property",
                    allow_empty=True,
                )
                if not entry:
                    break
                if "=" not in entry:
                    log_error("enter values in key=value format")
                    continue
                additional_properties.append(entry)

        sys_props: List[str] = []
        if prompt_yes_no("Add system properties (-D key=value)?", default=False):
            log("enter key=value pairs; leave blank when finished")
            while True:
                entry = prompt_loop(
                    "System property",
                    allow_empty=True,
                )
                if not entry:
                    break
                sys_props.append(entry)

        generator_args: List[str] = []
        if prompt_yes_no("Add raw OpenAPI Generator args?", default=False):
            log("enter arguments exactly as OpenAPI Generator expects; blank to finish")
            while True:
                entry = prompt_loop("Generator argument", allow_empty=True)
                if not entry:
                    break
                generator_args.append(entry)

        engine_choice = "embedded" if prompt_yes_no(
            "Use embedded Java runtime?", default=True
        ) else "system"

        skip_validate = prompt_yes_no(
            "Skip OpenAPI spec validation?", default=False
        )
        verbose = prompt_yes_no("Enable verbose generator output?", default=False)

    except InteractionAborted:
        log_error("interactive session cancelled")
        return EXIT_CODE_INTERRUPT

    if crudsql_base:
        base_to_use = crudsql_base or DEFAULT_CRUDSQL_BASE_URL
        schema_value = crudsql_dynamic_swagger_url(base_to_use)
        schema_display = schema_value
    else:
        if schema_input is None:  # pragma: no cover - defensive guard
            raise CLIError("schema path or URL not provided")
        schema_value = (
            schema_input
            if is_url(schema_input)
            else str(Path(schema_input).expanduser())
        )
        schema_display = schema_value
    out_value = str(Path(out_dir_input).expanduser())

    log("configuration preview")
    if crudsql_base:
        log(f"  crudsql base: {crudsql_base}")
        log(f"  dynamic swagger: {schema_display}")
    else:
        log(f"  schema: {schema_display}")
    log(f"  output: {out_value}")
    log(f"  languages: {', '.join(languages)}")
    if config_value:
        log(f"  config: {config_value}")
    if templates_value:
        log(f"  templates: {templates_value}")
    if additional_properties:
        log(f"  additional properties: {additional_properties}")
    if sys_props:
        log(f"  system properties: {sys_props}")
    if generator_args:
        log(f"  extra generator args: {generator_args}")
    log(f"  engine: {engine_choice}")
    log(f"  skip validate: {skip_validate}")
    log(f"  verbose: {verbose}")

    command_preview: List[str] = ["swain_cli"]
    if args.generator_version:
        command_preview.extend(["--generator-version", args.generator_version])
    command_preview.append("gen")
    if crudsql_base:
        if crudsql_base != DEFAULT_CRUDSQL_BASE_URL:
            command_preview.extend(["--crudsql-url", crudsql_base])
    else:
        command_preview.extend(["-i", schema_value])
    command_preview.extend(["-o", out_value])
    for lang in languages:
        command_preview.extend(["-l", lang])
    if config_value:
        command_preview.extend(["-c", config_value])
    if templates_value:
        command_preview.extend(["-t", templates_value])
    for prop in additional_properties:
        command_preview.extend(["-p", prop])
    for arg in generator_args:
        command_preview.extend(["--generator-arg", arg])
    for sys_prop in sys_props:
        command_preview.extend(["-D", sys_prop])
    if skip_validate:
        command_preview.append("--skip-validate-spec")
    if verbose:
        command_preview.append("-v")
    if engine_choice != "embedded":
        command_preview.extend(["--engine", engine_choice])

    log(f"equivalent command: {format_cli_command(command_preview)}")

    if not prompt_yes_no("Run generation now?", default=True):
        log("generation skipped; run the command above when ready")
        return 0

    parser = build_parser()
    parsed_args = parser.parse_args(command_preview[1:])
    return parsed_args.func(parsed_args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="swain_cli CLI")
    parser.add_argument(
        "--generator-version",
        help="override the OpenAPI Generator version to use (must be cached)",
    )

    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    parser_interactive = subparsers.add_parser(
        "interactive", help="guided wizard to collect generator options"
    )
    parser_interactive.set_defaults(func=handle_interactive)

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

    parser_auth = subparsers.add_parser(
        "auth", help="manage authentication for swain_cli services"
    )
    auth_sub = parser_auth.add_subparsers(dest="auth_command")
    auth_sub.required = True

    parser_auth_login = auth_sub.add_parser(
        "login", help="store an access token for future commands"
    )
    parser_auth_login.add_argument(
        "--token",
        help="access token value (otherwise read from stdin, env, or prompt)",
    )
    parser_auth_login.add_argument(
        "--stdin",
        action="store_true",
        help="read the access token from standard input",
    )
    parser_auth_login.add_argument(
        "--no-prompt",
        action="store_true",
        help="fail instead of prompting when no token is provided",
    )
    parser_auth_login.set_defaults(func=handle_auth_login)

    parser_auth_logout = auth_sub.add_parser(
        "logout", help="remove any stored access token"
    )
    parser_auth_logout.set_defaults(func=handle_auth_logout)

    parser_auth_status = auth_sub.add_parser(
        "status", help="display current authentication status"
    )
    parser_auth_status.set_defaults(func=handle_auth_status)

    parser_gen = subparsers.add_parser(
        "gen", help="generate SDKs using OpenAPI Generator"
    )
    schema_group = parser_gen.add_mutually_exclusive_group()
    schema_group.add_argument(
        "-i", "--schema", help="schema path or URL"
    )
    schema_group.add_argument(
        "--crudsql-url",
        help=(
            "CrudSQL base URL to pull dynamic swagger (default: "
            f"{DEFAULT_CRUDSQL_BASE_URL})"
        ),
    )
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
