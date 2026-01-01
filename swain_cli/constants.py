"""Shared constants for swain_cli."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

PINNED_GENERATOR_VERSION = "7.6.0"
PINNED_GENERATOR_SHA256 = "35074bdd3cdfc46be9a902e11a54a3faa3cae1e34eb66cbd959d1c8070bbd7d7"
# JRE assets were renamed after v0.3.0; use v0.3.2 where
# the filenames match entries in JRE_ASSETS.
ASSET_BASE = "https://github.com/takifouhal/swain_cli/releases/download/v0.3.2"
PACKAGE_NAME = "swain_cli"

CACHE_ENV_VAR = "SWAIN_CLI_CACHE_DIR"
DEFAULT_CACHE_DIR_NAME = "swain_cli"
AUTH_TOKEN_ENV_VAR = "SWAIN_CLI_AUTH_TOKEN"
ENGINE_ENV_VAR = "SWAIN_CLI_ENGINE"
GENERATOR_VERSION_ENV_VAR = "SWAIN_CLI_GENERATOR_VERSION"
TENANT_ID_ENV_VAR = "SWAIN_CLI_TENANT_ID"
TENANT_HEADER_NAME = "X-Tenant-ID"

KEYRING_SERVICE = "swain_cli"
KEYRING_USERNAME = "access_token"
KEYRING_REFRESH_USERNAME = "refresh_token"

JAVA_OPTS_ENV_VAR = "SWAIN_CLI_JAVA_OPTS"
DEFAULT_JAVA_OPTS = ["-Xms2g", "-Xmx10g", "-XX:+UseG1GC"]
FALLBACK_JAVA_HEAP_OPTION = "-Xmx14g"
OOM_MARKERS = ("OutOfMemoryError", "GC overhead limit exceeded")

GLOBAL_PROPERTY_DISABLE_DOCS = "apiDocs=false,apiTests=false,modelDocs=false,modelTests=false"
SKIP_OPERATION_EXAMPLE_FLAG = "--skip-operation-example"

DEFAULT_SWAIN_BASE_URL = "https://api.swain.technology"
DEFAULT_CRUDSQL_API_BASE_URL = f"{DEFAULT_SWAIN_BASE_URL.rstrip('/')}/crud"

EXIT_CODE_SUBPROCESS = 1
EXIT_CODE_USAGE = 2
EXIT_CODE_INTERRUPT = 130

LANGUAGE_ALIASES = {"typescript": "typescript-axios"}
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

HTTP_TIMEOUT_SECONDS = 30.0
JRE_MARKER_FILENAME = ".swain_cli_jre_asset_sha256"


@dataclass(frozen=True)
class JREAsset:
    filename: str
    sha256: Optional[str]
    checksum_filename: Optional[str] = None


JRE_ASSETS: Dict[Tuple[str, str], JREAsset] = {
    ("linux", "x86_64"): JREAsset(
        "swain_cli-jre-linux-x86_64.tar.gz",
        "e31f7c29d501ea038080ae39495699493105331e004bc9f8920d4f0454e809b0",
        "swain_cli-jre-linux-x86_64.tar.gz.sha256",
    ),
    ("linux", "arm64"): JREAsset(
        "swain_cli-jre-linux-arm64.tar.gz",
        "60340b7b8e5ed66a0d90e4a9645a4ca84f8e202fc181a10fbfc8a17b0bef0706",
        "swain_cli-jre-linux-arm64.tar.gz.sha256",
    ),
    ("macos", "x86_64"): JREAsset(
        "swain_cli-jre-macos-x86_64.tar.gz",
        "9322927079799a49322a708836c6150c2c699d2b8dab160666197a44c838a396",
        "swain_cli-jre-macos-x86_64.tar.gz.sha256",
    ),
    ("macos", "arm64"): JREAsset(
        "swain_cli-jre-macos-arm64.tar.gz",
        "770b81834bdcb70b9af0fe6c7b5e24ed287553f91380e543862e59f9bb72f9ea",
        "swain_cli-jre-macos-arm64.tar.gz.sha256",
    ),
    ("windows", "x86_64"): JREAsset(
        "swain_cli-jre-windows-x86_64.zip",
        "3d359a6c4631bcc891635b2ee8a541b44ac7c11a608db40d0a8d579fa999aa57",
        "swain_cli-jre-windows-x86_64.zip.sha256",
    ),
}
