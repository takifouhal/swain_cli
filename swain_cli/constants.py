"""Shared constants for swain_cli."""

from __future__ import annotations

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
