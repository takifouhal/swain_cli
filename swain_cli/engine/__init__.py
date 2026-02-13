"""Embedded engine (JRE + OpenAPI Generator) management for swain_cli."""

from __future__ import annotations

# ruff: noqa: F401
from .archives import extract_archive
from .checksums import (
    _digest,
    _parse_checksum_text,
    _sha256_digest,
    _verify_digest,
    _verify_sha256,
    parse_checksum_file,
)
from .core import (
    PlatformInfo,
    _env_truthy,
    asset_base_url,
    cache_lock,
    cache_lock_path,
    cache_root,
    downloads_dir,
    get_platform_info,
    jar_cache_dir,
    jre_install_dir,
    normalize_arch,
    normalize_os,
)
from .downloads import HTTPX_DOWNLOADER, HTTPXDownloader
from .handlers import (
    handle_engine_clean,
    handle_engine_install_jre,
    handle_engine_paths,
    handle_engine_prune_jars,
    handle_engine_status,
    handle_engine_update_jar,
    handle_engine_use_embedded,
    handle_engine_use_system,
    handle_list_generators,
)
from .jar import (
    ensure_generator_jar,
    fetch_maven_checksum,
    list_cached_jars,
    resolve_generator_jar,
)
from .jre import (
    checksum_filename,
    ensure_embedded_jre,
    fetch_asset_file,
    find_embedded_java,
    get_jre_asset,
    java_binary_name,
    normalize_runtime_dir,
    read_jre_marker,
    resolve_asset_sha256,
    write_jre_marker,
)
from .run import (
    ResolvedJavaOptions,
    resolve_java_opts,
    resolve_java_runtime,
    run_openapi_generator,
    run_openapi_generator_prepared,
)
from .snapshot import EngineSnapshot, collect_engine_snapshot, emit_engine_snapshot
