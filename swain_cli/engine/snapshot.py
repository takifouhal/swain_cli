"""Engine snapshot helpers (report embedded/runtime state)."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..console import log, log_error
from ..errors import CLIError
from .core import PlatformInfo, get_platform_info, jre_install_dir
from .jar import list_cached_jars, resolve_generator_jar
from .jre import find_embedded_java


@dataclass
class EngineSnapshot:
    platform: PlatformInfo
    runtime_dir: Path
    embedded_java: Optional[Path]
    selected_generator: Optional[Path]
    selected_generator_error: Optional[str]
    cached_jars: List[str]
    system_java: Optional[str]


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
    log(
        f"embedded java: {snapshot.embedded_java if snapshot.embedded_java else 'not installed'}"
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
    log(f"system java: {snapshot.system_java if snapshot.system_java else 'not found'}")
