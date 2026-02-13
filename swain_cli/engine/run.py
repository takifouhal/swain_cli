"""Java runtime resolution and OpenAPI Generator subprocess execution."""

from __future__ import annotations

import os
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

from ..console import log
from ..constants import DEFAULT_JAVA_OPTS, JAVA_OPTS_ENV_VAR
from ..errors import CLIError
from ..subprocess_runner import run_subprocess
from ..utils import format_cli_command, redact
from .jre import ensure_embedded_jre, find_embedded_java


@dataclass(frozen=True)
class ResolvedJavaOptions:
    options: List[str]
    provided: bool


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


def resolve_java_runtime(engine: str) -> Tuple[str, Dict[str, str]]:
    """Resolve the Java command/env for generator execution.

    This is useful when running multiple generators (e.g. parallel language
    generation) so the embedded JRE resolution + environment setup can be done
    once and reused.
    """

    if engine not in {"embedded", "system"}:
        raise CLIError(f"unknown engine '{engine}'")

    env = os.environ.copy()
    if engine == "embedded":
        runtime_dir = ensure_embedded_jre()
        java_exec_path = find_embedded_java(runtime_dir)
        if not java_exec_path:
            raise CLIError(
                "embedded JRE is not installed; run 'swain_cli engine install-jre'"
            )
        env["JAVA_HOME"] = str(runtime_dir)
        return str(java_exec_path), env

    java_exec = shutil.which("java")
    if not java_exec:
        raise CLIError(
            "java executable not found in PATH; install Java or use embedded engine"
        )
    return java_exec, env


def run_openapi_generator_prepared(
    java_cmd: str,
    env: Dict[str, str],
    jar: Path,
    generator_args: Sequence[str],
    java_opts: Sequence[str],
    *,
    stream: bool = True,
) -> Tuple[int, str]:
    cmd = [java_cmd, *list(java_opts), "-jar", str(jar), *list(generator_args)]
    log(f"exec {redact(format_cli_command(cmd))}")
    # Copy env so callers can reuse their prepared dict safely.
    return run_subprocess(
        cmd,
        env=dict(env),
        stream=stream,
        max_capture_chars=200_000,
    )


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
            raise CLIError(
                "embedded JRE is not installed; run 'swain_cli engine install-jre'"
            )
        java_cmd = str(java_exec_path)
        env = os.environ.copy()
        env["JAVA_HOME"] = str(runtime_dir)
    else:
        java_exec = shutil.which("java")
        if not java_exec:
            raise CLIError(
                "java executable not found in PATH; install Java or use embedded engine"
            )
        java_cmd = java_exec
        env = os.environ.copy()
    cmd = [java_cmd, *java_options, "-jar", str(jar), *generator_args]
    log(f"exec {redact(format_cli_command(cmd))}")
    return run_subprocess(cmd, env=env, stream=stream, max_capture_chars=200_000)
