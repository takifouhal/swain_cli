"""Shared utility helpers for swain_cli."""

from __future__ import annotations

import re
import shlex
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .errors import CLIError


def is_url(path: str) -> bool:
    return "://" in path


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


_SENSITIVE_KV_PATTERN = re.compile(
    r"(?i)\b("
    r"token|access_token|refresh_token|password|passwd|secret|api_key|apikey"
    r")\b\s*([:=])\s*([^\s]+)"
)
_AUTH_HEADER_PATTERN = re.compile(r"(?i)\bAuthorization:\s*Bearer\s+([^\s]+)")
_JWT_PATTERN = re.compile(
    r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)


def redact(text: str) -> str:
    """Best-effort redaction for common secret patterns in logs."""
    value = str(text)
    value = _AUTH_HEADER_PATTERN.sub("Authorization: Bearer ***", value)
    value = _SENSITIVE_KV_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}***", value)
    value = _JWT_PATTERN.sub("***", value)
    return value


def redact_cli_args(argv: Sequence[str]) -> List[str]:
    return [redact(str(part)) for part in argv]


def write_bytes_to_tempfile(
    data: bytes,
    *,
    suffix: str = "",
    description: str = "temporary file",
) -> Path:
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            delete=False,
            suffix=suffix,
        ) as handle:
            handle.write(data)
            return Path(handle.name)
    except OSError as exc:
        raise CLIError(f"failed to persist {description}: {exc}") from exc


def safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        if isinstance(value, bool):
            return int(value)
        return int(str(value))
    except (TypeError, ValueError):
        return None


def safe_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def as_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def pick(mapping: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


_safe_int = safe_int
_safe_str = safe_str
_as_dict = as_dict
_pick = pick
