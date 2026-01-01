"""Shared utility helpers for swain_cli."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Dict, Optional, Sequence


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
