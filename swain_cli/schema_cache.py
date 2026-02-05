"""Schema fetch caching helpers (opt-in)."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .engine import cache_root
from .errors import CLIError


def parse_ttl_seconds(value: str) -> int:
    raw = (value or "").strip().lower()
    if not raw:
        raise CLIError("schema cache ttl is empty")
    if raw.isdigit():
        return int(raw)
    units = {"s": 1, "m": 60, "h": 60 * 60, "d": 60 * 60 * 24}
    suffix = raw[-1]
    if suffix not in units:
        raise CLIError(
            "invalid schema cache ttl; use seconds (e.g. 60) or a unit suffix like 10m/2h"
        )
    number = raw[:-1].strip()
    if not number or not number.isdigit():
        raise CLIError(
            "invalid schema cache ttl; use seconds (e.g. 60) or a unit suffix like 10m/2h"
        )
    return int(number) * units[suffix]


def schema_cache_dir(*, create: bool = True) -> Path:
    path = cache_root(create=create) / "schemas"
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def schema_cache_key(payload: Dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def schema_cache_path(key: str) -> Path:
    return schema_cache_dir(create=True) / f"{key}.json"


def get_cached_schema_path(key: str, ttl_seconds: int) -> Optional[Path]:
    if ttl_seconds <= 0:
        return None
    path = schema_cache_dir(create=False) / f"{key}.json"
    try:
        stat = path.stat()
    except FileNotFoundError:
        return None
    age = time.time() - stat.st_mtime
    if age > ttl_seconds:
        try:
            path.unlink()
        except OSError:
            pass
        return None
    return path


def put_cached_schema(key: str, data: bytes) -> Path:
    target = schema_cache_path(key)
    tmp = target.with_suffix(".json.tmp")
    try:
        tmp.write_bytes(data)
        tmp.replace(target)
    except OSError as exc:
        raise CLIError(f"failed to write schema cache entry {target}: {exc}") from exc
    return target

