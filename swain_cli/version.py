"""Version helpers for swain_cli."""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as metadata_version

from .constants import PACKAGE_NAME, PINNED_GENERATOR_VERSION


@lru_cache()
def cli_version() -> str:
    try:
        return metadata_version(PACKAGE_NAME)
    except PackageNotFoundError:
        try:
            from . import __version__
        except Exception:
            return "0.0.0"
        return __version__


USER_AGENT = f"{PACKAGE_NAME}/{cli_version()} (openapi-generator/{PINNED_GENERATOR_VERSION})"
