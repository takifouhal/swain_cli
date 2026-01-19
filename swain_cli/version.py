"""Version helpers for swain_cli."""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as metadata_version

from .constants import PACKAGE_NAME, PINNED_GENERATOR_VERSION


@lru_cache()
def cli_version() -> str:
    try:
        from . import __version__
    except Exception:
        __version__ = ""

    if isinstance(__version__, str) and __version__.strip():
        return __version__

    try:
        return metadata_version(PACKAGE_NAME)
    except PackageNotFoundError:
        return "0.0.0"


USER_AGENT = f"{PACKAGE_NAME}/{cli_version()} (openapi-generator/{PINNED_GENERATOR_VERSION})"
