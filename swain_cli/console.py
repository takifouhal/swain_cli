"""Console helpers for swain_cli."""

from __future__ import annotations

import sys
from contextlib import contextmanager
from typing import Iterator

_LOG_TO_STDERR = False
_LOG_SILENCED = False


def configure_console(*, quiet: bool = False, stderr: bool = False) -> None:
    global _LOG_TO_STDERR, _LOG_SILENCED
    if stderr:
        _LOG_TO_STDERR = True
    if quiet:
        _LOG_SILENCED = True


def log(message: str) -> None:
    if _LOG_SILENCED:
        return
    stream = sys.stderr if _LOG_TO_STDERR else sys.stdout
    print(f"[swain_cli] {message}", file=stream)


def log_error(message: str) -> None:
    print(f"[swain_cli] {message}", file=sys.stderr)


@contextmanager
def logs_to_stderr() -> Iterator[None]:
    global _LOG_TO_STDERR
    previous = _LOG_TO_STDERR
    _LOG_TO_STDERR = True
    try:
        yield
    finally:
        _LOG_TO_STDERR = previous


@contextmanager
def suppress_logs() -> Iterator[None]:
    global _LOG_SILENCED
    previous = _LOG_SILENCED
    _LOG_SILENCED = True
    try:
        yield
    finally:
        _LOG_SILENCED = previous
