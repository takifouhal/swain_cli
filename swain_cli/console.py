"""Console helpers for swain_cli."""

from __future__ import annotations

import sys


def log(message: str) -> None:
    print(f"[swain_cli] {message}")


def log_error(message: str) -> None:
    print(f"[swain_cli] {message}", file=sys.stderr)
