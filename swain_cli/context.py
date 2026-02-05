"""Application context for injectable dependencies."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

import httpx

from .http import http_timeout

if TYPE_CHECKING:  # pragma: no cover
    from .config import ConfigFile


HttpClientFactory = Callable[[httpx.Timeout], httpx.Client]


def default_http_client_factory(timeout: httpx.Timeout) -> httpx.Client:
    return httpx.Client(timeout=timeout, follow_redirects=True)


@dataclass(frozen=True)
class AppContext:
    """Shared dependencies for CLI flows (HTTP, config, filesystem paths)."""

    config: Optional["ConfigFile"] = None
    config_path: Optional[Path] = None
    http_client_factory: HttpClientFactory = default_http_client_factory

    def new_http_client(self, timeout: Optional[httpx.Timeout] = None) -> httpx.Client:
        return self.http_client_factory(timeout or http_timeout())

