"""Plugin loading and extension hooks for swain_cli."""

from __future__ import annotations

import importlib.metadata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple, cast

from .args import GenArgs
from .context import AppContext
from .errors import CLIError

PLUGIN_GROUP = "swain_cli.plugins"


@dataclass(frozen=True)
class PluginInfo:
    name: str
    value: str


@dataclass(frozen=True)
class PluginSchemaResult:
    schema: str
    temp_path: Optional[Path] = None


class SwainCLIPlugin(Protocol):
    """Optional plugin surface (implement any subset)."""

    def resolve_schema(
        self,
        args: GenArgs,
        *,
        swain_base: str,
        crudsql_base: str,
        ctx: Optional[AppContext],
    ) -> Optional[PluginSchemaResult]: ...


def _iter_entry_points(group: str) -> List[importlib.metadata.EntryPoint]:
    entry_points = importlib.metadata.entry_points()
    if hasattr(entry_points, "select"):
        return list(entry_points.select(group=group))
    return [
        ep
        for ep in cast(Iterable[importlib.metadata.EntryPoint], entry_points)
        if ep.group == group
    ]


def list_plugins() -> List[PluginInfo]:
    infos: List[PluginInfo] = []
    for ep in _iter_entry_points(PLUGIN_GROUP):
        infos.append(PluginInfo(name=ep.name, value=ep.value))
    return infos


@lru_cache()
def load_plugins() -> Dict[str, Any]:
    plugins: Dict[str, Any] = {}
    errors = _load_plugin_errors()
    for ep in _iter_entry_points(PLUGIN_GROUP):
        if ep.name in errors:
            continue
        try:
            plugins[ep.name] = ep.load()
        except Exception as exc:
            errors[ep.name] = f"{exc}"
    return plugins


@lru_cache()
def _load_plugin_errors() -> Dict[str, str]:
    return {}


def plugin_load_errors() -> Dict[str, str]:
    return dict(_load_plugin_errors())


def plugin_statuses() -> List[Tuple[PluginInfo, Optional[str]]]:
    """
    Return (PluginInfo, error) tuples for discovered plugins.

    error is populated when a plugin failed to import/load.
    """
    infos = list_plugins()
    loaded = load_plugins()
    errors = _load_plugin_errors()
    statuses: List[Tuple[PluginInfo, Optional[str]]] = []
    for info in infos:
        error = errors.get(info.name)
        if info.name in loaded:
            error = None
        statuses.append((info, error))
    return statuses


def resolve_schema_with_plugins(
    args: GenArgs,
    *,
    swain_base: str,
    crudsql_base: str,
    ctx: Optional[AppContext],
) -> Optional[PluginSchemaResult]:
    for name, plugin in load_plugins().items():
        resolver = getattr(plugin, "resolve_schema", None)
        if not callable(resolver):
            continue
        try:
            result = resolver(
                args,
                swain_base=swain_base,
                crudsql_base=crudsql_base,
                ctx=ctx,
            )
        except Exception as exc:
            raise CLIError(f"plugin {name!r} failed to resolve schema: {exc}") from exc
        if result is not None:
            return result
    return None
