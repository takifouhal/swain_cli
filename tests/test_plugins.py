from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable, Dict, Optional

import pytest

import swain_cli.plugins as plugins
from swain_cli.args import GenArgs
from swain_cli.errors import CLIError
from swain_cli.plugins import PluginInfo, PluginSchemaResult


@dataclass
class DummyEntryPoint:
    name: str
    value: str
    loader: Callable[[], Any]

    def load(self) -> Any:
        return self.loader()


def _clear_plugin_caches() -> None:
    plugins.load_plugins.cache_clear()
    plugins._load_plugin_errors.cache_clear()  # type: ignore[attr-defined]


def test_list_plugins(monkeypatch) -> None:
    _clear_plugin_caches()

    entry_points = [
        DummyEntryPoint("alpha", "pkg.alpha:plugin", lambda: object()),
        DummyEntryPoint("beta", "pkg.beta:plugin", lambda: object()),
    ]
    monkeypatch.setattr(plugins, "_iter_entry_points", lambda group: entry_points)

    assert plugins.list_plugins() == [
        PluginInfo(name="alpha", value="pkg.alpha:plugin"),
        PluginInfo(name="beta", value="pkg.beta:plugin"),
    ]


def test_plugin_statuses_records_load_errors(monkeypatch) -> None:
    _clear_plugin_caches()

    def bad_loader() -> Any:
        raise RuntimeError("boom")

    entry_points = [DummyEntryPoint("bad", "pkg.bad:plugin", bad_loader)]
    monkeypatch.setattr(plugins, "_iter_entry_points", lambda group: entry_points)

    statuses = plugins.plugin_statuses()
    assert len(statuses) == 1
    info, error = statuses[0]
    assert info.name == "bad"
    assert error is not None
    assert "boom" in error


def test_resolve_schema_with_plugins_returns_first_match(monkeypatch) -> None:
    def make_plugin(result: Optional[PluginSchemaResult]) -> Any:
        def resolve_schema(
            _args: GenArgs,
            *,
            swain_base: str,
            crudsql_base: str,
            ctx: Any,
        ) -> Optional[PluginSchemaResult]:
            _ = swain_base, crudsql_base, ctx
            return result

        return SimpleNamespace(resolve_schema=resolve_schema)

    plugin_map: Dict[str, Any] = {
        "a": make_plugin(None),
        "b": make_plugin(PluginSchemaResult(schema="file:///tmp/schema.json")),
        "c": make_plugin(PluginSchemaResult(schema="file:///tmp/ignored.json")),
    }
    monkeypatch.setattr(plugins, "load_plugins", lambda: plugin_map)

    args = GenArgs(out="out", languages=["python"])
    result = plugins.resolve_schema_with_plugins(
        args,
        swain_base="https://api.example.com",
        crudsql_base="https://api.example.com/crud",
        ctx=None,
    )
    assert result is not None
    assert result.schema == "file:///tmp/schema.json"


def test_resolve_schema_with_plugins_wraps_exceptions(monkeypatch) -> None:
    def resolve_schema(
        _args: GenArgs,
        *,
        swain_base: str,
        crudsql_base: str,
        ctx: Any,
    ) -> Optional[PluginSchemaResult]:
        _ = swain_base, crudsql_base, ctx
        raise ValueError("bad news")

    monkeypatch.setattr(
        plugins,
        "load_plugins",
        lambda: {"bad": SimpleNamespace(resolve_schema=resolve_schema)},
    )

    args = GenArgs(out="out", languages=["python"])
    with pytest.raises(CLIError) as excinfo:
        plugins.resolve_schema_with_plugins(
            args,
            swain_base="https://api.example.com",
            crudsql_base="https://api.example.com/crud",
            ctx=None,
        )
    assert "plugin 'bad'" in str(excinfo.value)
