from __future__ import annotations

import swain_cli.generator as generator
import swain_cli.schema_cache as schema_cache
import swain_cli.swain_api as swain_api
from swain_cli.args import GenArgs


def test_schema_cache_key_normalizes_trailing_slash_for_crudsql(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(generator, "require_auth_token", lambda purpose="": "token")
    monkeypatch.setattr(
        generator,
        "determine_swain_tenant_id",
        lambda base, token, provided, *, allow_prompt: "1",
    )
    monkeypatch.setattr(generator, "get_cached_schema_path", lambda *a, **k: None)
    monkeypatch.setattr(generator, "put_cached_schema", lambda *a, **k: None)

    created = []

    def fake_fetch(base, token, tenant_id=None):
        path = tmp_path / f"schema_{len(created)}.json"
        path.write_text("{}", encoding="utf-8")
        created.append(path)
        return path

    monkeypatch.setattr(generator, "fetch_crudsql_schema", fake_fetch)

    payloads = []
    keys = []

    def capture(payload):
        payloads.append(payload)
        key = schema_cache.schema_cache_key(payload)
        keys.append(key)
        return key

    monkeypatch.setattr(generator, "schema_cache_key", capture)

    args = GenArgs(
        out=str(tmp_path / "out"),
        languages=["python"],
        schema_cache_ttl="60",
    )

    generator.resolve_schema_for_generation(args, "https://api.example.com", "https://api.example.com/crud/")
    generator.resolve_schema_for_generation(args, "https://api.example.com", "https://api.example.com/crud")

    assert len(keys) == 2
    assert keys[0] == keys[1]
    assert payloads[0]["crudsql_base_url"] == "https://api.example.com/crud"
    assert payloads[1]["crudsql_base_url"] == "https://api.example.com/crud"


def test_schema_cache_key_normalizes_trailing_slash_for_swain(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(generator, "require_auth_token", lambda purpose="": "token")
    monkeypatch.setattr(
        generator,
        "determine_swain_tenant_id",
        lambda base, token, provided, *, allow_prompt: "1",
    )
    monkeypatch.setattr(generator, "get_cached_schema_path", lambda *a, **k: None)
    monkeypatch.setattr(generator, "put_cached_schema", lambda *a, **k: None)

    connection = swain_api.SwainConnection(
        id=123,
        database_name=None,
        driver=None,
        stage=None,
        project_name="Alpha",
        schema_name="public",
        build_id=99,
        build_endpoint=None,
        connection_endpoint=None,
        raw={"id": 123},
    )
    monkeypatch.setattr(generator, "resolve_swain_connection", lambda **_kwargs: connection)

    created = []

    def fake_fetch_schema(base, conn, token, tenant_id=None):
        _ = base, conn, token, tenant_id
        path = tmp_path / f"schema_{len(created)}.json"
        path.write_text("{}", encoding="utf-8")
        created.append(path)
        return path

    monkeypatch.setattr(generator, "fetch_swain_connection_schema", fake_fetch_schema)

    payloads = []
    keys = []

    def capture(payload):
        payloads.append(payload)
        key = schema_cache.schema_cache_key(payload)
        keys.append(key)
        return key

    monkeypatch.setattr(generator, "schema_cache_key", capture)

    args = GenArgs(
        out=str(tmp_path / "out"),
        languages=["python"],
        swain_connection_id=connection.id,
        schema_cache_ttl="60",
    )

    generator.resolve_schema_for_generation(args, "https://api.example.com/", "https://api.example.com/crud")
    generator.resolve_schema_for_generation(args, "https://api.example.com", "https://api.example.com/crud")

    assert len(keys) == 2
    assert keys[0] == keys[1]
    assert payloads[0]["swain_base_url"] == "https://api.example.com"
    assert payloads[1]["swain_base_url"] == "https://api.example.com"
