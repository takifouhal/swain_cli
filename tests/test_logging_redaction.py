from pathlib import Path

import httpx

import swain_cli.crudsql as crudsql


def test_fetch_crudsql_schema_redacts_url_in_log_output(monkeypatch, capfd) -> None:
    schema_url = "https://api.example.com/dynamic-swagger?token=secret"

    monkeypatch.setattr(crudsql, "crudsql_discover_schema_url", lambda *a, **k: schema_url)

    class DummyClient:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            _ = exc_type, exc, tb
            return False

    monkeypatch.setattr(crudsql, "default_http_client_factory", lambda timeout: DummyClient())

    def fake_request_with_retries(client, method, url, *, headers=None, params=None, json=None, **kwargs):
        _ = client, headers, params, json, kwargs
        request = httpx.Request(method, str(url))
        return httpx.Response(200, request=request, content=b"{}")

    monkeypatch.setattr(crudsql, "request_with_retries", fake_request_with_retries)

    _path = crudsql.fetch_crudsql_schema("https://api.example.com", "token", tenant_id="1")
    assert isinstance(_path, Path)

    captured, _ = capfd.readouterr()
    assert "token=secret" not in captured
    assert "token=***" in captured
