from __future__ import annotations

import httpx

import swain_cli.auth as auth
import swain_cli.auth.remote as auth_remote
import swain_cli.crudsql as crudsql
import swain_cli.swain_api as swain_api
from swain_cli.context import AppContext


def test_swain_api_uses_ctx_http_client_factory(monkeypatch) -> None:
    class DummyClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            _ = exc_type, exc, tb
            return False

    dummy = DummyClient()

    def factory(_timeout: httpx.Timeout):
        return dummy

    ctx = AppContext(http_client_factory=factory)

    monkeypatch.setattr(swain_api, "default_http_client_factory", lambda _timeout: (_ for _ in ()).throw(AssertionError()))

    def fake_request_with_retries(client, method, url, *, headers=None, params=None, json=None, **kwargs):
        _ = headers, params, json, kwargs
        assert client is dummy
        request = httpx.Request(method, str(url))
        return httpx.Response(200, request=request, content=b'{"data": [], "totalPages": 1}')

    monkeypatch.setattr(swain_api, "request_with_retries", fake_request_with_retries)

    projects = swain_api.fetch_swain_projects(
        "https://api.example.com",
        "token",
        tenant_id="1",
        ctx=ctx,
    )
    assert projects == []


def test_crudsql_uses_ctx_http_client_factory(monkeypatch) -> None:
    class DummyClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            _ = exc_type, exc, tb
            return False

    dummy = DummyClient()

    def factory(_timeout: httpx.Timeout):
        return dummy

    ctx = AppContext(http_client_factory=factory)

    monkeypatch.setattr(crudsql, "default_http_client_factory", lambda _timeout: (_ for _ in ()).throw(AssertionError()))

    calls = {"count": 0}

    def fake_request_with_retries(client, method, url, *, headers=None, params=None, json=None, **kwargs):
        _ = headers, params, json, kwargs
        assert client is dummy
        calls["count"] += 1
        url_str = str(url)
        request = httpx.Request(method, url_str)
        if url_str.endswith("/api/schema-location"):
            return httpx.Response(404, request=request, content=b"")
        return httpx.Response(200, request=request, content=b"{}")

    monkeypatch.setattr(crudsql, "request_with_retries", fake_request_with_retries)

    path = crudsql.fetch_crudsql_schema(
        "https://api.example.com/crud",
        "token",
        tenant_id="1",
        ctx=ctx,
    )
    assert calls["count"] == 2
    assert path.read_text(encoding="utf-8") == "{}"


def test_auth_uses_ctx_http_client_factory(monkeypatch) -> None:
    class DummyClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            _ = exc_type, exc, tb
            return False

        def post(self, url, headers=None, json=None):
            _ = headers
            assert str(url).endswith("/auth/login")
            assert json == {"username": "user", "password": "pass"}
            request = httpx.Request("POST", str(url))
            return httpx.Response(200, request=request, content=b'{"token": "abc"}')

    dummy = DummyClient()

    def factory(_timeout: httpx.Timeout):
        return dummy

    ctx = AppContext(http_client_factory=factory)

    monkeypatch.setattr(auth_remote, "default_http_client_factory", lambda _timeout: (_ for _ in ()).throw(AssertionError()))

    payload = auth.swain_login_with_credentials(
        "https://api.example.com",
        "user",
        "pass",
        ctx=ctx,
    )
    assert payload["token"] == "abc"
