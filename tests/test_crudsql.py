import json

import pytest

import swain_cli.crudsql as crudsql
from swain_cli.errors import CLIError


def test_fetch_crudsql_schema_success(monkeypatch, tmp_path, fake_client, fake_response):
    discovery = fake_response(
        "https://api.example.com/api/schema-location",
        json_data={"schema_url": "/openapi/custom.json"},
        content=b"{}",
    )
    schema = fake_response(
        "https://api.example.com/openapi/custom.json",
        content=b'{"swagger": "2.0"}',
    )
    calls = []

    def fake_http_client(**kwargs):
        if not calls:
            return fake_client([discovery], calls)
        return fake_client([schema], calls)

    monkeypatch.setattr(crudsql.httpx, "Client", fake_http_client)
    temp_path = crudsql.fetch_crudsql_schema(
        "https://api.example.com",
        "token123",
        tenant_id="42",
    )
    try:
        data = json.loads(temp_path.read_text())
        assert data["swagger"] == "2.0"
    finally:
        temp_path.unlink(missing_ok=True)
    assert [entry[1] for entry in calls] == [
        "https://api.example.com/api/schema-location",
        "https://api.example.com/openapi/custom.json",
    ]
    discovery_headers = calls[0][2]
    assert discovery_headers["Authorization"] == "Bearer token123"
    assert discovery_headers["X-Tenant-ID"] == "42"
    schema_headers = calls[1][2]
    assert schema_headers["Authorization"] == "Bearer token123"
    assert schema_headers["X-Tenant-ID"] == "42"


def test_fetch_crudsql_schema_http_error(monkeypatch, fake_client, fake_response):
    response = fake_response(
        "https://api.example.com/api/schema-location",
        status_code=401,
        content=b"denied",
        reason="Unauthorized",
    )

    def fake_http_client(**kwargs):
        return fake_client([response])

    monkeypatch.setattr(crudsql.httpx, "Client", fake_http_client)
    with pytest.raises(CLIError) as excinfo:
        crudsql.fetch_crudsql_schema(
            "https://api.example.com",
            "token123",
            tenant_id="88",
        )
    assert "401" in str(excinfo.value)


def test_fetch_crudsql_schema_falls_back(monkeypatch, tmp_path, fake_client, fake_response):
    discovery = fake_response(
        "https://api.example.com/api/schema-location",
        status_code=404,
        content=b"missing",
        reason="Not Found",
    )
    schema = fake_response(
        "https://api.example.com/api/dynamic_swagger",
        content=b"{}",
    )

    worked_calls = []

    def fake_http_client(**kwargs):
        if not worked_calls:
            worked_calls.append("discovery")
            return fake_client([discovery])
        return fake_client([schema])

    monkeypatch.setattr(crudsql.httpx, "Client", fake_http_client)
    temp_path = crudsql.fetch_crudsql_schema(
        "https://api.example.com",
        "token123",
        tenant_id="55",
    )
    try:
        assert temp_path.read_text() == "{}"
    finally:
        temp_path.unlink(missing_ok=True)

