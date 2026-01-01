from typing import Any, List

import pytest

import swain_cli.swain_api as swain_api
from swain_cli.errors import CLIError


def test_fetch_swain_projects_parses_pages(monkeypatch, fake_client, fake_response):
    page1 = fake_response(
        "https://api.example.com/api/Project",
        json_data={
            "data": [{"id": 1, "name": "Alpha"}],
            "total_pages": 2,
        },
        content=b"{}",
    )
    page2 = fake_response(
        "https://api.example.com/api/Project",
        json_data={
            "data": [{"id": 2, "name": "Beta"}],
            "total_pages": 2,
        },
        content=b"{}",
    )
    calls: List[Any] = []

    def fake_http_client(**kwargs):
        return fake_client([page1, page2], calls)

    monkeypatch.setattr(swain_api.httpx, "Client", fake_http_client)
    projects = swain_api.fetch_swain_projects(
        "https://api.example.com",
        "token",
        tenant_id="999",
    )
    assert [project.id for project in projects] == [1, 2]
    assert calls[0][0] == "GET"
    assert calls[0][3]["page"] == 1
    assert calls[1][3]["page"] == 2
    assert calls[0][2]["X-Tenant-ID"] == "999"
    assert calls[1][2]["X-Tenant-ID"] == "999"


def test_fetch_swain_projects_with_fallback_on_404(monkeypatch, fake_client, fake_response):
    primary = fake_response(
        "https://primary.example.com/api/Project",
        status_code=404,
        content=b"missing",
        reason="Not Found",
    )
    fallback = fake_response(
        "https://fallback.example.com/api/Project",
        json_data={
            "data": [{"id": 1, "name": "Alpha"}],
            "total_pages": 1,
        },
        content=b"{}",
    )
    calls: List[Any] = []
    clients = [
        fake_client([primary], calls),
        fake_client([fallback], calls),
    ]

    def fake_http_client(**kwargs):
        return clients.pop(0)

    monkeypatch.setattr(swain_api.httpx, "Client", fake_http_client)
    projects = swain_api.fetch_swain_projects_with_fallback(
        "https://primary.example.com",
        "https://fallback.example.com",
        "token",
        tenant_id="1",
    )
    assert [project.id for project in projects] == [1]
    assert [entry[1] for entry in calls] == [
        "https://primary.example.com/api/Project",
        "https://fallback.example.com/api/Project",
    ]


def test_fetch_swain_projects_with_fallback_does_not_retry_on_401(
    monkeypatch, fake_client, fake_response
):
    primary = fake_response(
        "https://primary.example.com/api/Project",
        status_code=401,
        content=b"denied",
        reason="Unauthorized",
    )
    calls: List[Any] = []

    def fake_http_client(**kwargs):
        return fake_client([primary], calls)

    monkeypatch.setattr(swain_api.httpx, "Client", fake_http_client)
    with pytest.raises(CLIError):
        swain_api.fetch_swain_projects_with_fallback(
            "https://primary.example.com",
            "https://fallback.example.com",
            "token",
            tenant_id="1",
        )
    assert len(calls) == 1


def test_fetch_swain_connections_parses_payload(monkeypatch, fake_client, fake_response):
    response = fake_response(
        "https://api.example.com/api/Connection/filter",
        json_data={
            "data": [
                {
                    "id": 55,
                    "dbname": "analytics",
                    "driver": "postgres",
                    "stage": {"name": "prod"},
                    "project": {"name": "Alpha"},
                    "current_schema": {
                        "name": "public",
                        "current_build": {
                            "id": 7,
                            "api_endpoint": "https://build.example.com",
                        },
                    },
                    "api_endpoint": "https://connection.example.com",
                }
            ]
        },
        content=b"{}",
    )
    calls: List[Any] = []

    def fake_http_client(**kwargs):
        return fake_client([response], calls)

    monkeypatch.setattr(swain_api.httpx, "Client", fake_http_client)
    connections = swain_api.fetch_swain_connections(
        "https://api.example.com",
        "token",
        tenant_id="777",
        project_id=1,
    )
    assert len(connections) == 1
    conn = connections[0]
    assert conn.id == 55
    assert conn.driver == "postgres"
    assert conn.stage == "prod"
    assert conn.schema_name == "public"
    assert conn.build_endpoint == "https://build.example.com"
    assert calls[0][0] == "POST"
    assert calls[0][2]["X-Tenant-ID"] == "777"


def test_fetch_swain_connections_with_fallback_on_404(
    monkeypatch, fake_client, fake_response
):
    primary = fake_response(
        "https://primary.example.com/api/Connection/filter",
        status_code=404,
        content=b"missing",
        reason="Not Found",
    )
    fallback = fake_response(
        "https://fallback.example.com/api/Connection/filter",
        json_data={
            "data": [
                {
                    "id": 55,
                    "dbname": "analytics",
                }
            ]
        },
        content=b"{}",
    )
    calls: List[Any] = []
    clients = [
        fake_client([primary], calls),
        fake_client([fallback], calls),
    ]

    def fake_http_client(**kwargs):
        return clients.pop(0)

    monkeypatch.setattr(swain_api.httpx, "Client", fake_http_client)
    connections = swain_api.fetch_swain_connections_with_fallback(
        "https://primary.example.com",
        "https://fallback.example.com",
        "token",
        tenant_id="1",
        project_id=1,
    )
    assert [conn.id for conn in connections] == [55]
    assert [entry[1] for entry in calls] == [
        "https://primary.example.com/api/Connection/filter",
        "https://fallback.example.com/api/Connection/filter",
    ]
