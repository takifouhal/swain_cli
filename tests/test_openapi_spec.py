import json

import pytest

from swain_cli.openapi_spec import inject_base_url


def test_inject_base_url_preserves_ipv6_brackets_swagger2(tmp_path):
    schema = tmp_path / "schema.json"
    schema.write_text(
        json.dumps(
            {
                "swagger": "2.0",
                "host": "",
                "schemes": [],
                "basePath": "/api",
                "paths": {},
            }
        )
    )

    written = inject_base_url(schema, "http://[::1]:8080")
    assert written == "http://[::1]:8080/api"

    patched = json.loads(schema.read_text())
    assert patched["host"] == "[::1]:8080"
    assert patched["schemes"] == ["http"]
    assert patched["basePath"] == "/api"


def test_inject_base_url_preserves_ipv6_brackets_openapi3(tmp_path):
    schema = tmp_path / "schema.json"
    schema.write_text(
        json.dumps(
            {
                "openapi": "3.0.0",
                "info": {"title": "demo", "version": "0.0.0"},
                "paths": {},
            }
        )
    )

    written = inject_base_url(schema, "http://[::1]:8080")
    assert written == "http://[::1]:8080"

    patched = json.loads(schema.read_text())
    assert patched["servers"][0]["url"] == "http://[::1]:8080"


def test_inject_base_url_preserves_server_path_with_host_port_vars(tmp_path):
    schema = tmp_path / "schema.json"
    schema.write_text(
        json.dumps(
            {
                "openapi": "3.0.0",
                "info": {"title": "demo", "version": "0.0.0"},
                "paths": {},
                "servers": [{"url": "https://{host}:{port}/api"}],
            }
        )
    )

    written = inject_base_url(schema, "https://api.example.com")
    assert written == "https://api.example.com/api"

    patched = json.loads(schema.read_text())
    assert patched["servers"][0]["url"] == "https://api.example.com/api"


def test_inject_base_url_uses_server_var_defaults_for_path(tmp_path):
    schema = tmp_path / "schema.json"
    schema.write_text(
        json.dumps(
            {
                "openapi": "3.0.0",
                "info": {"title": "demo", "version": "0.0.0"},
                "paths": {},
                "servers": [
                    {
                        "url": "https://{host}{basePath}",
                        "variables": {"basePath": {"default": "/api"}},
                    }
                ],
            }
        )
    )

    written = inject_base_url(schema, "https://api.example.com")
    assert written == "https://api.example.com/api"

    patched = json.loads(schema.read_text())
    assert patched["servers"][0]["url"] == "https://api.example.com/api"


def test_inject_base_url_returns_none_on_unparsable_base_url(tmp_path):
    schema = tmp_path / "schema.json"
    schema.write_text(
        json.dumps(
            {
                "openapi": "3.0.0",
                "info": {"title": "demo", "version": "0.0.0"},
                "paths": {},
            }
        )
    )

    assert inject_base_url(schema, "http://[::1") is None


def test_inject_base_url_supports_yaml_openapi3(tmp_path):
    yaml = pytest.importorskip("yaml")
    schema = tmp_path / "schema.yaml"
    schema.write_text(
        "openapi: 3.0.0\n"
        "info:\n"
        "  title: demo\n"
        "  version: 0.0.0\n"
        "paths: {}\n",
        encoding="utf-8",
    )

    written = inject_base_url(schema, "https://api.example.com")
    assert written == "https://api.example.com"

    patched = yaml.safe_load(schema.read_text(encoding="utf-8"))
    assert patched["servers"][0]["url"] == "https://api.example.com"
