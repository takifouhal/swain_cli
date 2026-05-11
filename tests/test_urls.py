import pytest

import swain_cli.urls as urls
from swain_cli.errors import CLIError


def test_crudsql_dynamic_swagger_url_variants():
    assert (
        urls.crudsql_dynamic_swagger_url("https://api.example.com")
        == "https://api.example.com/api/dynamic_swagger"
    )
    assert (
        urls.crudsql_dynamic_swagger_url("https://api.example.com/base")
        == "https://api.example.com/base/api/dynamic_swagger"
    )
    with pytest.raises(CLIError):
        urls.crudsql_dynamic_swagger_url("api.example.com")


def test_swain_url_enforces_api_prefix_by_default():
    url = urls.swain_url("https://api.example.com", "Project")
    assert str(url) == "https://api.example.com/api/Project"


def test_swain_url_enforces_api_prefix_after_crud_proxy_base():
    url = urls.swain_url("https://api.example.com/api/crud", "Project")
    assert str(url) == "https://api.example.com/api/crud/api/Project"


def test_swain_url_can_skip_api_prefix():
    url = urls.swain_url(
        "https://api.example.com",
        "auth/login",
        enforce_api_prefix=False,
    )
    assert str(url) == "https://api.example.com/auth/login"


def test_swain_auth_candidate_urls_strip_crud_proxy_base():
    candidates = urls.swain_auth_candidate_urls(
        "https://api.example.com/api/crud",
        "auth/login",
    )
    assert [str(candidate) for candidate in candidates] == [
        "https://api.example.com/api/auth/login",
        "https://api.example.com/auth/login",
    ]


def test_resolve_base_urls_strips_trailing_crud():
    swain_base, crud_base = urls.resolve_base_urls(
        "https://dev-api.swain.technology/crud", None
    )
    assert swain_base == "https://dev-api.swain.technology"
    assert crud_base == "https://dev-api.swain.technology/api/crud"


def test_resolve_base_urls_preserves_direct_crudsql_base_without_proxy_suffix():
    swain_base, crud_base = urls.resolve_base_urls(None, "https://crud.example.com")
    assert swain_base == "https://crud.example.com"
    assert crud_base == "https://crud.example.com"
