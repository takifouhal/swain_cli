from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional

import httpx
import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError


class MemoryKeyring(KeyringBackend):
    priority = 1

    def __init__(self) -> None:
        self._storage: Dict[tuple, str] = {}

    def get_password(self, service: str, username: str) -> Optional[str]:
        return self._storage.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self._storage[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        try:
            del self._storage[(service, username)]
        except KeyError as exc:
            raise PasswordDeleteError(str(exc)) from exc


@pytest.fixture(autouse=True)
def memory_keyring() -> None:
    original = keyring.get_keyring()
    keyring.set_keyring(MemoryKeyring())
    try:
        yield
    finally:
        keyring.set_keyring(original)


class FakeResponse:
    def __init__(
        self,
        url: str,
        *,
        status_code: int = 200,
        content: bytes = b"",
        json_data: Any = None,
        reason: str = "OK",
    ) -> None:
        self.url = url
        self.status_code = status_code
        self.content = content
        self._json_data = json_data
        self.reason_phrase = reason
        self.headers: Dict[str, str] = {}
        self.text = (
            content.decode("utf-8", "replace") if isinstance(content, bytes) else str(content)
        )

    def json(self) -> Any:
        if self._json_data is not None:
            return self._json_data
        return json.loads(self.content.decode("utf-8"))

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("GET", self.url)
            raise httpx.HTTPStatusError(
                "error",
                request=request,
                response=self,
            )


class FakeClient:
    def __init__(self, responses: List[FakeResponse], calls: Optional[list] = None) -> None:
        self._responses = list(responses)
        self.calls = [] if calls is None else calls

    def __enter__(self) -> FakeClient:
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def _next_response(self, url: Any) -> FakeResponse:
        if not self._responses:
            raise AssertionError("unexpected request")
        response = self._responses.pop(0)
        assert response.url == str(url)
        return response

    def get(
        self, url: Any, *, headers: Optional[Dict[str, str]] = None, params: Any = None, json: Any = None
    ) -> FakeResponse:
        response = self._next_response(url)
        self.calls.append(("GET", str(url), headers or {}, params, json))
        return response

    def post(
        self, url: Any, *, headers: Optional[Dict[str, str]] = None, params: Any = None, json: Any = None
    ) -> FakeResponse:
        response = self._next_response(url)
        self.calls.append(("POST", str(url), headers or {}, params, json))
        return response


@pytest.fixture
def fake_response() -> type[FakeResponse]:
    return FakeResponse


@pytest.fixture
def fake_client() -> type[FakeClient]:
    return FakeClient


@pytest.fixture
def make_jwt():
    def _make(payload: Dict[str, Any]) -> str:
        header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = base64.urlsafe_b64encode(b"signature").decode().rstrip("=")
        return f"{header}.{body}.{signature}"

    return _make

