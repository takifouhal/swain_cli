import json

import httpx

import swain_cli.http as http


class _ResponseStub:
    def __init__(self, status_code: int, headers=None):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _ClientStub:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def request(self, *args, **kwargs):
        _ = args
        _ = kwargs
        self.calls += 1
        if not self._responses:
            raise AssertionError("unexpected extra request")
        return self._responses.pop(0)


def test_request_with_retries_closes_retryable_responses():
    first = _ResponseStub(503)
    second = _ResponseStub(429)
    third = _ResponseStub(200)
    client = _ClientStub([first, second, third])

    response = http.request_with_retries(
        client, "GET", "https://example.com", max_attempts=3, sleep=lambda _: None
    )

    assert response is third
    assert client.calls == 3
    assert first.closed is True
    assert second.closed is True
    assert third.closed is False


def test_request_with_retries_does_not_retry_non_retryable_4xx():
    response_400 = _ResponseStub(400)
    client = _ClientStub([response_400])

    response = http.request_with_retries(
        client, "GET", "https://example.com", max_attempts=3, sleep=lambda _: None
    )

    assert response is response_400
    assert client.calls == 1
    assert response_400.closed is False


def test_request_with_retries_jitter_is_opt_in(monkeypatch):
    monkeypatch.setattr(http.random, "uniform", lambda lo, hi: hi / 2)

    first = _ResponseStub(503)
    second = _ResponseStub(200)
    client = _ClientStub([first, second])

    delays = []

    def sleep(value: float) -> None:
        delays.append(value)

    http.request_with_retries(
        client,
        "GET",
        "https://example.com",
        max_attempts=2,
        backoff_initial=1.0,
        backoff_max=8.0,
        sleep=sleep,
        jitter=True,
    )

    assert delays == [0.5]


def test_describe_http_error_redacts_secrets_in_body():
    jwt = "abcdeabcde.abcdeabcde.abcdeabcde"
    request = httpx.Request("GET", "https://api.example.com")
    body = json.dumps({"detail": f"token=supersecret jwt={jwt}"}).encode("utf-8")
    response = httpx.Response(400, request=request, content=body)
    exc = httpx.HTTPStatusError("boom", request=request, response=response)

    detail = http.describe_http_error(exc)

    assert "supersecret" not in detail
    assert "token=***" in detail
    assert jwt not in detail
    assert "***" in detail
