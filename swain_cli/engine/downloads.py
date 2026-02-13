"""Download helpers for engine assets (JREs, jars, etc)."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, Optional

import httpx
import pooch

from ..console import log_error
from ..constants import HTTP_TIMEOUT_SECONDS
from ..errors import CLIError
from ..http import describe_http_error


class HTTPXDownloader:
    """Pooch downloader that uses httpx for transfers."""

    def __init__(
        self,
        timeout: float,
        *,
        max_attempts: int = 5,
        backoff_initial: float = 0.5,
        backoff_max: float = 8.0,
        sleep: Callable[[float], None] = time.sleep,
        client_factory: Optional[Callable[[httpx.Timeout], httpx.Client]] = None,
    ) -> None:
        self.timeout = timeout
        self.max_attempts = max(1, int(max_attempts))
        self.backoff_initial = max(0.0, float(backoff_initial))
        self.backoff_max = max(self.backoff_initial, float(backoff_max))
        self.sleep = sleep
        self.client_factory = client_factory or self._default_client_factory

    def _default_client_factory(self, timeout: httpx.Timeout) -> httpx.Client:
        return httpx.Client(timeout=timeout, follow_redirects=True)

    def _retry_delay(self, attempt: int, exc: httpx.HTTPError) -> float:
        if isinstance(exc, httpx.HTTPStatusError):
            retry_after = exc.response.headers.get("Retry-After")
            if retry_after:
                try:
                    parsed = float(retry_after)
                except ValueError:
                    parsed = 0.0
                if parsed > 0:
                    return min(parsed, self.backoff_max)
        if attempt <= 0:
            return 0.0
        delay = self.backoff_initial * (2 ** (attempt - 1))
        return min(delay, self.backoff_max)

    def _should_retry(self, exc: httpx.HTTPError) -> bool:
        if isinstance(exc, httpx.TimeoutException):
            return True
        if isinstance(exc, httpx.RequestError):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code in {408, 429, 500, 502, 503, 504}
        return False

    def __call__(
        self,
        url: str,
        output_file: str,
        pooch_obj: pooch.Pooch,
        check_only: bool = False,
        progressbar: bool = False,
        **_: Any,
    ) -> None:
        _ = pooch_obj
        timeout = httpx.Timeout(self.timeout, connect=self.timeout)
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = Path(f"{output_file}.tmp")
        display_name = _download_name(url, output_path.name)

        attempt = 0
        while attempt < self.max_attempts:
            attempt += 1
            progress_enabled = bool(progressbar and sys.stderr.isatty() and not check_only)
            progress = _DownloadProgress(
                label=display_name,
                enabled=progress_enabled,
            )
            try:
                with self.client_factory(timeout) as client:
                    if check_only:
                        response = client.head(url)
                        response.raise_for_status()
                        return
                    try:
                        if tmp_path.exists():
                            tmp_path.unlink()
                    except OSError:
                        pass

                    with client.stream("GET", url) as response:
                        response.raise_for_status()
                        total_raw = response.headers.get("Content-Length")
                        if total_raw:
                            try:
                                total_value = int(total_raw)
                            except ValueError:
                                total_value = None
                        else:
                            total_value = None
                        progress.set_total(total_value)
                        with tmp_path.open("wb") as fh:
                            for chunk in response.iter_bytes(chunk_size=1024 * 64):
                                if not chunk:
                                    continue
                                fh.write(chunk)
                                progress.update(len(chunk))

                    progress.finish()
                    os.replace(tmp_path, output_file)
                    return
            except httpx.HTTPError as exc:
                progress.finish(success=False)
                try:
                    if tmp_path.exists():
                        tmp_path.unlink()
                except OSError:
                    pass

                retryable = self._should_retry(exc)
                if attempt >= self.max_attempts or not retryable:
                    detail = describe_http_error(exc)
                    hint = _download_error_hint(exc)
                    source = _download_source(url)
                    extra = f" Hint: {hint}" if hint else ""
                    raise CLIError(
                        f"download failed for {display_name} from {source} after {attempt} attempt(s): {detail}{extra}"
                    ) from exc

                delay = self._retry_delay(attempt, exc)
                detail = describe_http_error(exc)
                source = _download_source(url)
                log_error(
                    f"download error for {display_name} from {source}: {detail}; retrying in {delay:.1f}s"
                    f" ({attempt + 1}/{self.max_attempts})"
                )
                if delay > 0:
                    self.sleep(delay)
            except OSError as exc:
                progress.finish(success=False)
                raise CLIError(
                    f"failed to write download file {output_path}: {exc}"
                ) from exc


HTTPX_DOWNLOADER = HTTPXDownloader(timeout=HTTP_TIMEOUT_SECONDS)


def _format_bytes(value: float) -> str:
    if value < 0:
        value = 0
    units = ("B", "KB", "MB", "GB", "TB")
    unit_index = 0
    size = float(value)
    while size >= 1024 and unit_index + 1 < len(units):
        size /= 1024.0
        unit_index += 1
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    return f"{size:.1f} {units[unit_index]}"


def _download_source(url: str) -> str:
    try:
        parsed = httpx.URL(url)
    except Exception:
        return url
    if parsed.host:
        return str(parsed.host)
    return url


def _download_name(url: str, fallback: str) -> str:
    try:
        parsed = httpx.URL(url)
    except Exception:
        parsed = None
    if parsed is not None:
        candidate = Path(parsed.path).name
        if candidate:
            return candidate
    stripped = (url or "").split("?", 1)[0].rstrip("/")
    if "/" in stripped:
        candidate = stripped.rsplit("/", 1)[-1].strip()
        if candidate:
            return candidate
    return fallback


def _download_error_hint(exc: httpx.HTTPError) -> Optional[str]:
    if isinstance(exc, httpx.ProxyError):
        return "check HTTP_PROXY/HTTPS_PROXY/NO_PROXY environment variables"
    if isinstance(exc, httpx.TimeoutException):
        return "network timeout; try again or use a more reliable connection"
    if isinstance(exc, httpx.ConnectError):
        return "could not connect; check your internet/VPN/firewall"
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 429:
            return "rate limited; wait a bit and retry"
        if status >= 500:
            return "server error; try again later"
        if status == 404:
            return "resource not found; check the URL/version and try again"
    return None


class _DownloadProgress:
    def __init__(self, *, label: str, enabled: bool) -> None:
        self.label = label
        self.enabled = enabled
        self.total: Optional[int] = None
        self.downloaded = 0
        self.started_at = time.monotonic()
        self._last_render_at = 0.0
        self._last_line_len = 0
        if self.enabled:
            self._render(force=True)

    def set_total(self, total: Optional[int]) -> None:
        self.total = total if total and total > 0 else None
        self._render(force=True)

    def update(self, chunk_size: int) -> None:
        if chunk_size > 0:
            self.downloaded += chunk_size
        self._render()

    def finish(self, *, success: bool = True) -> None:
        _ = success
        if not self.enabled:
            return
        self._render(force=True, final=True)
        sys.stderr.write("\n")
        sys.stderr.flush()
        self._last_line_len = 0

    def _render(self, *, force: bool = False, final: bool = False) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        if not force and (now - self._last_render_at) < 0.1:
            return
        self._last_render_at = now

        elapsed = max(now - self.started_at, 0.001)
        speed = self.downloaded / elapsed
        speed_str = f"{_format_bytes(speed)}/s"
        downloaded_str = _format_bytes(self.downloaded)

        if self.total:
            total_str = _format_bytes(self.total)
            ratio = min(max(self.downloaded / max(self.total, 1), 0.0), 1.0)
            width = 24
            filled = int(ratio * width)
            bar = "#" * filled + "-" * (width - filled)
            percent = int(ratio * 100)
            suffix = f"{percent:3d}%"
            line = f"{self.label} [{bar}] {suffix} {downloaded_str}/{total_str} {speed_str}"
        else:
            line = f"{self.label} {downloaded_str} {speed_str}"

        if final and self.total and self.downloaded < self.total:
            line = f"{line} (incomplete)"

        pad = ""
        if len(line) < self._last_line_len:
            pad = " " * (self._last_line_len - len(line))
        self._last_line_len = len(line)
        sys.stderr.write(f"\r{line}{pad}")
        sys.stderr.flush()


# Public re-exports expected by existing callers/tests.
_download_name = _download_name
_download_source = _download_source
_download_error_hint = _download_error_hint
_DownloadProgress = _DownloadProgress
