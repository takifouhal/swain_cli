import os
import platform
import re
import tarfile
import zipfile
from io import BytesIO
from time import time as now
from types import SimpleNamespace

import httpx
import pytest

import swain_cli.constants as constants
import swain_cli.engine as engine
from swain_cli.errors import CLIError


def test_normalize_os_variants():
    assert engine.normalize_os("Darwin") == "macos"
    assert engine.normalize_os("WINDOWS") == "windows"
    assert engine.normalize_os("linux") == "linux"
    assert engine.normalize_os("FreeBSD") == "freebsd"


def test_normalize_arch_variants():
    assert engine.normalize_arch("x86_64") == "x86_64"
    assert engine.normalize_arch("AMD64") == "x86_64"
    assert engine.normalize_arch("arm64") == "arm64"
    assert engine.normalize_arch("aarch64") == "arm64"
    assert engine.normalize_arch("riscv64") == "riscv64"


def test_cache_root_honors_env(tmp_path, monkeypatch):
    custom = tmp_path / "custom-cache"
    monkeypatch.setenv(constants.CACHE_ENV_VAR, str(custom))
    result = engine.cache_root()
    assert result == custom
    assert result.is_dir()


def test_jre_assets_have_pinned_checksums():
    for key, asset in constants.JRE_ASSETS.items():
        assert isinstance(key, tuple)
        assert asset.sha256 is not None
        assert re.fullmatch(r"[a-f0-9]{64}", asset.sha256)
        assert asset.checksum_filename
        assert asset.checksum_filename.endswith(".sha256")


def test_get_jre_asset_unsupported(monkeypatch):
    engine.get_platform_info.cache_clear()
    monkeypatch.setattr(platform, "system", lambda: "Plan9")
    monkeypatch.setattr(platform, "machine", lambda: "mips")
    with pytest.raises(CLIError):
        engine.get_jre_asset()
    engine.get_platform_info.cache_clear()


def test_ensure_embedded_jre_reuses_cached_install(tmp_path, monkeypatch):
    runtime_dir = tmp_path / "jre"
    (runtime_dir / "bin").mkdir(parents=True)
    (runtime_dir / "bin" / "java").write_text("", encoding="utf-8")
    expected_sha = "cached-sha"
    (runtime_dir / constants.JRE_MARKER_FILENAME).write_text(expected_sha, encoding="utf-8")

    monkeypatch.setattr(engine, "java_binary_name", lambda: "java")
    monkeypatch.setattr(engine, "jre_install_dir", lambda *args, **kwargs: runtime_dir)
    monkeypatch.setattr(engine, "get_jre_asset", lambda: engine.JREAsset("dummy.tar.gz", None))
    monkeypatch.setattr(engine, "resolve_asset_sha256", lambda asset: expected_sha)

    def fail_fetch(*args, **kwargs):
        raise AssertionError("unexpected download while cached JRE is valid")

    monkeypatch.setattr(engine, "fetch_asset_file", fail_fetch)

    assert engine.ensure_embedded_jre(force=False) == runtime_dir
    assert (runtime_dir / "bin" / "java").exists()


def test_ensure_embedded_jre_reinstalls_on_marker_mismatch(tmp_path, monkeypatch):
    runtime_dir = tmp_path / "jre"
    (runtime_dir / "bin").mkdir(parents=True)
    (runtime_dir / "bin" / "java").write_text("old", encoding="utf-8")
    (runtime_dir / constants.JRE_MARKER_FILENAME).write_text("old-sha", encoding="utf-8")
    expected_sha = "new-sha"

    monkeypatch.setattr(engine, "java_binary_name", lambda: "java")
    monkeypatch.setattr(engine, "jre_install_dir", lambda *args, **kwargs: runtime_dir)
    monkeypatch.setattr(engine, "get_jre_asset", lambda: engine.JREAsset("dummy.tar.gz", None))
    monkeypatch.setattr(engine, "resolve_asset_sha256", lambda asset: expected_sha)

    calls = {"fetches": 0}

    def fake_fetch(asset_name, sha256, *, force=False):
        calls["fetches"] += 1
        assert asset_name == "dummy.tar.gz"
        assert sha256 == expected_sha
        assert force is False
        return tmp_path / "archive.tar.gz"

    def fake_extract(archive, dest):
        (dest / "bin").mkdir(parents=True, exist_ok=True)
        (dest / "bin" / "java").write_text("new", encoding="utf-8")

    monkeypatch.setattr(engine, "fetch_asset_file", fake_fetch)
    monkeypatch.setattr(engine, "extract_archive", fake_extract)
    monkeypatch.setattr(engine, "normalize_runtime_dir", lambda *_: None)

    assert engine.ensure_embedded_jre(force=False) == runtime_dir
    assert calls["fetches"] == 1
    assert (runtime_dir / constants.JRE_MARKER_FILENAME).read_text(encoding="utf-8").strip() == expected_sha
    assert (runtime_dir / "bin" / "java").read_text(encoding="utf-8") == "new"


def test_ensure_embedded_jre_force_reinstalls(tmp_path, monkeypatch):
    runtime_dir = tmp_path / "jre"
    (runtime_dir / "bin").mkdir(parents=True)
    (runtime_dir / "bin" / "java").write_text("old", encoding="utf-8")
    expected_sha = "force-sha"
    (runtime_dir / constants.JRE_MARKER_FILENAME).write_text(expected_sha, encoding="utf-8")

    monkeypatch.setattr(engine, "java_binary_name", lambda: "java")
    monkeypatch.setattr(engine, "jre_install_dir", lambda *args, **kwargs: runtime_dir)
    monkeypatch.setattr(engine, "get_jre_asset", lambda: engine.JREAsset("dummy.tar.gz", None))
    monkeypatch.setattr(engine, "resolve_asset_sha256", lambda asset: expected_sha)

    observed = {"force": None}

    def fake_fetch(asset_name, sha256, *, force=False):
        observed["force"] = force
        return tmp_path / "archive.tar.gz"

    def fake_extract(archive, dest):
        (dest / "bin").mkdir(parents=True, exist_ok=True)
        (dest / "bin" / "java").write_text("new", encoding="utf-8")

    monkeypatch.setattr(engine, "fetch_asset_file", fake_fetch)
    monkeypatch.setattr(engine, "extract_archive", fake_extract)
    monkeypatch.setattr(engine, "normalize_runtime_dir", lambda *_: None)

    assert engine.ensure_embedded_jre(force=True) == runtime_dir
    assert observed["force"] is True
    assert (runtime_dir / constants.JRE_MARKER_FILENAME).read_text(encoding="utf-8").strip() == expected_sha
    assert (runtime_dir / "bin" / "java").read_text(encoding="utf-8") == "new"


def test_extract_archive_unknown(tmp_path):
    archive = tmp_path / "archive.xyz"
    archive.write_text("dummy")
    with pytest.raises(CLIError):
        engine.extract_archive(archive, tmp_path / "out")


def test_extract_archive_blocks_zip_slip(tmp_path):
    archive = tmp_path / "archive.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../evil.txt", "owned")
    with pytest.raises(CLIError):
        engine.extract_archive(archive, tmp_path / "out")


def test_extract_archive_blocks_tar_slip(tmp_path):
    archive = tmp_path / "archive.tar.gz"
    data = b"owned"
    with tarfile.open(archive, "w:gz") as tf:
        info = tarfile.TarInfo(name="../evil.txt")
        info.size = len(data)
        tf.addfile(info, BytesIO(data))
    with pytest.raises(CLIError):
        engine.extract_archive(archive, tmp_path / "out")


def test_cache_lock_removes_stale_lock(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setattr(engine, "cache_root", lambda create=True: cache_dir)

    lock_path = engine.cache_lock_path()
    lock_path.write_text("stale", encoding="utf-8")
    old = now() - 10_000
    os.utime(lock_path, (old, old))

    with engine.cache_lock(timeout_seconds=0.1, stale_after_seconds=0):
        assert lock_path.exists()
    assert not lock_path.exists()


def test_parse_checksum_file_variants(tmp_path):
    digest = "a" * 64

    p1 = tmp_path / "bare.sha256"
    p1.write_text(f"{digest}\n")
    assert engine.parse_checksum_file(p1) == digest

    p2 = tmp_path / "gnu.sha256"
    p2.write_text(f"{digest}  swain_cli-jre-windows-x86_64.zip\n")
    assert engine.parse_checksum_file(p2) == digest

    p3 = tmp_path / "bsd.sha256"
    p3.write_text(f"SHA256 (swain_cli-jre-windows-x86_64.zip) = {digest}\n")
    assert engine.parse_checksum_file(p3) == digest

    p4 = tmp_path / "ps.sha256"
    p4.write_text(
        "Algorithm       Hash                                                       Path\n"
        f"SHA256          {digest.upper()}   C:\\tmp\\swain_cli-jre-windows-x86_64.zip\n"
    )
    assert engine.parse_checksum_file(p4) == digest


def test_httpx_downloader_retries_request_errors(tmp_path):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if calls["count"] == 1:
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(200, content=b"ok", request=request)

    transport = httpx.MockTransport(handler)

    sleeps = []

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    downloader = engine.HTTPXDownloader(
        timeout=0.1,
        max_attempts=3,
        backoff_initial=0.01,
        backoff_max=0.01,
        sleep=fake_sleep,
        client_factory=lambda timeout: httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            transport=transport,
        ),
    )

    output = tmp_path / "out.bin"
    downloader(
        "https://example.com/out.bin",
        str(output),
        SimpleNamespace(),
        progressbar=False,
    )
    assert output.read_bytes() == b"ok"
    assert calls["count"] == 2
    assert sleeps == [0.01]


def test_httpx_downloader_respects_retry_after(tmp_path):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if calls["count"] == 1:
            return httpx.Response(
                503,
                headers={"Retry-After": "2"},
                content=b"service unavailable",
                request=request,
            )
        return httpx.Response(200, content=b"ok", request=request)

    transport = httpx.MockTransport(handler)

    sleeps = []

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    downloader = engine.HTTPXDownloader(
        timeout=0.1,
        max_attempts=2,
        backoff_initial=0.01,
        backoff_max=10.0,
        sleep=fake_sleep,
        client_factory=lambda timeout: httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            transport=transport,
        ),
    )

    output = tmp_path / "out.bin"
    downloader(
        "https://example.com/out.bin",
        str(output),
        SimpleNamespace(),
        progressbar=False,
    )
    assert output.read_bytes() == b"ok"
    assert calls["count"] == 2
    assert sleeps == [2.0]


def test_httpx_downloader_does_not_retry_404(tmp_path):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(404, content=b"nope", request=request)

    transport = httpx.MockTransport(handler)
    downloader = engine.HTTPXDownloader(
        timeout=0.1,
        max_attempts=5,
        backoff_initial=0.0,
        backoff_max=0.0,
        sleep=lambda *_: None,
        client_factory=lambda timeout: httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            transport=transport,
        ),
    )

    output = tmp_path / "out.bin"
    with pytest.raises(CLIError) as excinfo:
        downloader(
            "https://example.com/out.bin",
            str(output),
            SimpleNamespace(),
            progressbar=False,
        )

    assert calls["count"] == 1
    message = str(excinfo.value)
    assert "after 1 attempt(s)" in message
    assert "404" in message
    assert "Hint:" in message
