from __future__ import annotations

from pathlib import Path

import swain_cli.constants as constants
import swain_cli.engine as engine
import swain_cli.engine.jar as engine_jar


def test_ensure_generator_jar_verifies_signature_when_enabled(monkeypatch, tmp_path) -> None:
    cache_root = tmp_path / "cache"
    monkeypatch.setenv(constants.CACHE_ENV_VAR, str(cache_root))
    monkeypatch.setenv(constants.VERIFY_SIGNATURES_ENV_VAR, "1")

    # Avoid checksum/digest concerns; this test focuses on signature wiring.
    monkeypatch.setattr(engine_jar, "_verify_digest", lambda *a, **k: None)

    calls = {"verify": [], "retrieve": []}

    def fake_retrieve(*, url, path, fname, known_hash=None, downloader=None, **kwargs):
        _ = known_hash, downloader, kwargs
        calls["retrieve"].append(url)
        out = Path(path) / fname
        out.parent.mkdir(parents=True, exist_ok=True)
        if str(url).endswith(".asc"):
            out.write_text("sig", encoding="utf-8")
        else:
            out.write_bytes(b"jar")
        return str(out)

    monkeypatch.setattr(engine_jar.pooch, "retrieve", fake_retrieve)

    def fake_verify(jar_path: Path, signature_path: Path) -> None:
        calls["verify"].append((Path(jar_path), Path(signature_path)))

    monkeypatch.setattr(engine_jar, "verify_gpg_signature", fake_verify)

    jar = engine.ensure_generator_jar(constants.PINNED_GENERATOR_VERSION, verify=True)
    assert jar.exists()

    assert len(calls["verify"]) == 1
    jar_path, sig_path = calls["verify"][0]
    assert jar_path == jar
    assert sig_path.name.endswith(".jar.asc")


def test_ensure_generator_jar_skips_signature_when_disabled(monkeypatch, tmp_path) -> None:
    cache_root = tmp_path / "cache"
    monkeypatch.setenv(constants.CACHE_ENV_VAR, str(cache_root))

    monkeypatch.setattr(engine_jar, "_verify_digest", lambda *a, **k: None)

    def fake_retrieve(*, url, path, fname, known_hash=None, downloader=None, **kwargs):
        _ = url, known_hash, downloader, kwargs
        out = Path(path) / fname
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b"jar")
        return str(out)

    monkeypatch.setattr(engine_jar.pooch, "retrieve", fake_retrieve)

    def fail_verify(*_a, **_k):
        raise AssertionError("verify_gpg_signature should not be called")

    monkeypatch.setattr(engine_jar, "verify_gpg_signature", fail_verify)

    jar = engine.ensure_generator_jar(constants.PINNED_GENERATOR_VERSION, verify=True)
    assert jar.exists()
