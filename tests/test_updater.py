import sys
from pathlib import Path
from types import SimpleNamespace

import swain_cli.constants as constants
import swain_cli.updater as updater


def test_handle_self_update_defaults_signature_verification_from_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(constants.VERIFY_SIGNATURES_ENV_VAR, "1")
    monkeypatch.setattr(sys, "frozen", True, raising=False)

    exe = tmp_path / "swain_cli"
    exe.write_bytes(b"old",)
    monkeypatch.setattr(sys, "executable", str(exe))

    def fake_download(url: str, dest: Path) -> None:
        _ = url
        dest.write_bytes(b"new")

    monkeypatch.setattr(updater, "_download_file", fake_download)

    calls = {"verify": 0}

    def fake_verify(binary: Path, signature: Path) -> None:
        calls["verify"] += 1
        assert binary.exists()
        assert signature.exists()

    monkeypatch.setattr(updater, "verify_gpg_signature", fake_verify)

    args = SimpleNamespace(
        version="latest",
        no_verify=True,
        verify_signatures=False,
        dry_run=True,
    )
    assert updater.handle_self_update(args) == 0
    assert calls["verify"] == 1
