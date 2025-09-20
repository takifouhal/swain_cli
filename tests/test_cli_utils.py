import os
import subprocess
import sys
import pytest

import swaggen.cli as cli


def test_typescript_alias():
    assert cli.LANGUAGE_ALIASES["typescript"] == "typescript-axios"


def test_normalize_os_variants():
    assert cli.normalize_os("Darwin") == "macos"
    assert cli.normalize_os("WINDOWS") == "windows"
    assert cli.normalize_os("linux") == "linux"
    assert cli.normalize_os("FreeBSD") == "freebsd"


def test_normalize_arch_variants():
    assert cli.normalize_arch("x86_64") == "x86_64"
    assert cli.normalize_arch("AMD64") == "x86_64"
    assert cli.normalize_arch("arm64") == "arm64"
    assert cli.normalize_arch("aarch64") == "arm64"
    assert cli.normalize_arch("riscv64") == "riscv64"


def test_cache_root_honors_env(tmp_path, monkeypatch):
    explicit = tmp_path / "custom-cache"
    monkeypatch.setenv(cli.CACHE_ENV_VAR, str(explicit))
    result = cli.cache_root()
    assert result == explicit
    assert result.is_dir()


def test_get_jre_asset_unsupported(monkeypatch):
    monkeypatch.setattr(cli.platform, "system", lambda: "Plan9")
    monkeypatch.setattr(cli.platform, "machine", lambda: "mips")
    with pytest.raises(cli.CLIError):
        cli.get_jre_asset()


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX-only path expectations")
def test_cli_help_invocation(tmp_path):
    env = os.environ.copy()
    env["SWAGGEN_CACHE_DIR"] = str(tmp_path)
    completed = subprocess.run(
        [sys.executable, "-m", "swaggen.cli", "--help"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    assert "usage" in completed.stdout.lower()
