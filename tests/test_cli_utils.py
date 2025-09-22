import argparse
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
    cli.get_engine_paths.cache_clear()
    cli.get_platform_info.cache_clear()
    explicit = tmp_path / "custom-cache"
    monkeypatch.setenv(cli.CACHE_ENV_VAR, str(explicit))
    try:
        result = cli.cache_root()
        assert result == explicit
        assert result.is_dir()
    finally:
        cli.get_engine_paths.cache_clear()
        cli.get_platform_info.cache_clear()


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


def test_build_generate_command_alias(tmp_path):
    args = argparse.Namespace(
        config=None,
        templates=None,
        additional_properties=None,
        generator_arg=None,
        property=[],
        skip_validate_spec=False,
        verbose=False,
    )

    resolved, target, cmd = cli.build_generate_command(
        "schema.yaml", "typescript", args, tmp_path
    )

    assert resolved == "typescript-axios"
    assert target == tmp_path / "typescript-axios"
    assert cmd[:7] == [
        "generate",
        "-i",
        "schema.yaml",
        "-g",
        "typescript-axios",
        "-o",
        str(target),
    ]


def test_extract_archive_unknown(tmp_path):
    archive = tmp_path / "archive.xyz"
    archive.write_text("dummy")

    with pytest.raises(cli.CLIError):
        cli.extract_archive(archive, tmp_path / "out")


def test_interactive_wizard_skip_generation(monkeypatch, capfd):
    responses = iter(
        [
            "http://example.com/openapi.yaml",  # schema
            "sdks",  # output directory
            "TypeScript",  # languages (case-insensitive)
            "",  # config
            "",  # templates
            "n",  # additional properties
            "n",  # system properties
            "n",  # raw generator args
            "",  # use embedded (default yes)
            "n",  # skip validation
            "n",  # verbose
            "n",  # run now
        ]
    )

    def fake_input(prompt: str) -> str:
        try:
            return next(responses)
        except StopIteration:  # pragma: no cover - defensive guard
            pytest.fail("interactive wizard requested more input than expected")

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(cli, "guess_default_schema", lambda: None)

    result = cli.handle_interactive(argparse.Namespace(generator_version=None))
    assert result == 0

    captured = capfd.readouterr()
    assert "interactive SDK generation wizard" in captured.out
    assert "swaggen gen -i http://example.com/openapi.yaml -o sdks -l typescript" in captured.out


def test_interactive_reprompts_on_missing_config(tmp_path, monkeypatch, capfd):
    schema = tmp_path / "openapi.yaml"
    schema.write_text("openapi: 3.0.0")
    config_valid = tmp_path / "config.yaml"
    config_valid.write_text("generator: python")

    responses = iter(
        [
            str(schema),  # schema path
            str(tmp_path / "sdks"),  # output directory
            "python",  # languages
            str(tmp_path / "missing.yaml"),  # config (first attempt - invalid)
            str(config_valid),  # config (second attempt - valid)
            "",  # templates
            "n",  # additional properties
            "n",  # system properties
            "n",  # raw generator args
            "",  # use embedded (default yes)
            "n",  # skip validation
            "n",  # verbose
            "n",  # run now
        ]
    )

    def fake_input(prompt: str) -> str:
        try:
            return next(responses)
        except StopIteration:  # pragma: no cover
            pytest.fail("interactive wizard requested more input than expected")

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(cli, "guess_default_schema", lambda: None)

    result = cli.handle_interactive(argparse.Namespace(generator_version=None))
    assert result == 0

    out, err = capfd.readouterr()
    assert "config file" in err
    assert str(config_valid) in out
