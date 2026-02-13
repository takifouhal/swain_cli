import json

import swain_cli.generator as generator
from swain_cli.args import GenArgs


def test_gen_plan_only_is_side_effect_free(monkeypatch, tmp_path, capfd) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("network/downloads should not run in plan-only mode")

    monkeypatch.setattr(generator, "require_auth_token", fail)
    monkeypatch.setattr(generator, "resolve_schema_for_generation", fail)
    monkeypatch.setattr(generator, "fetch_crudsql_schema", fail)
    monkeypatch.setattr(generator, "fetch_swain_connection_schema", fail)
    monkeypatch.setattr(generator, "resolve_generator_jar", fail)
    monkeypatch.setattr(generator, "run_openapi_generator", fail)

    out_dir = tmp_path / "out"
    assert not out_dir.exists()

    args = GenArgs(
        out=str(out_dir),
        languages=["python"],
        plan_only=True,
        plan_format="json",
    )

    assert generator.handle_gen(args) == 0

    stdout, stderr = capfd.readouterr()
    assert stderr == ""
    payload = json.loads(stdout)
    assert payload["mode"] == "plan-only"

    assert not out_dir.exists()


def test_gen_dry_run_is_side_effect_free(monkeypatch, tmp_path, capfd) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("network/downloads should not run in dry-run mode")

    monkeypatch.setattr(generator, "require_auth_token", fail)
    monkeypatch.setattr(generator, "resolve_schema_for_generation", fail)
    monkeypatch.setattr(generator, "fetch_crudsql_schema", fail)
    monkeypatch.setattr(generator, "fetch_swain_connection_schema", fail)
    monkeypatch.setattr(generator, "resolve_generator_jar", fail)
    monkeypatch.setattr(generator, "run_openapi_generator", fail)

    out_dir = tmp_path / "out"
    assert not out_dir.exists()

    args = GenArgs(
        out=str(out_dir),
        languages=["python"],
        dry_run=True,
        plan_format="json",
    )

    assert generator.handle_gen(args) == 0

    stdout, stderr = capfd.readouterr()
    assert stderr == ""
    payload = json.loads(stdout)
    assert payload["mode"] == "dry-run"

    assert not out_dir.exists()
