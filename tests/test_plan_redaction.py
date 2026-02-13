import json

import swain_cli.generator as generator
from swain_cli.args import GenArgs


def test_plan_only_json_redacts_schema_input(capfd, tmp_path) -> None:
    out_dir = tmp_path / "out"
    args = GenArgs(
        out=str(out_dir),
        languages=["python"],
        schema="https://api.example.com/dynamic-swagger?token=secret",
        plan_only=True,
        plan_format="json",
    )

    assert generator.handle_gen(args) == 0
    captured, err = capfd.readouterr()
    assert err == ""
    assert "token=secret" not in captured
    assert "token=***" in captured

    payload = json.loads(captured)
    assert payload["schema"].get("input")


def test_plan_only_text_redacts_schema_input(capfd, tmp_path) -> None:
    out_dir = tmp_path / "out"
    args = GenArgs(
        out=str(out_dir),
        languages=["python"],
        schema="https://api.example.com/dynamic-swagger?token=secret",
        plan_only=True,
        plan_format="text",
    )

    assert generator.handle_gen(args) == 0
    captured, err = capfd.readouterr()
    assert err == ""
    assert "token=secret" not in captured
    assert "token=***" in captured
