import swain_cli.prompts as prompts


def test_prompt_text_reprompts_until_non_empty(monkeypatch):
    answers = iter(["", "   ", "  ok  "])

    class FakeQuestion:
        def ask(self):
            return next(answers)

    def fake_text(*args, **kwargs):
        _ = args
        _ = kwargs
        return FakeQuestion()

    errors = []

    monkeypatch.setattr(prompts.questionary, "text", fake_text)
    monkeypatch.setattr(prompts, "log_error", lambda message: errors.append(message))

    assert prompts.prompt_text("value") == "ok"
    assert errors == ["please enter a value", "please enter a value"]
