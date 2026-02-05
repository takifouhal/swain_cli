from swain_cli.utils import redact


def test_redact_masks_kv_secrets():
    assert redact("token=abc123") == "token=***"
    assert redact("password: hunter2") == "password:***"


def test_redact_masks_bearer_tokens():
    assert redact("Authorization: Bearer abc.def.ghi") == "Authorization: Bearer ***"


def test_redact_masks_jwt_like_strings():
    raw = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "signaturelong"
    )
    assert redact(raw) == "***"
