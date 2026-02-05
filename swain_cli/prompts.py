"""Interactive prompt helpers for swain_cli."""

from __future__ import annotations

from typing import Any, Callable, List, Optional, Sequence, Union

import questionary

from .console import log_error


class InteractionAborted(Exception):
    """Raised when the interactive session is cancelled."""


def prompt_text(
    prompt: str,
    *,
    default: Optional[str] = None,
    validate: Optional[Callable[[str], Optional[str]]] = None,
    allow_empty: bool = False,
) -> str:
    wrapped_validate: Optional[Callable[[str], Union[bool, str]]]
    if validate is None:
        wrapped_validate = None
    else:

        def wrapped_validate(value: str) -> Union[bool, str]:
            verdict = validate(value)
            return True if verdict is None else verdict

    question = questionary.text(
        prompt,
        default=default or "",
        validate=wrapped_validate,
    )
    result = question.ask()
    if result is None:
        raise InteractionAborted()
    stripped = result.strip()
    if not stripped and not allow_empty:
        log_error("please enter a value")
        return prompt_text(
            prompt,
            default=default,
            validate=validate,
            allow_empty=allow_empty,
        )
    return stripped


def prompt_confirm(prompt: str, *, default: bool) -> bool:
    result = questionary.confirm(prompt, default=default).ask()
    if result is None:
        raise InteractionAborted()
    return bool(result)


def prompt_password(prompt: str) -> str:
    result = questionary.password(prompt).ask()
    if result is None:
        raise InteractionAborted()
    return result.strip()


def prompt_select(prompt: str, choices: Sequence[Any]) -> Any:
    result = questionary.select(prompt, choices=choices).ask()
    if result is None:
        raise InteractionAborted()
    return result


def prompt_multi_select(prompt: str, choices: Sequence[Any]) -> List[Any]:
    result = questionary.checkbox(prompt, choices=choices).ask()
    if result is None:
        raise InteractionAborted()
    return list(result)
