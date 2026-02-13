"""Auth token storage + retrieval (env/file/keyring)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import keyring
from keyring.errors import NoKeyringError, PasswordDeleteError

from ..console import log, log_error
from ..constants import (
    AUTH_TOKEN_ENV_VAR,
    AUTH_TOKEN_FILE_ENV_VAR,
    KEYRING_REFRESH_USERNAME,
    KEYRING_SERVICE,
    KEYRING_USERNAME,
)
from ..errors import CLIError


@dataclass
class AuthState:
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None


_CHUNK_MARKER_PREFIX = "__swain_cli_chunked_v1__:"
# Windows Credential Manager has a relatively small credential blob limit. Keep
# chunks comfortably under 512 bytes (implementation-defined encoding).
_KEYRING_CHUNK_SIZE = 200


def _chunk_keyring_username(base_username: str, idx: int) -> str:
    return f"{base_username}__chunk_{idx}"


def _parse_chunk_marker(value: str) -> Optional[int]:
    if not isinstance(value, str):
        return None
    if not value.startswith(_CHUNK_MARKER_PREFIX):
        return None
    raw = value[len(_CHUNK_MARKER_PREFIX) :].strip()
    try:
        count = int(raw)
    except ValueError:
        return None
    if count <= 0:
        return None
    return count


def _load_keyring_secret(service: str, username: str) -> Optional[str]:
    try:
        secret = keyring.get_password(service, username)
    except NoKeyringError:
        return None
    except Exception as exc:
        log_error(f"failed to read stored credentials from keyring: {exc}")
        return None
    if not secret:
        return None

    chunk_count = _parse_chunk_marker(secret)
    if chunk_count is None:
        return secret.strip() or None

    chunks: List[str] = []
    for idx in range(chunk_count):
        try:
            chunk = keyring.get_password(service, _chunk_keyring_username(username, idx))
        except NoKeyringError:
            return None
        except Exception as exc:
            log_error(f"failed to read stored credentials from keyring: {exc}")
            return None
        if not chunk:
            return None
        chunks.append(chunk)
    joined = "".join(chunks).strip()
    return joined or None


def _delete_keyring_chunks(service: str, username: str, *, start: int = 0) -> None:
    # Best-effort cleanup. Stop on first missing chunk entry so we don't loop
    # forever on empty keyrings.
    idx = start
    while True:
        try:
            keyring.delete_password(service, _chunk_keyring_username(username, idx))
        except (NoKeyringError, PasswordDeleteError):
            break
        except Exception:
            break
        idx += 1


def _store_keyring_secret_chunked(service: str, username: str, secret: str) -> None:
    chunks = [
        secret[idx : idx + _KEYRING_CHUNK_SIZE]
        for idx in range(0, len(secret), _KEYRING_CHUNK_SIZE)
    ]
    if not chunks:
        raise CLIError("attempted to persist empty auth token")

    # Write the chunks first, then atomically point the main entry at them via a
    # marker. This keeps reads safe even if a run is interrupted mid-write.
    for idx, chunk in enumerate(chunks):
        keyring.set_password(service, _chunk_keyring_username(username, idx), chunk)
    keyring.set_password(service, username, f"{_CHUNK_MARKER_PREFIX}{len(chunks)}")
    _delete_keyring_chunks(service, username, start=len(chunks))


def load_auth_state() -> AuthState:
    env_token = os.environ.get(AUTH_TOKEN_ENV_VAR, "").strip()
    if env_token:
        return AuthState(env_token, None)

    access_value = _load_keyring_secret(KEYRING_SERVICE, KEYRING_USERNAME)
    refresh_value = _load_keyring_secret(KEYRING_SERVICE, KEYRING_REFRESH_USERNAME)
    return AuthState(access_value, refresh_value)


def persist_auth_token(token: str, refresh_token: Optional[str] = None) -> None:
    normalized = token.strip()
    if not normalized:
        raise CLIError("attempted to persist empty auth token")

    stored_mode = "direct"
    try:
        try:
            keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, normalized)
            _delete_keyring_chunks(KEYRING_SERVICE, KEYRING_USERNAME)
            stored_mode = "direct"
        except NoKeyringError:
            raise
        except Exception as exc:
            log_error(f"failed to store access token in keyring ({exc}); retrying chunked")
            try:
                _store_keyring_secret_chunked(KEYRING_SERVICE, KEYRING_USERNAME, normalized)
                stored_mode = "chunked"
            except NoKeyringError:
                raise
            except Exception as exc2:
                raise CLIError(
                    "failed to persist authentication token in keyring; "
                    f"set {AUTH_TOKEN_ENV_VAR} for this session ({exc2})"
                ) from exc2

        if refresh_token is not None:
            refresh_normalized = refresh_token.strip()
            if refresh_normalized:
                try:
                    keyring.set_password(
                        KEYRING_SERVICE,
                        KEYRING_REFRESH_USERNAME,
                        refresh_normalized,
                    )
                    _delete_keyring_chunks(KEYRING_SERVICE, KEYRING_REFRESH_USERNAME)
                except Exception:
                    _store_keyring_secret_chunked(
                        KEYRING_SERVICE,
                        KEYRING_REFRESH_USERNAME,
                        refresh_normalized,
                    )
            else:
                try:
                    keyring.delete_password(KEYRING_SERVICE, KEYRING_REFRESH_USERNAME)
                except (NoKeyringError, PasswordDeleteError):
                    pass
                _delete_keyring_chunks(KEYRING_SERVICE, KEYRING_REFRESH_USERNAME)

    except NoKeyringError as exc:
        raise CLIError(
            "no keyring backend available; set SWAIN_CLI_AUTH_TOKEN for this session"
        ) from exc

    if stored_mode == "direct":
        log(f"stored access token ({mask_token(normalized)}) in system keyring")
    else:
        log(f"stored access token ({mask_token(normalized)}) in system keyring (chunked)")


def clear_auth_state() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
    except (NoKeyringError, PasswordDeleteError):
        pass
    _delete_keyring_chunks(KEYRING_SERVICE, KEYRING_USERNAME)

    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_REFRESH_USERNAME)
    except (NoKeyringError, PasswordDeleteError):
        pass
    _delete_keyring_chunks(KEYRING_SERVICE, KEYRING_REFRESH_USERNAME)


def mask_token(token: str) -> str:
    if len(token) <= 8:
        return "*" * len(token)
    return f"{token[:4]}...{token[-4:]}"


def resolve_auth_token() -> Optional[str]:
    env_token = os.environ.get(AUTH_TOKEN_ENV_VAR, "").strip()
    if env_token:
        return env_token

    token_file = os.environ.get(AUTH_TOKEN_FILE_ENV_VAR, "").strip()
    if token_file:
        path = Path(token_file).expanduser()
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise CLIError(f"failed to read auth token file {path}: {exc}") from exc
        if not value:
            raise CLIError(f"auth token file is empty: {path}")
        return value

    state = load_auth_state()
    return state.access_token


def require_auth_token(purpose: str = "perform this action") -> str:
    token = resolve_auth_token()
    if not token:
        raise CLIError(
            f"authentication token required to {purpose}; run 'swain_cli auth login'"
        )
    return token
