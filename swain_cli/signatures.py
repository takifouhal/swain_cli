"""Optional signature verification utilities."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Optional

from .console import log
from .errors import CLIError
from .utils import format_cli_command, redact


def _which_gpg() -> Optional[str]:
    return shutil.which("gpg") or shutil.which("gpg2")


def verify_gpg_signature(artifact: Path, signature: Path) -> None:
    gpg = _which_gpg()
    if not gpg:
        raise CLIError("gpg is not installed (required for signature verification)")
    cmd = [gpg, "--verify", str(signature), str(artifact)]
    log(f"exec {redact(format_cli_command(cmd))}")
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise CLIError(f"failed to run gpg: {exc}") from exc
    if proc.returncode != 0:
        output = (proc.stdout or "").strip()
        suffix = f": {output}" if output else ""
        raise CLIError(f"signature verification failed{suffix}")

