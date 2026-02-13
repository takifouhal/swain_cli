"""Subprocess execution helpers.

This module centralizes bounded output capture so callers (engine + generator hooks)
stay consistent.
"""

from __future__ import annotations

import subprocess
import sys
from collections import deque
from pathlib import Path
from typing import Mapping, Optional, Sequence, Tuple


def run_subprocess(
    cmd: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
    stream: bool = True,
    max_capture_chars: int = 200_000,
) -> Tuple[int, str]:
    proc = subprocess.Popen(
        list(cmd),
        cwd=str(cwd) if cwd is not None else None,
        env=dict(env) if env is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    captured: deque[str] = deque()
    captured_size = 0

    def capture(line: str) -> None:
        nonlocal captured_size
        if len(line) > max_capture_chars:
            captured.clear()
            line = line[-max_capture_chars:]
            captured_size = 0
        captured.append(line)
        captured_size += len(line)
        while captured and captured_size > max_capture_chars:
            removed = captured.popleft()
            captured_size -= len(removed)

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if stream:
                sys.stdout.write(line)
            capture(line)
        proc.stdout.close()
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        raise
    return proc.returncode, "".join(captured)
