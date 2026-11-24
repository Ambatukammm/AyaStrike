"""Safe external-tool runner.

External CLI tools (nmap, etc.) are invoked here through a single choke point
that:

  * NEVER uses a shell (argument lists only — no shell injection surface),
  * resolves the executable on PATH (or an explicit configured path),
  * enforces timeouts,
  * streams output back line-by-line to a callback for live UI updates,
  * returns a structured result,
  * degrades gracefully (``ToolNotFound``) when the tool is not installed.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence


class ToolNotFound(Exception):
    """The requested external tool is not installed / not on PATH."""


@dataclass
class RunResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    lines: list[str] = field(default_factory=list)


def which(tool: str, explicit: str = "") -> Optional[str]:
    if explicit:
        return explicit if shutil.which(explicit) or _is_file(explicit) else None
    return shutil.which(tool)


def _is_file(path: str) -> bool:
    import os

    return os.path.isfile(path)


def run(
    cmd: Sequence[str],
    timeout: float = 120.0,
    on_line: Optional[Callable[[str], None]] = None,
    cancel=None,
    input_text: Optional[str] = None,
) -> RunResult:
    """Run ``cmd`` (a list of args) with no shell. Raises ToolNotFound if the
    executable cannot be resolved."""
    cmd = list(cmd)
    exe = which(cmd[0])
    if exe is None and not _is_file(cmd[0]):
        raise ToolNotFound(
            f"'{cmd[0]}' was not found on PATH. Install it or set its path in "
            f"Settings. AyaStrike does not bundle third-party tools."
        )
    if exe:
        cmd[0] = exe

    collected: list[str] = []
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE if input_text is not None else None,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    timed_out = {"v": False}

    def _watchdog():
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out["v"] = True
            proc.kill()

    wd = threading.Thread(target=_watchdog, daemon=True)
    wd.start()

    if input_text is not None and proc.stdin:
        try:
            proc.stdin.write(input_text)
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip("\n")
        collected.append(line)
        if on_line:
            on_line(line)
        if cancel is not None and cancel.is_set():
            proc.kill()
            break

    proc.wait()
    wd.join(timeout=1)
    stderr = proc.stderr.read() if proc.stderr else ""
    return RunResult(
        cmd=cmd,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout="\n".join(collected),
        stderr=stderr,
        timed_out=timed_out["v"],
        lines=collected,
    )
