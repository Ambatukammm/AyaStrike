#!/usr/bin/env python3
"""AyaStrike - All-In-One Penetration Testing Toolkit.

Entry point. Shows the mandatory legal disclaimer, then launches the GUI.

    python main.py            # launch the GUI
    python main.py --check    # environment self-check (no GUI), for debugging

Built for AUTHORISED penetration testing, security research, and education only.
Made by Ruel.
"""

from __future__ import annotations

import os
import sys
import traceback
from datetime import datetime

# --- make 'aya' importable no matter where the program is launched from ----
# (Double-clicking, running from another folder, or a shortcut can set a
#  different working directory; without this, `import aya` would fail and the
#  window would vanish before you could read the error.)
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def _log_crash(exc: BaseException) -> str:
    """Write the traceback somewhere the user can find it; return the path."""
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body = f"AyaStrike startup error  ({stamp})\n{'='*60}\n{tb}\n"
    paths = [os.path.join(HERE, "ayastrike_error.log"),
             os.path.join(os.path.expanduser("~"), "ayastrike_error.log")]
    written = ""
    for p in paths:
        try:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(body)
            written = p
            break
        except OSError:
            continue
    return written, tb


def _show_error(tb: str, logpath: str) -> None:
    """Make the error VISIBLE: a dialog if we can, and always the console."""
    msg = (f"AyaStrike could not start.\n\n{tb.strip().splitlines()[-1]}\n\n"
           f"Full details saved to:\n{logpath or '(could not write log)'}")
    sys.stderr.write("\n" + "=" * 60 + "\n" + tb + "\n" + "=" * 60 + "\n")
    sys.stderr.write(msg + "\n")
    try:
        import tkinter as tk
        from tkinter import messagebox
        r = tk.Tk()
        r.withdraw()
        messagebox.showerror("AyaStrike - startup error", msg)
        r.destroy()
    except Exception:
        pass
    # Keep a flashed console open so the message can be read.
    if os.name == "nt" and sys.stdin and sys.stdin.isatty():
        try:
            input("\nPress Enter to close…")
        except (EOFError, KeyboardInterrupt):
            pass


def check_environment() -> int:
    """Print a diagnostic report without launching the GUI."""
    print("AyaStrike - environment self-check")
    print("=" * 50)
    print(f"Python      : {sys.version.split()[0]}  ({sys.executable})")
    print(f"Platform    : {sys.platform}")
    print(f"App dir     : {HERE}")

    ok = True
    try:
        import tkinter
        print(f"tkinter     : OK (Tk {tkinter.TkVersion})")
    except Exception as e:
        ok = False
        print(f"tkinter     : MISSING - {e}")
        if sys.platform.startswith("linux"):
            print("              Install with: sudo apt install python3-tk")
        else:
            print("              Reinstall Python from python.org (includes Tk).")

    for name in ("requests", "reportlab", "dns", "paramiko", "msgpack", "cryptography"):
        try:
            __import__(name)
            print(f"{name:<12}: OK")
        except Exception:
            print(f"{name:<12}: not installed (optional)")

    try:
        from aya.core import plugins
        print(f"modules     : {len(plugins.discover())} loaded")
    except Exception as e:
        ok = False
        print(f"modules     : FAILED - {e}")

    print("=" * 50)
    print("Result      :", "READY - run `python main.py`" if ok
          else "NOT READY - fix the items marked MISSING/FAILED above")
    return 0 if ok else 1


def main() -> int:
    if "--check" in sys.argv or "-c" in sys.argv:
        return check_environment()

    try:
        import tkinter as tk
    except ImportError:
        sys.stderr.write(
            "\nTkinter is not available.\n"
            "  • Windows/macOS: reinstall Python from https://python.org "
            "(Tkinter is included).\n"
            "  • Linux: sudo apt install python3-tk\n\n"
            "Run `python main.py --check` for a full diagnostic.\n")
        if os.name == "nt":
            try:
                input("Press Enter to close…")
            except (EOFError, KeyboardInterrupt):
                pass
        return 2

    try:
        from aya.core.config import get_config
        from aya.gui.disclaimer import show_disclaimer
        from aya.gui.app import AyaApp

        root = tk.Tk()
        root.withdraw()  # hide the bare root until the disclaimer is accepted

        theme = get_config().settings.theme
        if not show_disclaimer(root, theme):
            root.destroy()
            return 0

        # Bring the real window up front (Tk 9.0 / Windows can open it behind).
        root.deiconify()
        root.lift()
        try:
            root.attributes("-topmost", True)
            root.after(300, lambda: root.attributes("-topmost", False))
        except Exception:
            pass
        root.focus_force()

        AyaApp(root)
        root.mainloop()
        return 0
    except Exception as exc:  # any startup failure becomes visible + logged
        logpath, tb = _log_crash(exc)
        _show_error(tb, logpath)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
