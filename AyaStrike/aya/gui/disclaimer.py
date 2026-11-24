"""Startup legal disclaimer modal.

The app does not proceed until the operator affirms authorised use. The choice
is recorded (with a hash) in the user's config directory so there's a record
that the disclaimer was shown and accepted.
"""

from __future__ import annotations

import hashlib
import time
import tkinter as tk
from tkinter import ttk

from aya import LEGAL_BANNER, __app_name__, __version__
from aya.core.config import app_home
from aya.gui.theme import palette


class DisclaimerDialog(tk.Toplevel):
    def __init__(self, master, theme="dark"):
        super().__init__(master)
        self.accepted = False
        c = palette(theme)
        self.title(f"{__app_name__} — Legal Notice")
        self.configure(bg=c["bg"])
        self.resizable(False, False)
        # Only mark transient if the master is actually on screen. A transient
        # child of a withdrawn/hidden root is never drawn on Windows, which
        # would hang the app on an invisible dialog.
        try:
            if master is not None and master.winfo_viewable():
                self.transient(master)
        except Exception:
            pass

        wrap = ttk.Frame(self, padding=24)
        wrap.pack(fill="both", expand=True)

        ttk.Label(wrap, text=f"⚠  {__app_name__} v{__version__}",
                  style="Title.TLabel").pack(anchor="w")
        ttk.Label(wrap, text="Authorised Use Only", style="Muted.TLabel").pack(
            anchor="w", pady=(0, 12))

        box = tk.Text(wrap, width=72, height=11, wrap="word", relief="flat",
                      bg=c["panel"], fg=c["fg"], padx=14, pady=12,
                      font=("Segoe UI", 10))
        box.insert("1.0", LEGAL_BANNER + "\n\n"
                   "By continuing you confirm that:\n"
                   "  • You will only test systems you own or are explicitly, "
                   "contractually authorised to test.\n"
                   "  • You will stay within the agreed scope and rules of engagement.\n"
                   "  • You accept full responsibility for your use of this tool.\n\n"
                   "Intrusive capabilities (online credential testing, exploit "
                   "launching) are disabled by default and require separate, "
                   "explicit authorisation inside the app.")
        box.configure(state="disabled")
        box.pack()

        self.var = tk.IntVar(value=0)
        ttk.Checkbutton(wrap, variable=self.var,
                        text="I have read and agree, and I am authorised to test my targets.",
                        command=self._toggle).pack(anchor="w", pady=14)

        btns = ttk.Frame(wrap)
        btns.pack(fill="x")
        ttk.Button(btns, text="Exit", command=self._decline).pack(side="right", padx=6)
        self.accept_btn = ttk.Button(btns, text="Accept & Continue",
                                     style="Accent.TButton", command=self._accept,
                                     state="disabled")
        self.accept_btn.pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._decline)
        self.update_idletasks()
        self._center()
        self._make_visible()

    def _center(self):
        # Centre on screen (works whether or not the master is visible).
        self.update_idletasks()
        w = self.winfo_reqwidth() or 520
        h = self.winfo_reqheight() or 420
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry("+%d+%d" % (max((sw - w) // 2, 0), max((sh - h) // 3, 0)))

    def _make_visible(self):
        """Force the dialog to actually appear and take focus, then grab.

        grab_set() before the window is viewable raises on some platforms, so
        we wait for visibility first. This is what prevents the app from
        hanging on an undrawn dialog."""
        self.deiconify()
        self.lift()
        try:
            self.attributes("-topmost", True)
            self.after(400, lambda: self._safe_untop())
        except Exception:
            pass
        try:
            self.wait_visibility()
        except Exception:
            pass
        try:
            self.grab_set()
        except Exception:
            pass
        self.focus_force()

    def _safe_untop(self):
        try:
            self.attributes("-topmost", False)
        except Exception:
            pass

    def _toggle(self):
        self.accept_btn.configure(state="normal" if self.var.get() else "disabled")

    def _accept(self):
        self.accepted = True
        rec = f"{time.time()}:accepted:v{__version__}"
        try:
            (app_home() / "disclaimer_accepted.txt").write_text(
                rec + "\n" + hashlib.sha256(rec.encode()).hexdigest())
        except OSError:
            pass
        self.destroy()

    def _decline(self):
        self.accepted = False
        self.destroy()


def show_disclaimer(master, theme="dark") -> bool:
    dlg = DisclaimerDialog(master, theme)
    master.wait_window(dlg)
    return dlg.accepted
