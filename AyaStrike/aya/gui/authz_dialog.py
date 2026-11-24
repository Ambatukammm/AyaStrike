"""Authorisation dialog for intrusive capabilities.

Shows a prominent RED legal warning, a written-permission confirmation
checkbox, and requires the operator to type the confirmation phrase before an
intrusive capability (online credential testing / exploit launching) is enabled
for the session. Grants are in-memory only and audit-logged by the caller.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from aya.core.authz import CONFIRM_PHRASE, AuthorizationGate
from aya.gui.theme import palette


class AuthorizationDialog(tk.Toplevel):
    def __init__(self, master, gate: AuthorizationGate, capability: str,
                 theme="dark"):
        super().__init__(master)
        self.gate = gate
        self.capability = capability
        self.granted = False
        c = palette(theme)
        self.title("Authorisation Required")
        self.configure(bg=c["bg"])
        self.resizable(False, False)
        try:
            if master is not None and master.winfo_viewable():
                self.transient(master)
        except Exception:
            pass

        label = AuthorizationGate.GATED.get(capability, capability)

        wrap = ttk.Frame(self, padding=22)
        wrap.pack(fill="both", expand=True)

        banner = tk.Label(
            wrap, text="⛔  INTRUSIVE CAPABILITY — WRITTEN AUTHORISATION REQUIRED",
            bg=c["err"], fg="#ffffff", font=("Segoe UI", 11, "bold"),
            padx=12, pady=10)
        banner.pack(fill="x")

        msg = tk.Text(wrap, width=68, height=9, wrap="word", relief="flat",
                      bg=c["panel"], fg=c["fg"], padx=14, pady=12,
                      font=("Segoe UI", 10))
        msg.insert("1.0",
                   f"You are about to enable: {label}.\n\n"
                   "This capability actively interacts with target systems and may "
                   "cause account lockouts, service disruption, or be unlawful if "
                   "performed without authorisation.\n\n"
                   "Only enable this if you hold CURRENT, WRITTEN permission to "
                   "perform this activity against every target in your scope, and "
                   "you are operating within the agreed rules of engagement.\n\n"
                   "This grant lasts for the current session only and every use is "
                   "permanently recorded in the audit log.")
        msg.configure(state="disabled")
        msg.pack(pady=(10, 6))

        self.chk = tk.IntVar(value=0)
        ttk.Checkbutton(
            wrap, variable=self.chk, command=self._update,
            text="I confirm I have WRITTEN authorisation to test all targets in scope."
        ).pack(anchor="w", pady=(6, 10))

        ttk.Label(wrap, text=f'Type the phrase to confirm:  "{CONFIRM_PHRASE}"',
                  style="Muted.TLabel").pack(anchor="w")
        self.entry = ttk.Entry(wrap, width=52)
        self.entry.pack(anchor="w", pady=(2, 4), fill="x")
        self.entry.bind("<KeyRelease>", lambda e: self._update())

        self.note = ttk.Entry(wrap, width=52)
        ttk.Label(wrap, text="Engagement / authorisation reference (optional):",
                  style="Muted.TLabel").pack(anchor="w", pady=(8, 0))
        self.note.pack(anchor="w", pady=(2, 10), fill="x")

        btns = ttk.Frame(wrap)
        btns.pack(fill="x")
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right", padx=6)
        self.ok = ttk.Button(btns, text="Authorise", style="Danger.TButton",
                             command=self._grant, state="disabled")
        self.ok.pack(side="right")

        self.update_idletasks()
        w = self.winfo_reqwidth() or 520
        h = self.winfo_reqheight() or 460
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry("+%d+%d" % (max((sw - w) // 2, 0), max((sh - h) // 3, 0)))
        self.deiconify()
        self.lift()
        try:
            self.attributes("-topmost", True)
            self.after(400, lambda: self.attributes("-topmost", False))
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

    def _update(self):
        ok = self.chk.get() and self.entry.get().strip().upper() == CONFIRM_PHRASE
        self.ok.configure(state="normal" if ok else "disabled")

    def _grant(self):
        if self.gate.grant(self.capability, self.entry.get(), note=self.note.get()):
            self.granted = True
        self.destroy()


def request_authorization(master, gate, capability, theme="dark") -> bool:
    dlg = AuthorizationDialog(master, gate, capability, theme)
    master.wait_window(dlg)
    return dlg.granted
