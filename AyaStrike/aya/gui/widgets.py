"""Reusable GUI widgets: the module runner panel and the findings table.

``ModulePanel`` renders a form from a module's declared ``inputs`` and runs it on
a background thread, streaming events and findings back to the Tk main loop via a
queue. This is the heart of the data-driven UI — it works for any module.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog
from typing import Type

from aya.core import plugins
from aya.core.authz import NotAuthorised
from aya.core.ratelimit import Throttle
from aya.core.scope import ScopeViolation
from aya.gui.theme import palette, SEVERITY_COLORS
from aya.modules.base import BaseModule, Event, Finding


class ModulePanel(ttk.Frame):
    """A form + run/stop + live console for a single module."""

    def __init__(self, master, app, module_cls: Type[BaseModule], theme="dark"):
        super().__init__(master, style="Panel.TFrame", padding=14)
        self.app = app
        self.module_cls = module_cls
        self.c = palette(theme)
        self._queue: "queue.Queue" = queue.Queue()
        self._throttle: Throttle | None = None
        self._thread: threading.Thread | None = None
        self.vars: dict[str, tk.Variable] = {}
        self._build()

    # -- form construction ------------------------------------------------
    def _build(self):
        header = ttk.Frame(self, style="Panel.TFrame")
        header.pack(fill="x")
        title = self.module_cls.name
        if self.module_cls.disabled_by_default:
            title += "   ⛔ gated"
        ttk.Label(header, text=title, style="H2.TLabel").pack(side="left")
        ttk.Label(self, text=self.module_cls.description, style="Panel.TLabel",
                  wraplength=560).pack(anchor="w", pady=(2, 10))

        form = ttk.Frame(self, style="Panel.TFrame")
        form.pack(fill="x")
        for i, inp in enumerate(self.module_cls.inputs):
            ttk.Label(form, text=inp.label + (" *" if inp.required else ""),
                      style="Panel.TLabel").grid(row=i, column=0, sticky="nw",
                                                 padx=(0, 10), pady=4)
            widget = self._make_widget(form, inp)
            widget.grid(row=i, column=1, sticky="ew", pady=4)
            if inp.help:
                ttk.Label(form, text=inp.help, style="Muted.TLabel",
                          wraplength=360).grid(row=i, column=2, sticky="w", padx=8)
        form.columnconfigure(1, weight=1)

        bar = ttk.Frame(self, style="Panel.TFrame")
        bar.pack(fill="x", pady=(10, 6))
        self.run_btn = ttk.Button(bar, text="▶  Run", style="Accent.TButton",
                                  command=self._run)
        self.run_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="■ Stop", command=self._stop,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        self.status = ttk.Label(bar, text="idle", style="Muted.TLabel")
        self.status.pack(side="left", padx=12)

        self.console = tk.Text(self, height=12, wrap="word", relief="flat",
                               bg=self.c["entry"], fg=self.c["fg"],
                               insertbackground=self.c["fg"], font=("Consolas", 9))
        self.console.pack(fill="both", expand=True, pady=(6, 0))
        for level, col in (("info", self.c["muted"]), ("success", self.c["ok"]),
                           ("warn", self.c["warn"]), ("error", self.c["err"]),
                           ("finding", self.c["accent"])):
            self.console.tag_configure(level, foreground=col)
        self.console.configure(state="disabled")

    def _make_widget(self, parent, inp):
        if inp.kind == "bool":
            var = tk.IntVar(value=1 if inp.default else 0)
            self.vars[inp.key] = var
            return ttk.Checkbutton(parent, variable=var)
        if inp.kind == "choice":
            var = tk.StringVar(value=str(inp.default))
            self.vars[inp.key] = var
            return ttk.Combobox(parent, textvariable=var, values=inp.choices,
                                state="readonly")
        if inp.kind == "multiline":
            txt = tk.Text(parent, height=4, width=48, relief="flat",
                          bg=self.c["entry"], fg=self.c["fg"],
                          insertbackground=self.c["fg"], font=("Consolas", 9))
            if inp.default:
                txt.insert("1.0", str(inp.default))
            self.vars[inp.key] = _TextVar(txt)
            return txt
        if inp.kind == "file":
            frame = ttk.Frame(parent, style="Panel.TFrame")
            var = tk.StringVar(value=str(inp.default))
            self.vars[inp.key] = var
            ttk.Entry(frame, textvariable=var).pack(side="left", fill="x", expand=True)
            ttk.Button(frame, text="…", width=3,
                       command=lambda v=var: v.set(filedialog.askopenfilename() or v.get())
                       ).pack(side="left", padx=4)
            return frame
        # text / int / float / password
        var = tk.StringVar(value=str(inp.default))
        self.vars[inp.key] = var
        show = "*" if inp.kind == "password" else ""
        return ttk.Entry(parent, textvariable=var, show=show)

    # -- run lifecycle ----------------------------------------------------
    def _collect(self) -> dict:
        params = {}
        for inp in self.module_cls.inputs:
            raw = self.vars[inp.key].get()
            if inp.kind == "bool":
                params[inp.key] = bool(raw)
            elif inp.kind == "int":
                try:
                    params[inp.key] = int(raw)
                except (ValueError, TypeError):
                    params[inp.key] = inp.default
            elif inp.kind == "float":
                try:
                    params[inp.key] = float(raw)
                except (ValueError, TypeError):
                    params[inp.key] = inp.default
            else:
                params[inp.key] = raw
        return params

    def _run(self):
        ws = self.app.workspace
        if ws is None:
            self._log("No active project. Create/open one in the Project menu.", "error")
            return
        # Gate check with dialog if needed.
        cap = self.module_cls.requires_authz
        if cap and not ws.authz.is_authorised(cap):
            from aya.gui.authz_dialog import request_authorization
            granted = request_authorization(self.app.root, ws.authz, cap, self.app.theme_name)
            ws.audit.log("authz_grant" if granted else "authz_declined",
                         module=self.module_cls.id, detail={"capability": cap},
                         severity="warn")
            if not granted:
                self._log("Authorisation declined — module not run.", "warn")
                return

        params = self._collect()
        self._throttle = Throttle(ws.config.settings.rate_limit_per_sec,
                                  ws.config.settings.max_concurrency)
        self.run_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status.configure(text="running…")
        self._clear()

        def worker():
            try:
                plugins.execute(
                    self.module_cls.id, ws, params, self._throttle,
                    on_event=lambda e: self._queue.put(("event", e)),
                    on_finding=lambda f: self._queue.put(("finding", f)),
                )
                self._queue.put(("done", None))
            except ScopeViolation as e:
                self._queue.put(("event", Event(f"SCOPE VIOLATION: {e}", "error")))
                self._queue.put(("done", None))
            except NotAuthorised as e:
                self._queue.put(("event", Event(str(e), "error")))
                self._queue.put(("done", None))
            except Exception as e:  # pragma: no cover
                self._queue.put(("event", Event(f"Error: {e}", "error")))
                self._queue.put(("done", None))

        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()
        self.after(80, self._drain)

    def _drain(self):
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "event":
                    self._log(payload.message, payload.level)
                elif kind == "finding":
                    self._log(f"✔ {payload.severity.value.upper()}: {payload.title}",
                              "finding")
                    self.app.on_finding(payload)
                elif kind == "done":
                    self._finish()
                    return
        except queue.Empty:
            pass
        self.after(80, self._drain)

    def _finish(self):
        self.run_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status.configure(text="done")

    def _stop(self):
        if self._throttle:
            self._throttle.cancel.cancel()
        self.status.configure(text="stopping…")

    # -- console ----------------------------------------------------------
    def _log(self, msg, level="info"):
        self.console.configure(state="normal")
        self.console.insert("end", msg + "\n", level)
        self.console.see("end")
        self.console.configure(state="disabled")

    def _clear(self):
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")


class _TextVar:
    """Adapter so a tk.Text behaves like a Variable with get()."""

    def __init__(self, text_widget):
        self._t = text_widget

    def get(self):
        return self._t.get("1.0", "end").rstrip("\n")

    def set(self, value):
        self._t.delete("1.0", "end")
        self._t.insert("1.0", value)
