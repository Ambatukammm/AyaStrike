"""Main application window for AyaStrike."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from aya import __app_name__, __version__
from aya.core import plugins
from aya.core.config import get_config
from aya.core.workspace import Workspace, list_projects
from aya.gui.theme import apply_theme, palette, SEVERITY_COLORS
from aya.gui.widgets import ModulePanel
from aya.modules.base import Phase


class AyaApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.config = get_config()
        self.theme_name = self.config.settings.theme
        self.c = apply_theme(root, self.theme_name)
        self.workspace: Workspace | None = None

        root.title(f"{__app_name__} v{__version__} — made by Ruel")
        root.geometry("1180x780")
        root.minsize(980, 640)

        self._build_menu()
        self._build_layout()
        plugins.discover()
        self._populate_tabs()
        self._open_last_or_new()

    # -- menu -------------------------------------------------------------
    def _build_menu(self):
        menu = tk.Menu(self.root)
        proj = tk.Menu(menu, tearoff=0)
        proj.add_command(label="New Project…", command=self.new_project)
        proj.add_command(label="Open Project…", command=self.open_project)
        proj.add_separator()
        proj.add_command(label="Exit", command=self.root.quit)
        menu.add_cascade(label="Project", menu=proj)

        tools = tk.Menu(menu, tearoff=0)
        tools.add_command(label="Verify Audit Log", command=self.verify_audit)
        tools.add_command(label="Revoke All Authorisations",
                          command=self.revoke_authz)
        menu.add_cascade(label="Tools", menu=tools)

        helpm = tk.Menu(menu, tearoff=0)
        helpm.add_command(label="About", command=self.about)
        helpm.add_command(label="Legal / Responsible Use", command=self.legal)
        menu.add_cascade(label="Help", menu=helpm)
        self.root.config(menu=menu)

    # -- layout -----------------------------------------------------------
    def _build_layout(self):
        top = ttk.Frame(self.root, padding=(12, 8))
        top.pack(fill="x")
        # Brand wordmark: "Aya" in white, "Strike" in red.
        brand = ttk.Frame(top)
        brand.pack(side="left")
        ttk.Label(brand, text="Aya", style="Brand.TLabel").pack(side="left")
        ttk.Label(brand, text="Strike", style="BrandAccent.TLabel").pack(side="left")
        ttk.Label(top, text="Offensive Security Toolkit · made by Ruel",
                  style="Muted.TLabel").pack(side="left", padx=(14, 0), pady=(10, 0))
        self.authz_label = ttk.Label(top, text="", style="Muted.TLabel")
        self.authz_label.pack(side="right", pady=(10, 0))
        self.proj_label = ttk.Label(top, text="no project", style="Muted.TLabel")
        self.proj_label.pack(side="right", padx=16, pady=(10, 0))

        # Red accent bar under the header.
        accent = tk.Frame(self.root, bg=self.c["accent"], height=3)
        accent.pack(fill="x", padx=12, pady=(2, 0))

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(6, 6))

        self.status = ttk.Label(self.root, text="Ready", style="Muted.TLabel",
                                anchor="w", padding=(12, 4))
        self.status.pack(fill="x")

    def _populate_tabs(self):
        by_phase = plugins.by_phase()
        # One tab per lifecycle phase, each with a left module list + right panel.
        for phase in Phase:
            modules = by_phase.get(phase.value, [])
            tab = self._phase_tab(modules)
            self.nb.add(tab, text=phase.value)
        # Extra tabs
        self.nb.add(self._scope_tab(), text="◈ Scope")
        self.nb.add(self._findings_tab(), text="◈ Findings")
        self.nb.add(self._audit_tab(), text="◈ Audit")
        self.nb.add(self._guide_tab(), text="📘 Guide")
        self.nb.add(self._settings_tab(), text="◈ Settings")

    # -- guide / tutorial tab --------------------------------------------
    def _guide_tab(self):
        frame = ttk.Frame(self.nb, padding=12)
        ttk.Label(frame, text="How to use AyaStrike", style="Title.TLabel").pack(anchor="w")
        ttk.Label(frame, text="Walkthroughs for every phase, including the "
                  "Metasploit exploitation interface. made by Ruel.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        self._tutorial_viewer(frame).pack(fill="both", expand=True)
        return frame

    def _tutorial_viewer(self, parent):
        """A scrollable, read-only view of the tutorial content."""
        from aya.gui.tutorials import as_plain_text
        wrap = ttk.Frame(parent)
        txt = tk.Text(wrap, wrap="word", relief="flat", bg=self.c["entry"],
                      fg=self.c["fg"], insertbackground=self.c["fg"],
                      font=("Consolas", 10), padx=16, pady=14, borderwidth=0)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        # Highlight section titles in red.
        txt.tag_configure("title", foreground=self.c["accent2"],
                          font=("Consolas", 11, "bold"), spacing1=10, spacing3=4)
        for line in as_plain_text().splitlines():
            if line and not line.startswith(" ") and (line[0].isdigit() and ". " in line[:5]):
                txt.insert("end", line + "\n", "title")
            elif set(line) == {"-"}:
                continue
            else:
                txt.insert("end", line + "\n")
        txt.configure(state="disabled")
        sb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        return wrap

    def _phase_tab(self, modules):
        frame = ttk.Frame(self.nb)
        if not modules:
            ttk.Label(frame, text="No modules in this phase.",
                      style="Muted.TLabel").pack(pady=40)
            return frame
        paned = ttk.PanedWindow(frame, orient="horizontal")
        paned.pack(fill="both", expand=True)
        left = ttk.Frame(paned, width=220)
        right = ttk.Frame(paned)
        paned.add(left, weight=0)
        paned.add(right, weight=1)

        lb = tk.Listbox(left, bg=self.c["panel"], fg=self.c["fg"],
                        selectbackground=self.c["accent"], relief="flat",
                        highlightthickness=0, font=("Segoe UI", 10), activestyle="none")
        lb.pack(fill="both", expand=True, padx=6, pady=6)
        for m in modules:
            lb.insert("end", ("⛔ " if m.disabled_by_default else "  ") + m.name)

        panels: dict[int, ModulePanel] = {}

        def show(_evt=None):
            sel = lb.curselection()
            if not sel:
                return
            idx = sel[0]
            for p in panels.values():
                p.pack_forget()
            if idx not in panels:
                panels[idx] = ModulePanel(right, self, modules[idx], self.theme_name)
            panels[idx].pack(fill="both", expand=True)

        lb.bind("<<ListboxSelect>>", show)
        lb.selection_set(0)
        self.root.after(100, show)
        return frame

    # -- scope tab --------------------------------------------------------
    def _scope_tab(self):
        frame = ttk.Frame(self.nb, padding=16)
        ttk.Label(frame, text="Authorised Target Scope", style="Title.TLabel").pack(anchor="w")
        ttk.Label(frame, text="Only targets in this whitelist can be probed. "
                  "Private/loopback ranges are allowed by default. Deny entries win.",
                  style="Muted.TLabel", wraplength=800).pack(anchor="w", pady=(0, 10))

        body = ttk.Frame(frame)
        body.pack(fill="both", expand=True)
        # allow
        al = ttk.Frame(body)
        al.pack(side="left", fill="both", expand=True, padx=(0, 8))
        ttk.Label(al, text="Allow", style="H2.TLabel").pack(anchor="w")
        self.allow_list = tk.Listbox(al, bg=self.c["entry"], fg=self.c["fg"],
                                     relief="flat", highlightthickness=0)
        self.allow_list.pack(fill="both", expand=True, pady=4)
        ae = ttk.Frame(al)
        ae.pack(fill="x")
        self.allow_entry = ttk.Entry(ae)
        self.allow_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(ae, text="Add", command=self._add_allow).pack(side="left", padx=4)
        ttk.Button(ae, text="Remove", command=lambda: self._remove_scope(self.allow_list)
                   ).pack(side="left")
        # deny
        dn = ttk.Frame(body)
        dn.pack(side="left", fill="both", expand=True, padx=(8, 0))
        ttk.Label(dn, text="Deny", style="H2.TLabel").pack(anchor="w")
        self.deny_list = tk.Listbox(dn, bg=self.c["entry"], fg=self.c["fg"],
                                    relief="flat", highlightthickness=0)
        self.deny_list.pack(fill="both", expand=True, pady=4)
        de = ttk.Frame(dn)
        de.pack(fill="x")
        self.deny_entry = ttk.Entry(de)
        self.deny_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(de, text="Add", command=self._add_deny).pack(side="left", padx=4)
        ttk.Button(de, text="Remove", command=lambda: self._remove_scope(self.deny_list)
                   ).pack(side="left")

        opts = ttk.Frame(frame)
        opts.pack(fill="x", pady=10)
        self.enforce_var = tk.IntVar(value=1)
        ttk.Checkbutton(opts, text="Enforce scope (strongly recommended)",
                        variable=self.enforce_var,
                        command=self._toggle_enforce).pack(side="left")
        ttk.Button(opts, text="Save Scope", style="Accent.TButton",
                   command=self._save_scope).pack(side="right")
        return frame

    def _refresh_scope_lists(self):
        if not self.workspace:
            return
        self.allow_list.delete(0, "end")
        self.deny_list.delete(0, "end")
        for a in self.workspace.scope.allow:
            self.allow_list.insert("end", a)
        for d in self.workspace.scope.deny:
            self.deny_list.insert("end", d)
        self.enforce_var.set(1 if self.workspace.scope.enforce else 0)

    def _add_allow(self):
        if self.workspace and self.allow_entry.get().strip():
            try:
                self.workspace.scope.add(self.allow_entry.get().strip())
                self.allow_entry.delete(0, "end")
                self._refresh_scope_lists()
            except ValueError as e:
                messagebox.showerror("Invalid entry", str(e))

    def _add_deny(self):
        if self.workspace and self.deny_entry.get().strip():
            try:
                self.workspace.scope.add_deny(self.deny_entry.get().strip())
                self.deny_entry.delete(0, "end")
                self._refresh_scope_lists()
            except ValueError as e:
                messagebox.showerror("Invalid entry", str(e))

    def _remove_scope(self, listbox):
        sel = listbox.curselection()
        if self.workspace and sel:
            self.workspace.scope.remove(listbox.get(sel[0]))
            self._refresh_scope_lists()

    def _toggle_enforce(self):
        if self.workspace:
            if not self.enforce_var.get():
                if not messagebox.askyesno(
                        "Disable scope enforcement?",
                        "Disabling scope enforcement removes the guard that keeps you "
                        "from touching out-of-scope hosts. Only do this in an isolated "
                        "lab you fully control. Continue?"):
                    self.enforce_var.set(1)
                    return
            self.workspace.scope.enforce = bool(self.enforce_var.get())

    def _save_scope(self):
        if self.workspace:
            self.workspace.save_scope()
            self.status.configure(text="Scope saved.")

    # -- findings tab -----------------------------------------------------
    def _findings_tab(self):
        frame = ttk.Frame(self.nb, padding=10)
        bar = ttk.Frame(frame)
        bar.pack(fill="x")
        self.risk_label = ttk.Label(bar, text="Risk: —", style="Title.TLabel")
        self.risk_label.pack(side="left")
        ttk.Button(bar, text="Refresh", command=self.refresh_findings).pack(side="right")
        cols = ("sev", "title", "target", "module", "cve")
        self.find_tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col, w in (("sev", 80), ("title", 420), ("target", 160),
                       ("module", 150), ("cve", 150)):
            self.find_tree.heading(col, text=col.upper())
            self.find_tree.column(col, width=w, anchor="w")
        for sev, col in SEVERITY_COLORS.items():
            self.find_tree.tag_configure(sev, foreground=col)
        self.find_tree.pack(fill="both", expand=True, pady=8)
        return frame

    def refresh_findings(self):
        if not self.workspace:
            return
        for i in self.find_tree.get_children():
            self.find_tree.delete(i)
        findings = self.workspace.findings()
        from aya.modules.reporting.risk_engine import risk_score, SEV_ORDER
        order = {s: i for i, s in enumerate(SEV_ORDER)}
        for f in sorted(findings, key=lambda x: order.get(x["severity"], 9)):
            self.find_tree.insert("", "end", tags=(f["severity"],),
                                  values=(f["severity"].upper(), f["title"],
                                          f["target"], f["module"],
                                          ",".join(f.get("cve", []))))
        r = risk_score(findings)
        self.risk_label.configure(text=f"Risk: {r['score']}/100 ({r['rating']})  ·  "
                                       f"{r['total']} findings")

    def on_finding(self, finding):
        self.refresh_findings()

    # -- audit tab --------------------------------------------------------
    def _audit_tab(self):
        frame = ttk.Frame(self.nb, padding=10)
        bar = ttk.Frame(frame)
        bar.pack(fill="x")
        ttk.Label(bar, text="Audit Log", style="Title.TLabel").pack(side="left")
        ttk.Button(bar, text="Refresh", command=self.refresh_audit).pack(side="right")
        ttk.Button(bar, text="Verify Integrity", command=self.verify_audit
                   ).pack(side="right", padx=6)
        cols = ("time", "action", "module", "target", "sev")
        self.audit_tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col, w in (("time", 160), ("action", 160), ("module", 150),
                       ("target", 180), ("sev", 80)):
            self.audit_tree.heading(col, text=col.upper())
            self.audit_tree.column(col, width=w)
        self.audit_tree.pack(fill="both", expand=True, pady=8)
        return frame

    def refresh_audit(self):
        if not self.workspace:
            return
        for i in self.audit_tree.get_children():
            self.audit_tree.delete(i)
        for rec in reversed(self.workspace.audit.tail(400)):
            self.audit_tree.insert("", "end", values=(
                rec.get("iso", ""), rec.get("action", ""), rec.get("module") or "",
                rec.get("target") or "", rec.get("severity", "")))

    # -- settings tab -----------------------------------------------------
    def _settings_tab(self):
        frame = ttk.Frame(self.nb, padding=16)
        ttk.Label(frame, text="Settings", style="Title.TLabel").pack(anchor="w")
        grid = ttk.Frame(frame)
        grid.pack(fill="x", pady=10)
        s = self.config.settings
        self.setting_vars = {}
        fields = [
            ("rate_limit_per_sec", "Rate limit (req/sec)", s.rate_limit_per_sec),
            ("max_concurrency", "Max concurrency", s.max_concurrency),
            ("connect_timeout", "Connect timeout (s)", s.connect_timeout),
            ("nmap_path", "nmap path (blank = auto)", s.nmap_path),
            ("shodan_api_key", "Shodan API key", s.shodan_api_key),
            ("msf_rpc_host", "MSF RPC host", s.msf_rpc_host),
            ("msf_rpc_port", "MSF RPC port", s.msf_rpc_port),
            ("msf_rpc_user", "MSF RPC user", s.msf_rpc_user),
            ("ollama_host", "Ollama host", s.ollama_host),
            ("ollama_model", "Ollama model", s.ollama_model),
        ]
        for i, (key, label, val) in enumerate(fields):
            ttk.Label(grid, text=label, style="TLabel").grid(
                row=i, column=0, sticky="w", padx=(0, 12), pady=4)
            var = tk.StringVar(value=str(val))
            self.setting_vars[key] = var
            show = "*" if "key" in key else ""
            ttk.Entry(grid, textvariable=var, width=42, show=show).grid(
                row=i, column=1, sticky="ew", pady=4)
        grid.columnconfigure(1, weight=1)
        ttk.Button(frame, text="Save Settings", style="Accent.TButton",
                   command=self._save_settings).pack(anchor="w", pady=10)

        # --- Tutorials & Help (as requested, right here in Settings) ---
        ttk.Label(frame, text="Tutorials & Help", style="Title.TLabel").pack(
            anchor="w", pady=(14, 2))
        ttk.Label(frame, text="How to use each phase, including a full "
                  "Metasploit exploitation walkthrough. Also on the 📘 Guide tab.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 6))
        self._tutorial_viewer(frame).pack(fill="both", expand=True)
        return frame

    def _save_settings(self):
        updates = {}
        for key, var in self.setting_vars.items():
            raw = var.get()
            cur = getattr(self.config.settings, key)
            if isinstance(cur, bool):
                updates[key] = raw.lower() in ("1", "true", "yes")
            elif isinstance(cur, int):
                try:
                    updates[key] = int(raw)
                except ValueError:
                    continue
            elif isinstance(cur, float):
                try:
                    updates[key] = float(raw)
                except ValueError:
                    continue
            else:
                updates[key] = raw
        self.config.update(**updates)
        self.status.configure(text="Settings saved.")

    # -- project lifecycle ------------------------------------------------
    def _open_last_or_new(self):
        existing = list_projects()
        if existing:
            self.load_workspace(existing[0])
        else:
            self.new_project(initial=True)

    def new_project(self, initial=False):
        name = simpledialog.askstring("New Project", "Project / engagement name:",
                                      parent=self.root)
        if not name:
            if initial and not self.workspace:
                name = "default"
            else:
                return
        self.load_workspace(name)

    def open_project(self):
        existing = list_projects()
        if not existing:
            messagebox.showinfo("No projects", "No projects yet. Create one first.")
            return
        win = tk.Toplevel(self.root)
        win.title("Open Project")
        win.configure(bg=self.c["bg"])
        lb = tk.Listbox(win, bg=self.c["entry"], fg=self.c["fg"], width=40, height=12)
        lb.pack(padx=12, pady=12)
        for p in existing:
            lb.insert("end", p)

        def choose():
            sel = lb.curselection()
            if sel:
                self.load_workspace(lb.get(sel[0]))
                win.destroy()
        ttk.Button(win, text="Open", style="Accent.TButton", command=choose).pack(pady=6)

    def load_workspace(self, name):
        if self.workspace:
            self.workspace.close()
        self.workspace = Workspace(name)
        self.proj_label.configure(text=f"project: {self.workspace.name}")
        self._refresh_scope_lists()
        self.refresh_findings()
        self.refresh_audit()
        self._update_authz_label()
        self.status.configure(text=f"Opened project '{self.workspace.name}'.")

    def _update_authz_label(self):
        if self.workspace:
            active = self.workspace.authz.active()
            self.authz_label.configure(
                text=("⛔ authorised: " + ", ".join(active)) if active
                else "no intrusive grants")

    # -- tools/help -------------------------------------------------------
    def verify_audit(self):
        if not self.workspace:
            return
        ok, bad = self.workspace.audit.verify()
        if ok:
            messagebox.showinfo("Audit integrity", "Audit log hash chain is intact. ✔")
        else:
            messagebox.showerror("Audit integrity",
                                 f"Audit log integrity FAILED at line {bad}. "
                                 "The log may have been tampered with.")

    def revoke_authz(self):
        if self.workspace:
            self.workspace.authz.revoke_all()
            self.workspace.audit.log("authz_revoke_all", severity="warn")
            self._update_authz_label()
            self.status.configure(text="All intrusive authorisations revoked.")

    def about(self):
        messagebox.showinfo(
            "About",
            f"{__app_name__} v{__version__}\nAll-In-One Penetration Testing Toolkit\n"
            "made by Ruel\n\nFor authorised security testing and education only.")

    def legal(self):
        from aya import LEGAL_BANNER
        messagebox.showinfo("Legal / Responsible Use", LEGAL_BANNER)
