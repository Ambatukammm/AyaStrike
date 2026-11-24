"""Theming for AyaStrike — a modern dark UI with a striking red accent."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

# Primary look: deep near-black with a bold "strike red" accent.
RED = {
    "bg": "#0b0b0e",         # app background (near black)
    "panel": "#141419",      # cards / panels
    "panel2": "#1c1c23",     # raised controls
    "elev": "#26262e",       # hover / selected row
    "fg": "#f3f3f5",         # primary text
    "muted": "#8b8b97",      # secondary text
    "accent": "#e01e37",     # strike red
    "accent2": "#ff3b52",    # brighter red (hover/active)
    "accentdim": "#5c0f1b",  # dim red (borders/underlines)
    "border": "#2b2b35",
    "entry": "#0f0f14",
    "ok": "#3fb950", "warn": "#e3a008", "err": "#ff4d4d", "crit": "#ff2d55",
}
DARK = dict(RED, accent="#58a6ff", accent2="#79b8ff", accentdim="#1f3b5c")
LIGHT = {
    "bg": "#f4f4f6", "panel": "#ffffff", "panel2": "#ececed", "elev": "#e2e2e6",
    "fg": "#17171a", "muted": "#60606a", "accent": "#d11a30", "accent2": "#ff3b52",
    "accentdim": "#f3c0c6", "border": "#d6d6dc", "entry": "#ffffff",
    "ok": "#1a7f37", "warn": "#9a6700", "err": "#cf222e", "crit": "#a40e26",
}

SEVERITY_COLORS = {
    "critical": "#ff2d55", "high": "#ff6b2d", "medium": "#e3a008",
    "low": "#3fb950", "info": "#7d8590",
}

_FONT = "Segoe UI"
_MONO = "Consolas"


def palette(name: str) -> dict:
    return {"red": RED, "dark": DARK, "light": LIGHT}.get(name, RED)


def apply_theme(root: tk.Tk, name: str = "red") -> dict:
    c = palette(name)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    root.configure(bg=c["bg"])

    base = (_FONT, 10)
    style.configure(".", background=c["bg"], foreground=c["fg"],
                    fieldbackground=c["entry"], bordercolor=c["border"],
                    font=base, focuscolor=c["accent"])

    # Frames / labels
    style.configure("TFrame", background=c["bg"])
    style.configure("Panel.TFrame", background=c["panel"])
    style.configure("Card.TFrame", background=c["panel"], relief="flat")
    style.configure("Accent.TFrame", background=c["accent"])
    style.configure("TLabel", background=c["bg"], foreground=c["fg"], font=base)
    style.configure("Muted.TLabel", background=c["bg"], foreground=c["muted"],
                    font=(_FONT, 9))
    style.configure("Panel.TLabel", background=c["panel"], foreground=c["fg"])
    style.configure("PanelMuted.TLabel", background=c["panel"], foreground=c["muted"],
                    font=(_FONT, 9))
    style.configure("Brand.TLabel", background=c["bg"], foreground=c["fg"],
                    font=(_FONT, 20, "bold"))
    style.configure("BrandAccent.TLabel", background=c["bg"], foreground=c["accent"],
                    font=(_FONT, 20, "bold"))
    style.configure("Title.TLabel", background=c["bg"], foreground=c["fg"],
                    font=(_FONT, 15, "bold"))
    style.configure("H2.TLabel", background=c["panel"], foreground=c["accent2"],
                    font=(_FONT, 12, "bold"))

    # Buttons
    style.configure("TButton", background=c["panel2"], foreground=c["fg"],
                    borderwidth=0, focusthickness=0, padding=(12, 7), font=base)
    style.map("TButton",
              background=[("active", c["elev"]), ("pressed", c["elev"])],
              foreground=[("active", c["fg"])])
    style.configure("Accent.TButton", background=c["accent"], foreground="#ffffff",
                    borderwidth=0, padding=(14, 8), font=(_FONT, 10, "bold"))
    style.map("Accent.TButton",
              background=[("active", c["accent2"]), ("pressed", c["accentdim"])],
              foreground=[("active", "#ffffff")])
    style.configure("Danger.TButton", background=c["accent"], foreground="#ffffff",
                    borderwidth=0, padding=(14, 8), font=(_FONT, 10, "bold"))
    style.map("Danger.TButton",
              background=[("active", c["accent2"]), ("pressed", c["accentdim"])])
    style.configure("Ghost.TButton", background=c["panel"], foreground=c["muted"],
                    borderwidth=0, padding=(10, 6))
    style.map("Ghost.TButton", background=[("active", c["panel2"])],
              foreground=[("active", c["fg"])])

    # Inputs
    style.configure("TEntry", fieldbackground=c["entry"], foreground=c["fg"],
                    insertcolor=c["accent2"], borderwidth=1, padding=5)
    style.map("TEntry", bordercolor=[("focus", c["accent"])])
    style.configure("TCombobox", fieldbackground=c["entry"], foreground=c["fg"],
                    arrowcolor=c["accent2"], padding=4)
    style.map("TCombobox", fieldbackground=[("readonly", c["entry"])],
              bordercolor=[("focus", c["accent"])])
    style.configure("TCheckbutton", background=c["panel"], foreground=c["fg"],
                    focuscolor=c["accent"])
    style.map("TCheckbutton", indicatorcolor=[("selected", c["accent"])],
              background=[("active", c["panel"])])

    # Notebook (phase tabs)
    style.configure("TNotebook", background=c["bg"], borderwidth=0, tabmargins=(6, 6, 6, 0))
    style.configure("TNotebook.Tab", background=c["bg"], foreground=c["muted"],
                    padding=(16, 9), font=(_FONT, 10), borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected", c["panel"])],
              foreground=[("selected", c["accent2"]), ("active", c["fg"])])

    # Treeview (findings / audit)
    style.configure("Treeview", background=c["entry"], fieldbackground=c["entry"],
                    foreground=c["fg"], rowheight=26, borderwidth=0, font=(_FONT, 9))
    style.configure("Treeview.Heading", background=c["panel2"], foreground=c["muted"],
                    font=(_FONT, 9, "bold"), relief="flat", padding=6)
    style.map("Treeview.Heading", background=[("active", c["elev"])])
    style.map("Treeview", background=[("selected", c["accentdim"])],
              foreground=[("selected", "#ffffff")])

    # Panedwindow / scrollbars
    style.configure("TPanedwindow", background=c["bg"])
    style.configure("Vertical.TScrollbar", background=c["panel2"], troughcolor=c["bg"],
                    borderwidth=0, arrowcolor=c["muted"])
    style.map("Vertical.TScrollbar", background=[("active", c["accent"])])
    style.configure("Horizontal.TScrollbar", background=c["panel2"], troughcolor=c["bg"],
                    borderwidth=0, arrowcolor=c["muted"])
    return c
