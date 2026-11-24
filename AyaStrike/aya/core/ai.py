"""Local AI helper (Ollama), with graceful heuristic fallback.

Matches AyaRecon's design: the AI layer is a LOCAL Ollama model so no findings
ever leave the operator's machine. If Ollama is not running / not installed,
every function degrades to a deterministic heuristic so reporting still works.
"""

from __future__ import annotations

import json

from aya.core import net


def available(settings) -> bool:
    try:
        res = net.http_get(settings.ollama_host + "/api/tags", settings, timeout=3)
        return res.status == 200
    except Exception:
        return False


def generate(prompt: str, settings, system: str = "", timeout: float = 120.0) -> str:
    """Call Ollama's /api/generate. Returns '' if unavailable."""
    if not settings.ai_enabled:
        return ""
    try:
        import requests
        payload = {
            "model": settings.ollama_model,
            "prompt": prompt,
            "system": system or ("You are a senior penetration tester writing a "
                                 "concise, accurate, professional security report. "
                                 "Never invent findings; only use what is provided."),
            "stream": False,
            "options": {"temperature": 0.2},
        }
        r = requests.post(settings.ollama_host + "/api/generate",
                          json=payload, timeout=timeout)
        if r.status_code == 200:
            return r.json().get("response", "").strip()
    except Exception:
        return ""
    return ""
