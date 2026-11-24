#!/usr/bin/env bash
# AyaStrike launcher for Linux / macOS.
#   chmod +x run_aya.sh   (first time)
#   ./run_aya.sh
cd "$(dirname "$0")" || exit 1

if command -v python3 >/dev/null 2>&1; then
    python3 main.py
else
    echo "python3 not found. Install Python 3 (and python3-tk on Linux)."
    exit 1
fi
