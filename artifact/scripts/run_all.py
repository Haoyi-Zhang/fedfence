#!/usr/bin/env python3
from __future__ import annotations
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]

def cleanup_temp() -> None:
    shutil.rmtree(ROOT / "fedfence" / "__pycache__", ignore_errors=True)
    shutil.rmtree(ROOT / "scripts" / "__pycache__", ignore_errors=True)
    shutil.rmtree(ROOT / "results" / ".mplconfig", ignore_errors=True)
    for suffix in ("aux", "log", "out", "toc"):
        try:
            (ROOT.parent / "paper" / f"main.{suffix}").unlink()
        except FileNotFoundError:
            pass

def main() -> int:
    cleanup_temp()
    script = ROOT / "scripts" / "reproduce_all.sh"
    env = dict(os.environ)
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    try:
        subprocess.run(["bash", str(script)], cwd=str(ROOT), env=env, check=True)
    finally:
        cleanup_temp()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
