#!/usr/bin/env python3
"""Capture the web UI at desktop and phone widths, in both themes, for review.

Usage: python scripts/ui_screenshots.py --base http://127.0.0.1:8766 --out research_out/shots \
           --run <run_id> [--run <run_id> ...]
Needs `pip install playwright`; uses the installed Microsoft Edge (or
Playwright's own Chromium if --browser-path is omitted and it is installed)."""
from __future__ import annotations
import argparse
import os
from pathlib import Path

from playwright.sync_api import sync_playwright

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8765")
    ap.add_argument("--out", default="research_out/shots")
    ap.add_argument("--run", action="append", default=[])
    ap.add_argument("--browser-path", default=EDGE if os.path.exists(EDGE) else None)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    pages = [("intake", "/"), ("log", "/runs")] + [(f"run-{r[:8]}", f"/runs/{r}") for r in a.run]
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=a.browser_path) if a.browser_path else p.chromium.launch()
        for theme in ("dark", "light"):
            for vp_name, vp in (("desktop", {"width": 1440, "height": 900}),
                                ("phone", {"width": 390, "height": 844})):
                ctx = b.new_context(viewport=vp, color_scheme=theme)
                pg = ctx.new_page()
                for name, path in pages:
                    pg.goto(a.base + path)
                    pg.wait_for_timeout(1800)
                    overflow = pg.evaluate("document.documentElement.scrollWidth - "
                                           "document.documentElement.clientWidth")
                    f = out / f"{name}-{vp_name}-{theme}.png"
                    pg.screenshot(path=str(f), full_page=True)
                    print(f"{f}  horizontal overflow: {overflow}px")
                ctx.close()
        b.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
