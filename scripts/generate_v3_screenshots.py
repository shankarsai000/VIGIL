import os
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
UI_OUT = ROOT / "docs" / "ui" / "v3"
UI_OUT.mkdir(parents=True, exist_ok=True)
SCRATCH = ROOT / "scratch"

views = [
    ("taint_graph", SCRATCH / "taint_graph.html"),
    ("containment_pill", SCRATCH / "containment_pill.html"),
    ("antibody_card", SCRATCH / "antibody_card.html"),
    ("blast_radius", SCRATCH / "blast_radius.html"),
]

viewports = [
    (1440, 900, "1440"),
    (390, 844, "390"),
]

with sync_playwright() as p:
    browser = p.chromium.launch()
    for name, html_path in views:
        if not html_path.exists():
            print(f"ERROR: {html_path} does not exist!")
            continue
        for width, height, label in viewports:
            page = browser.new_page(viewport={"width": width, "height": height})
            page.goto(html_path.as_uri())
            page.wait_for_timeout(300)
            out_file = UI_OUT / f"{name}_{label}.png"
            page.screenshot(path=str(out_file), full_page=False)
            print(f"Captured {out_file.name} ({width}x{height}, {out_file.stat().st_size} bytes)")
            page.close()
    browser.close()

print("All V3 screenshots successfully generated!")
