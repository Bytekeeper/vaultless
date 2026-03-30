#!/usr/bin/env python3
"""
Takes a screenshot of the Vaultless UI and writes it to assets/screenshot.png.

Run:
  python3 tests/screenshot.py
  # or: make screenshot
"""

import http.server
import os
import pathlib
import sys
import threading
import time

PORT  = 8792
ROOT  = pathlib.Path(__file__).parent.parent
OUT   = ROOT / 'assets' / 'screenshot.png'


def start_server():
    os.chdir(ROOT)

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(('localhost', PORT), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    return server


def run():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        sys.exit('error: pip install playwright && playwright install chromium --with-deps')

    OUT.parent.mkdir(exist_ok=True)
    server = start_server()

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page    = browser.new_page(viewport={'width': 680, 'height': 900},
                                       color_scheme='dark')

            page.goto(f'http://localhost:{PORT}/dist/vaultless.html')
            page.wait_for_load_state('networkidle')

            # Clip to the app element so we don't capture empty page background.
            app = page.locator('.app')
            app.screenshot(path=str(OUT))

            browser.close()
    finally:
        server.shutdown()

    print(f'wrote {OUT.relative_to(ROOT)}')


if __name__ == '__main__':
    run()
