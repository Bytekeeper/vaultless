#!/usr/bin/env python3
"""
Headless test runner for Vaultless.

Spins up Python's built-in HTTP server, opens tests/index.html in a headless
Chromium browser via Playwright, waits for all async tests to finish, prints
results, and exits non-zero if any test fails.

Install once:
  pip install playwright
  playwright install chromium --with-deps

Run:
  python3 tests/run_headless.py
  # or: make test
"""

import http.server
import os
import pathlib
import sys
import threading
import time

PORT = 8791
ROOT = pathlib.Path(__file__).parent.parent


def start_server():
    """Start a local HTTP server rooted at the project root in a daemon thread."""
    os.chdir(ROOT)

    # Silence the default request logging.
    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(('localhost', PORT), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)   # give the socket a moment to bind
    return server


def run():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print('error: playwright not installed.')
        print('  pip install playwright && playwright install chromium --with-deps')
        sys.exit(2)

    server = start_server()

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page    = browser.new_page()

            # Forward browser console errors so CI logs show crypto failures.
            page.on('console', lambda msg: (
                print(f'  browser [{msg.type}]: {msg.text}', file=sys.stderr)
                if msg.type in ('error', 'warning') else None
            ))
            page.on('pageerror', lambda err: print(f'  page error: {err}', file=sys.stderr))

            page.goto(f'http://localhost:{PORT}/tests/')

            # #summary gets class 'all-pass' or 'has-fail' only after every
            # async test has resolved — wait up to 120s for slow PBKDF2 runs.
            page.wait_for_selector(
                '#summary.all-pass, #summary.has-fail',
                timeout=120_000
            )

            # Print section headers and individual test rows.
            for el in page.query_selector_all('h2, .row'):
                tag  = el.evaluate('el => el.tagName.toLowerCase()')
                text = el.inner_text().strip()
                if tag == 'h2':
                    print(f'\n{text}')
                else:
                    print(f'  {text}')

            summary  = page.text_content('#summary').strip()
            has_fail = page.evaluate(
                "document.getElementById('summary').classList.contains('has-fail')"
            )

            print(f'\n{summary}')
            browser.close()

    finally:
        server.shutdown()

    sys.exit(1 if has_fail else 0)


if __name__ == '__main__':
    run()
