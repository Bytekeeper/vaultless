#!/usr/bin/env python3
"""
Build script for Vaultless — no dependencies beyond Python 3 stdlib.

Reads src/template.html, replaces the BUILD:inline marker block with the
inlined content of the referenced file, writes dist/vaultless.html, and
prints the SHA-256 hash for integrity verification.

Usage:
  python3 build.py
"""

import hashlib
import pathlib
import re
import sys

ROOT     = pathlib.Path(__file__).parent
SRC      = ROOT / 'src'
DIST     = ROOT / 'dist'
TEMPLATE = SRC / 'template.html'
OUTPUT   = DIST / 'vaultless.html'

# Matches:
#   <!-- BUILD:inline src/core.js -->
#   ...anything...
#   <!-- /BUILD -->
BUILD_RE = re.compile(
    r'<!-- BUILD:inline (\S+) -->\n.*?<!-- /BUILD -->',
    re.DOTALL
)

def inline_file(match):
    path    = ROOT / match.group(1)
    content = path.read_text(encoding='utf-8')
    return f'<script>\n{content}</script>'

def build():
    if not TEMPLATE.exists():
        print(f'error: {TEMPLATE} not found', file=sys.stderr)
        sys.exit(1)

    DIST.mkdir(exist_ok=True)

    source = TEMPLATE.read_text(encoding='utf-8')
    output, count = BUILD_RE.subn(inline_file, source)

    if count == 0:
        print('warning: no BUILD:inline markers found — output is unchanged', file=sys.stderr)

    OUTPUT.write_text(output, encoding='utf-8')

    sha256 = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
    print(f'built  {OUTPUT.relative_to(ROOT)}')
    print(f'sha256 {sha256}')

if __name__ == '__main__':
    build()
