# Vaultless

> **Disclaimer:** Unlike my other projects, this one was built mostly by AI. The code was produced iteratively through conversation with [Claude](https://claude.ai) (Anthropic) via [Claude Code](https://claude.ai/code). I contributed code review, security critique, and minor corrections throughout.

A stateless, single-file password manager. No vault, no server, no installation.

**[Try it live →](https://www.bytekeeper.org/vaultless/)**

Or download `vaultless.html` and open it in any modern browser. Nothing is sent anywhere.

## How it works

Passwords are **derived**, not stored. Every password is computed on-the-fly from:

```
PBKDF2-SHA256( master password, site + username + version, 1,000,000 iterations )
```

The same inputs always produce the same output — so you never need to store the password itself. Lose your device, open the file on another machine, and all your passwords are reproducible from memory alone.

**What *is* optionally stored** (in `localStorage`, encrypted): site names, aliases, and settings like length and character classes. Nothing in storage is plaintext.

## Security primitives

| Primitive | Purpose |
|-----------|---------|
| PBKDF2-SHA256, 1,000,000 iterations | Password derivation |
| HMAC-SHA256 | Site hash (keyed on full master password) |
| AES-GCM-256, 100,000 iterations | Per-entry localStorage encryption |
| AES-GCM-256, 1,500,000 iterations | Export file encryption |

All cryptography uses the browser's built-in [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) — zero dependencies, zero supply chain risk.

## Export file

The exported `.json` file is safe to store publicly (e.g. in a git repo or cloud drive). Each site entry is encrypted individually, so a diff of the file reveals only that a single entry changed — nothing else.

## Usage

1. Enter your master password and a site name (`github`, `email`, …)
2. Optionally add a username for extra uniqueness
3. Hit **generate + save**
4. To get a new password for a site (breach, forced rotation): increment the **version** number

Inspired by [LessPass](https://lesspass.com).
