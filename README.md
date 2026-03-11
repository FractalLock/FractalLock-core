# Lockbox Core

Lockbox Core provides the cryptographic vault format and recovery system used by Lockbox.

This repository contains only the cryptographic container logic and is intended for independent audit and verification.

Features:

- XChaCha20-Poly1305 encryption (libsodium)
- Shamir Secret Sharing recovery
- Versioned vault format
- Append-only encrypted payloads
- Logical delete support

This repository intentionally contains **no UI or Electron code**.