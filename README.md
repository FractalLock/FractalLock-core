# FractalLock Core

FractalLock Core provides the cryptographic vault format and recovery system used by FractalLock.

This repository contains only the cryptographic container logic and is intended for independent audit and verification.

Features:

- XChaCha20-Poly1305 encryption (libsodium)
- Shamir Secret Sharing recovery
- Versioned vault format
- Append-only encrypted payloads
- Logical delete support

This repository intentionally contains **no UI or Electron code**.

## License

FractalLock Core is source-available under a non-commercial license.

You may view and audit the code, but commercial use, redistribution,
or use in competing products is prohibited.

See the LICENSE file for full terms.