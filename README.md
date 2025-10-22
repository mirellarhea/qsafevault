# Q‑Safe Vault

A secure, local-only password manager built with Flutter. Vault data is encrypted at rest using AES‑256‑GCM, with password-based key derivation via Argon2id and optional fast-unlock backed by platform secure storage.

Supported platforms
- Windows (supported)
- Linux (supported)
- Android (supported)

Downloads
- Prebuilt releases are available from the repository’s Releases tab (Windows, Linux, Android APK/AAB).

---

## Table of contents
- [Overview](#overview)
- [Key features](#key-features)
- [Security architecture](#security-architecture)
- [Threat model](#threat-model)
- [Operational guidance](#operational-guidance)
- [Build, run, and test](#build-run-and-test)
- [Repository layout](#repository-layout)
- [Roadmap & status](#roadmap--status)
- [Responsible disclosure](#responsible-disclosure)
- [License](#license)
- [Contact](#contact)

---

## Overview
Q‑Safe Vault keeps your password vault local and encrypted. It uses well‑maintained crypto libraries:
- cryptography for AES‑GCM and SecretKey handling
- pointycastle and crypto for HMACs and hashing
- flutter_secure_storage for OS‑backed secure storage used by fast‑unlock

No cloud sync or telemetry is included.

---

## Key features
- Local‑only, encrypted vault at rest
- AES‑256‑GCM (cryptography) for confidentiality and integrity
- Password KDF: Argon2id with runtime calibration to target device cost
- Optional fast unlock using a wrapped master key in secure storage
- Atomic writes, multi‑part file storage, backups with pruning
- Cross‑platform UI (Windows, Linux, Android)

---

## Security architecture

Cryptography and KDFs
- Master encryption: AES‑256‑GCM (256‑bit key) for vault data.
- Password KDF (slow path): Argon2id with runtime calibration targeting ~400 ms on the current device (bounds enforced by minimums).
- Fast unlock KDF: Argon2id targeting ~120 ms to derive a fast key that wraps the master key for quicker unlocks.
- Verifier: HMAC‑SHA3‑512 keyed by the master key to validate password correctness without decrypting the vault.
- Fast‑params signature: HMAC‑SHA3‑512 keyed by the master key to detect tampering of stored fast‑unlock parameters.

Key wrapping and nonces
- Wrapped master key: AES‑GCM over (wrap_label || master_key). The 96‑bit nonce is deterministically derived as HMAC‑SHA256(fast_key, label|ctr) using a monotonic counter stored in metadata. This prevents nonce reuse across rewraps.
- Entry nonces/tags: Deterministic 96‑bit nonces and accept tags derived from the master key using labeled HMACs to avoid collisions and bind to a counter (and optional entryId).

Integrity and comparisons
- AEAD tags protect vault and wrapped key blobs.
- Constant‑time comparisons for MACs to reduce timing differences.
- Best‑effort zeroization of sensitive byte arrays after use (language‑level limitations apply).

Storage layout and metadata
- pwdb.meta.json: KDF parameters, salts, counters, cipher info, verifier, fast‑unlock params/signature.
- pwdb.enc.partN: Encrypted vault split into parts for safer updates.
- derived.key (optional): Wrapped master key on disk only when explicitly allowed (see configuration). By default, wrapped key is stored in secure storage if available; disk fallback is disabled.

Backups, atomicity, and concurrency
- Atomic writes via .tmp file rename.
- Per‑save backups (.bak) created, with old backups pruned (keep latest).
- Synchronization locks guard critical write paths.

Secure storage (fast unlock)
- Platform backends via flutter_secure_storage:
  - Windows: DPAPI
  - macOS/iOS: Keychain
  - Android: EncryptedSharedPreferences
- Availability is verified with a write/read/delete probe. If available, the wrapped master key is stored there.
- If not available and disk fallback is disabled, the app falls back to slow KDF (no fast unlock on that device).

Privacy
- No telemetry or analytics.
- Password creation UI optionally queries the HIBP “Pwned Passwords” k‑Anonymity API (range endpoint) to check breach exposure. Only the SHA‑1 prefix (first 5 hex chars) is sent; your full password is never transmitted.
- Clipboard operations may expose secrets to the OS/global clipboard. Handle with care on shared systems.

Post‑quantum note
- Current primitives are classical: AES‑256‑GCM, Argon2id, HMAC‑SHA3‑512/HMAC‑SHA256.
- AES‑256 maintains strong margins under Grover assumptions (effective ~128‑bit).
- No PQ/hybrid primitives are implemented yet.

---

## Threat model
Defends against
- Offline access to vault files without the password.
- Parameter tampering for fast unlock (detected via HMAC‑SHA3‑512 signature).
- Accidental corruption during saves (atomic writes, multi‑part files, backups).

Out of scope
- Compromised endpoints (malware, keyloggers, memory forensics while running).
- Side‑channel resistance beyond constant‑time MAC compares.
- Cloud sync and multi‑device state reconciliation.

Operator cautions
- Do not manually edit pwdb.meta.json. This can corrupt counters and risk nonce reuse.
- Do not copy/move vault files while a save is in progress.

---

## Operational guidance

Default behavior
- Vault creation location: prompts for folder; if not empty, a pwdb subfolder is created.
- Parts: defaults to 3 parts for vault data.
- Calibration: KDF parameters are tuned at runtime for the device; values are persisted in metadata.

Configuration
- Fast unlock disk fallback: disabled by default.
  - To enable, construct StorageService with allowDiskWrappedKeyFallback: true. This writes derived.key next to the vault and sets 600 permissions on Unix-like systems.
- Secure storage availability: subject to platform bindings and environment; if unavailable, fast unlock is skipped.

Backup and restore
- Backups (.bak) are created on each save. To restore, replace pwdb.enc.partN with the corresponding .bak files and keep metadata intact.
- Keep multiple copies of your vault folder in offline storage for disaster recovery.

Mobile considerations (Android)
- Consider enabling device lock/biometrics and screen lock to improve protection while the app is running.
- Clipboard contents are managed by the OS; clear it promptly if copying secrets is necessary.

Known limitations
- Secure storage availability varies by distro/environment. If unavailable, fast unlock is not used unless disk fallback is explicitly enabled.
- Clipboard exposure of secrets is inherent to OS clipboards.

---

## Build, run, and test

Prerequisites
- Flutter SDK (stable), Dart SDK (as pinned by Flutter)
- Platform toolchains:
  - Windows: Visual Studio with Desktop C++ workload
  - Linux: GTK/Clang as required by Flutter desktop
  - Android: Android Studio/SDK, device or emulator

Install deps
- flutter pub get

Run (desktop/mobile)
- Windows: flutter run -d windows
- Linux: flutter run -d linux
- Android: flutter run -d android

Build release
- Windows: flutter build windows
- Linux: flutter build linux
- Android (APK): flutter build apk --release
- Android (AAB): flutter build appbundle --release

Quality gates
- Static analysis: dart analyze
- Formatting: dart format --output=none --set-exit-if-changed .
- Tests: flutter test

---

## Repository layout
```
/android      # Android
/ios          # iOS (planned)
/lib          # Flutter app source
/linux        # Linux desktop embedding
/macos        # macOS (planned)
/public       # Assets
/test         # Tests
/web          # Web config (not primary target)
/windows      # Windows desktop embedding
pubspec.yaml  # Dependencies and config
README.md     # This file
```

---

## Roadmap & status
- [✅] Core vault storage and desktop/mobile UI
- [✅] Calibrated Argon2id + AES‑256‑GCM
- [✅] Optional fast unlock with secure storage and tamper detection
- [✅] Atomic writes, backups, and file‑part storage
- [✅] Android support
- [❌] Cloud sync or multi‑device support
- [❌] Third‑party security audit
- [❌] PQ/hybrid cryptography

---

## Responsible disclosure
Please report security issues privately. Open a GitHub Security Advisory or contact the maintainer via issue for a secure channel. Do not file public issues for vulnerabilities.

---

## License
Creative Commons Attribution‑NonCommercial 4.0 International (CC BY‑NC 4.0).

---

## Contact
Open an issue for questions or suggestions. Contributions via PRs and issues are welcome.
