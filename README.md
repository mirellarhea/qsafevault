# Q‑Safe Vault

A secure, local‑first password manager built with Flutter. Vault data is encrypted at rest with AES‑256‑GCM, using Argon2id for password‑based key derivation and optional fast‑unlock keys wrapped in platform secure storage. Device‑to‑device sync uses WebRTC data channels, authenticated by Ed25519 device identities, and a short‑lived PIN rendezvous.

Key highlights
- Local‑only vault; no cloud storage
- AES‑256‑GCM encryption; Argon2id KDF
- Fast unlock via OS secure storage (optional)
- Cross‑platform app (Windows, Linux, Android; macOS/iOS planned)
- Peer‑to‑peer sync over WebRTC with PIN rendezvous
- No telemetry

Supported platforms
- Windows (desktop)
- Linux (desktop)
- Android (mobile)
- macOS/iOS (on dev)

License
- Creative Commons Attribution‑NonCommercial 4.0 International (CC BY‑NC 4.0)

---

## Table of contents
- Overview and architecture
- Security model
- Requirements
- Install and run
- Build from source
- Configuration (rendezvous server, environment)
- Device synchronization (PIN pairing)
- Troubleshooting
- Contributing
- Roadmap
- License and acknowledgements

---

## Overview and architecture

Components
- App: Flutter UI and services (vault storage, crypto, sync).
- Storage: AES‑256‑GCM encrypted vault; atomic writes; backups; optional wrapped key in secure storage.
- Device identity: Ed25519 key pair generated per device; public key shared to build a trusted peers list.
- Sync: WebRTC data channel with rendezvous signaling via short PIN. Offer/Answer are sealed using a key derived from the PIN (Argon2id + AES‑GCM) so the server never sees plaintext SDP.

Data flow
1) Unlock vault with password (Argon2id -> master key -> decrypt vault)
2) Optionally store a wrapped fast‑unlock key in platform secure storage
3) Sync:
   - Host creates a session (PIN) and publishes a sealed offer
   - Join resolves PIN, fetches offer, and publishes sealed answer
   - Devices authenticate peers by Ed25519 public keys
   - Manifest exchange decides whether to send or request vault
   - Vault JSON sent over encrypted data channel

---

## Security model

- Encryption at rest: AES‑256‑GCM
- Password KDF: Argon2id (calibrated); fast‑unlock also Argon2id with separate parameters
- Integrity: AEAD tags; HMAC‑SHA3‑512 for verifier and tamper detection of fast‑params
- Device trust: Ed25519 public key pinning; sync will warn on untrusted peers
- Signaling privacy: Offer/Answer sealed with AES‑GCM using a key derived from PIN via Argon2id (server stores only sealed envelopes)
- Transport: WebRTC DTLS/SRTP

Operator guidance
- Share only public keys; verify and add peers to trusted list before syncing
- Use a new PIN for each pairing; PINs expire automatically
- Prefer trusted networks; use TURN if NATs are restrictive
- Clipboard handling exposes secrets to OS/global clipboard

---

## Requirements

- Flutter SDK (stable); Dart as included with Flutter
- Platform toolchains:
  - Windows: Visual Studio with Desktop C++ workload
  - Linux: gtk3/clang toolchain as required by Flutter
  - Android: Android Studio/SDK and a device/emulator
- Optional: a rendezvous server for PIN pairing (HTTPS)

---

## Install and run

Prebuilt binaries
- See Releases for Windows installer, Linux .deb, Android APK/AAB.
- Android: allow installing from unknown sources to sideload APK.

Run from source (quick)
- Windows: flutter run -d windows
- Linux: flutter run -d linux
- Android: flutter run -d android

Web is not a primary target, but can be tried via: flutter run -d chrome

---

## Build from source

Install deps
- flutter pub get

Build release
- Windows: flutter build windows
- Linux: flutter build linux
- Android (APK): flutter build apk --release
- Android (AAB): flutter build appbundle --release

CI/CD
- See .github/workflows/flutter_build.yml for multi‑platform builds and release packaging.

---

## Configuration

Runtime configuration is via --dart-define.

- QSV_SYNC_BASEURL: Base URL for the rendezvous (PIN) server
  - Example: --dart-define=QSV_SYNC_BASEURL=https://qsafevault-server.vercel.app
  - For local development: --dart-define=QSV_SYNC_BASEURL=http://localhost:3000

Notes
- All HTTP/HTTPS calls are logged at debug level (sanitized: PIN masked, ciphertext redacted).
- Default timeouts: httpTimeout=8s, pollInterval≈800ms, pollMaxWait=180s.

---

## Device synchronization (PIN pairing)

Prerequisites
- Both devices open the Sync dialog
- Exchange and add each other’s Ed25519 public key to “Trusted peers” (one‑time)

Rendezvous server (required)
- The app expects:
  - POST /v1/sessions → { sessionId, pin, saltB64, ttlSec }
  - GET /v1/sessions/resolve?pin=XXXXXX → { sessionId, saltB64, ttlSec }
  - POST/GET /v1/sessions/{id}/offer → { envelope }
  - POST/GET /v1/sessions/{id}/answer → { envelope }
  - DELETE /v1/sessions/{id}
- Offer/Answer envelopes are sealed; server stores no plaintext SDP or PIN.
- See SERVER_API_SPEC.md for schema details and examples.

How to sync
- Host:
  - Open Sync dialog → Start pairing → a PIN appears with TTL
  - Wait; the app publishes a sealed offer automatically
- Join:
  - Enter the PIN → the app resolves, polls for offer, then publishes the sealed answer
- Both:
  - The data channel opens; devices authenticate public keys
  - Manifest exchange decides direction; vault is sent automatically

Troubleshooting
- PIN not found or expired
  - Generate a new PIN (host) and re‑enter (join)
- “Answer not received before timeout”
  - Check that the join device posted the answer within TTL; ensure STUN/TURN reachability
- Flaky pairing
  - Ensure the joiner resolves once and polls /offer (the app does this by default)
- Untrusted peer
  - Add the displayed public key to your trusted list and retry

---

## Logging and diagnostics

- Sync HTTP logs: prefix [rv] (RendezvousClient)
  - Requests and responses are printed with masked PIN and redacted ciphertext
  - Polling logs include start/timeout markers
- App events (SyncService):
  - LocalDescriptionReadyEvent, PeerAuthenticatedEvent, HandshakeCompleteEvent
  - ManifestReceivedEvent, VaultRequestedEvent, VaultReceivedEvent

Windows console
- The Windows runner opens a console when run under a debugger; logs are printed there.

---

## Contributing

- Issues and PRs are welcome for bug reports, documentation, and non‑commercial improvements.
- Security issues: please report privately (see Responsible disclosure).

---

## Roadmap

- [Done] Core vault and desktop/mobile UI
- [Done] AES‑256‑GCM + Argon2id (calibrated)
- [Done] Fast unlock via secure storage (optional)
- [Done] Atomic writes, backups, multi‑part storage
- [Done] WebRTC sync with PIN rendezvous and device trust
- [Planned] macOS/iOS support
- [Planned] Third‑party security audit
- [Planned] PQ/hybrid crypto options

---

## License and acknowledgements

License
- Creative Commons Attribution‑NonCommercial 4.0 International (CC BY‑NC 4.0). See LICENSE.

Acknowledgements
- cryptography, pointycastle, flutter_secure_storage, flutter_webrtc and the Flutter ecosystem.
- WebRTC STUN servers and any TURN infrastructure you configure.

---
