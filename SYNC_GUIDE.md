# Device Sync (PIN) Guide

Audience
- End users performing device-to-device sync.
- Operators running the rendezvous server.

What this covers
- PIN pairing flow, prerequisites, expected logs, and targeted troubleshooting.

## Prerequisites
- Both devices have Q‑Safe Vault installed and a vault open.
- Trusted peers: Exchange device public keys (base64) and add them to each other’s trusted list (one‑time).
- Rendezvous server: App configured with QSV_SYNC_BASEURL (HTTPS preferred).
  - Example run: --dart-define=QSV_SYNC_BASEURL=https://qsafevault-server.vercel.app

## Quick Start

Host (Device A)
1) Open Sync dialog → Select “Host” → Start pairing.
2) A 6–8 digit PIN appears with a short TTL; share the PIN verbally.
3) Wait. The app publishes a sealed offer and waits for the answer.

Join (Device B)
1) Open Sync dialog → Select “Join” → Enter the PIN → Join.
2) The app resolves the PIN and polls for the host’s offer.
3) It creates an answer and publishes it back.
4) After the channel opens, peers authenticate and sync proceeds.

Identity verification
- After the channel opens, confirm the last 4 chars of device IDs match on both devices.
- If warned “Untrusted peer”, add the displayed public key to your trusted list and retry.

## What to expect in logs (debug)
- Joiner:
  - [rv] GET /v1/sessions/resolve → 200 once
  - [rv] pollOffer start … → repeated GET /offer 404 offer_not_set, then 200
  - [rv] POST /v1/sessions/{id}/answer → 200
- Host:
  - [rv] POST /v1/sessions → 200
  - [rv] POST /v1/sessions/{id}/offer → 200
  - [rv] pollAnswer start … → GET /answer 200 shortly after join’s POST
- App events:
  - PeerAuthenticatedEvent → HandshakeCompleteEvent → Manifest/Vault exchange

Note: Logs mask PIN and redact ciphertext. That’s expected.

## Troubleshooting

Common errors and fixes
- 404 pin_not_found
  - The PIN is wrong or the session was already resolved and deleted. Generate a new PIN on host and re-enter.
- 410 session_expired / PIN expired
  - TTL elapsed. Restart pairing and use the new PIN.
- 404 offer_not_set (Joiner while polling /offer)
  - Normal until host has published the offer. The app will keep polling; just wait.
- “Answer not received before timeout” (Host)
  - Joiner didn’t post answer in time. Ensure the join device is online and within TTL; retry with a new PIN if needed.
- Untrusted peer
  - Add the displayed public key to your trusted list, then retry pairing.
- Flaky pairing or no channel open
  - Ensure STUN reachability on both devices. Add TURN if behind restrictive NATs (symmetric NAT/corporate networks).

Network tips
- STUN: stun:stun.l.google.com:19302 is used by default.
- TURN: If your environment is restrictive, configure TURN on both devices (app code) and ensure credentials are valid.

## Mobile platforms (Android/iOS) notes

Permissions
- Android: INTERNET and ACCESS_NETWORK_STATE in android/app/src/main/AndroidManifest.xml.
  - These are install-time; Android won’t prompt at runtime.
- iOS: Add NSLocalNetworkUsageDescription in ios/Runner/Info.plist to avoid local network privacy blocks when peers are on the same LAN.

TURN for restrictive NATs
- If pairing stalls after “offer received” or ICE fails on mobile, use a TURN server:
  - Build/run with:
    - --dart-define=QSV_TURN_URLS=turns:your.turn.example:5349
    - --dart-define=QSV_TURN_USERNAME=yourUser
    - --dart-define=QSV_TURN_CREDENTIAL=yourPass
  - To force relayed transport (bypass P2P when needed):
    - --dart-define=QSV_TURN_FORCE_RELAY=true

Diagnostics
- On Windows builds, sync logs are also written to qsafevault-sync.log next to the executable (fallback to %TEMP%).
- Logs include ICE candidate types (host/srflx/relay) and connection state transitions.

## Security & Privacy

- No plaintext SDP or PIN ever stored on the rendezvous server; Offer/Answer are sealed with a PIN‑derived key (Argon2id + AES‑GCM).
- WebRTC data channel is protected by DTLS; vault remains AES‑256‑GCM encrypted at rest.
- Only share public keys; never share private keys.
- Use a new PIN per pairing; sessions are single‑use and time‑limited.

## Server expectations (summary)

Endpoints
- POST /v1/sessions → { sessionId, pin, saltB64, ttlSec }
- GET /v1/sessions/resolve?pin=XXXXXX → { sessionId, saltB64, ttlSec }
- POST/GET /v1/sessions/{id}/offer → { envelope }
- POST/GET /v1/sessions/{id}/answer → { envelope }
- DELETE /v1/sessions/{id}

Behavior
- Keep PIN→session mapping valid after resolve; do not delete on first resolve.
- Return 404 for unset offer/answer, 410 for expired sessions, 429 for rate limits.
- Store only sealed envelopes (no plaintext SDP/PIN), enforce TTL and rate limits.

Notes
- The README has a high‑level overview; this guide focuses on practical usage and troubleshooting for PIN pairing.
