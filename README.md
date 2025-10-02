# qsafevault

**Quantum-safe password manager**

A cross-platform password manager built with Flutter using AES‑256‑GCM algorithm that aims to explore and demonstrate quantum-resistant cryptographic approaches for secure vault storage. This repository contains releases and source code of said project.
Supported platforms:
- Windows (🟢)
- Linux (🟢)
- Android (🔴)
---

## Table of contents
- [What is qsafevault?](#what-is-qsafevault)
- [Key features](#key-features)
- [Repository layout](#repository-layout)
- [Roadmap & status](#roadmap--status)
- [License](#license)
- [Contact](#contact)
---

## What is qsafevault?
`qsafevault` is a Flutter-based password manager project intended to protect user password and credential offline using algorithms designed to resist quantum-computer attacks. The app stores encrypted vaults locally and provides standard password manager UX (entry creation, organize vaults, search and copy-to-clipboard).

---

## Key features
- Cross-platform Flutter app (mobile, desktop, web)
- Modular architecture separating UI and crypto logic
- Designed to support quantum-resistant encryption primitives
- Local encrypted vaults with manual backup/export support

---

## Repository layout
```
/android      # Android-specific code
/ios          # iOS-specific code
/lib          # Flutter application source (shared)
/linux        # Linux desktop embedding
/macos        # macOS desktop embedding
/public       # Public assets and demos
/test         # Unit & widget tests
/web          # Web-specific configuration
/windows      # Windows desktop embedding
pubspec.yaml  # Dart & Flutter package configuration
README.md     # (this file)
```
---


## Roadmap & status
- [✅] Core vault storage and UI
- [✅] Post-quantum crypto integration
- [❌] Cross-platform autofill & platform integrations
- [❌] Third-party security audit
---


## License
This project is licensed under Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)
---

## Contact
If you have questions or want help improving this README, open an issue or ping under user's contact listed.
---