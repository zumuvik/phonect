# Security Policy — phonect

## Threat Model

### Overview

phonect implements a **Challenge-Response authentication scheme** over a local
P2P Wi-Fi network.  The goal is to unlock a Linux laptop using a fingerprint
scan performed on an Android phone.

```
┌─ Laptop (PC) ─────────────────┐       ┌─ Android Phone ──────────────────┐
│                                │       │                                  │
│  generates random 32-byte      │       │  private key locked by           │
│  Nonce                         │       │  BIOMETRIC_STRONG in Keystore    │
│         │                      │       │         │                        │
│         │── TCP frame ────────►│       │         │                        │
│         │   {nonce, session}  │       │         │                        │
│         │                      │       │         ▼                        │
│         │                      │       │  BiometricPrompt appears         │
│         │                      │       │  user scans fingerprint          │
│         │                      │       │         │                        │
│         │                      │       │         ▼                        │
│         │◄── TCP frame ────────│       │  private_key.sign(nonce)         │
│         │   {signature}        │       │                                  │
│         │                      │       │                                  │
│  verify(nonce, signature,      │       │                                  │
│         pubkey)                │       │                                  │
│         │                      │       │                                  │
│         ▼                      │       │                                  │
│  loginctl unlock-session       │       │                                  │
└────────────────────────────────┘       └──────────────────────────────────┘
```

### What phonect DOES protect against

| Threat | Mitigation |
|--------|-----------|
| **Replay attack** | Each handshake uses a fresh 32-byte cryptographically random Nonce. A captured signature is useless for a different Nonce. |
| **Packet sniffing / MitM on LAN** | The Nonce + signature are exchanged over TCP in cleartext, but the signature itself is a cryptographic proof that can only be produced by the phone's private key. An attacker who sees the signature cannot forge a signature for a different Nonce. |
| **Offline brute-force of private key** | The private key is generated with RSA-4096 and stored in Android Hardware-backed Keystore (`KeyProperties.PURPOSE_SIGN`, `setUserAuthenticationRequired(true)`). The key material never leaves the Keystore / TEE. |
| **Impersonation of the phone** | The PC stores a whitelist of trusted public keys. Only a response signed by the corresponding private key is accepted. |
| **Unauthorized unlock (lost phone)** | The private key cannot be used without a fresh biometric match (`BIOMETRIC_STRONG`). Even if the phone is stolen, the attacker cannot sign challenges. |

### What phonect does NOT protect against (and why)

| Non-goal | Rationale |
|----------|-----------|
| **Encryption of the TCP channel** | The challenge-response is a zero-knowledge proof: exposing the Nonce and signature does not weaken security. If TLS were added, it would protect against passive sniffing of the *device identity* (public key fingerprint), but that is not the primary threat. A future version may add TLS for operational security. |
| **Mutual authentication (phone → PC)** | Currently only the phone authenticates to the PC. The phone does **not** verify the PC's identity. A rogue device on the LAN could send a challenge to the phone and collect a signature. However, because the Nonce is random and single-use, this does not help unlock a PC. **Future versions will add mutual RSA authentication** (the PC also signs the challenge with its own key). |
| **Cloud / remote unlock** | phonect is explicitly a **local-only** P2P system. No data ever leaves the LAN. |

### Data sensitivity

| Data | Where stored | Transmitted over network? |
|------|-------------|--------------------------|
| **Fingerprint biometric data** | Android device only (BiometricPrompt / Keystore). **Never** leaves the phone. | ❌ No |
| **Private key (RSA-4096)** | Android Hardware-backed Keystore (TEE/StrongBox). | ❌ No |
| **Public key** | PC filesystem + Android memory. | ✅ Yes (during pairing via QR code) |
| **Nonce (random challenge)** | PC memory + TCP frame. | ✅ Yes (plaintext — safe by design) |
| **Signature** | TCP frame. | ✅ Yes (plaintext — safe by design, proves nothing without the private key) |

### Biometric data privacy statement

**phonect never transmits, stores, or processes fingerprint images or any
biometric template over the network.**  The Android `BiometricPrompt` API
performs fingerprint matching entirely on-device in the TEE / Secure Element.
After successful authentication, the API only releases a cryptographic handle
that allows the private key in Android Keystore to be used for signing.  The
raw biometric data never reaches the phonect application layer.

### Reporting a vulnerability

If you discover a security vulnerability in phonect, please file a
[GitHub Security Advisory](https://github.com/zumuvik/phonect/security/advisories)
or email the maintainers directly.  Do **not** open a public issue.

We commit to:
- Acknowledging receipt within 48 hours.
- Providing a fix or mitigation within 90 days for critical issues.
- Crediting the reporter in the release notes (if desired).
