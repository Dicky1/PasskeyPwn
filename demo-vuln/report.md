# PasskeyPwn — Security Test Report

**Target:** http://localhost:8099
**Start:** 2026-10-24T12:30:52.759Z
**End:** 2026-10-24T12:57:53.144Z
**Findings:** 8

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Error (High) | 2 |
| 🟡 Warning (Medium) | 5 |
| 🔵 Note (Low) | 1 |

## Test Matrix

| # | Module | Ceremony | Verdict | HTTP | Server response |
|---|--------|----------|---------|------|-----------------|
| 1 | `enum` | authenticate | 🔴 FINDING | 200 | Enumeration signal: response bodies differ in size (known=218B, absent=146B). |
| 2 | `rogue-persist` | register | 🔴 FINDING | 200 | {"verified":true} |
| 3 | `downgrade` | register | 🔴 FINDING | 200 | {"verified":true} |
| 4 | `recovery` | authenticate | ✅ rejected (secure) | — | No weaker fallback detected on the login page (heuristic). |
| 5 | `origin` | authenticate | 🔴 FINDING | 200 | {"verified":true} |
| 6 | `challenge` | authenticate | 🔴 FINDING | 200 | {"verified":true} |
| 7 | `counter` | authenticate | 🔴 FINDING | 200 | {"verified":true} |
| 8 | `flags` | authenticate | 🔴 FINDING | 200 | {"verified":true} |
| 9 | `attestation` | register | 🔴 FINDING | 200 | {"verified":true} |
| 10 | `credid` | authenticate | ✅ rejected (secure) | 400 | {"error":"Unrecognized credential ID"} |

> A "rejected (secure)" verdict means the relying party correctly refused the mutated ceremony. A "FINDING" means it accepted something it should have rejected.

## Findings

### 🟡 1. Account enumeration via authentication flow

- **Rule ID:** `exploit.enum.user-existence`
- **Severity:** warning
- **Category:** account-enumeration
- **Endpoint:** `http://localhost:8099`

The authentication options response differs between an existing and a non-existing username, allowing an attacker to enumerate valid accounts. A hardened RP returns a uniform response (same status, shape, and timing) regardless of whether the user exists.

**Payload:**
```
known="ppwn_enum_known_1792845121307" vs absent="ppwn_enum_absent_1792845121307_zzz"
```

**Server Response:**
```
Enumeration signal: response bodies differ in size (known=218B, absent=146B).

[known]
{"challenge":"MMF4E0CzE44leYotQ2BuL8EPU_prdTDiXamMfweFaHY","rpId":"localhost","timeout":60000,"userVerification":"required","allowCredentials":[{"type":"public-key","id":"oKW5oTPmWjURqqVEYXyyHttCRuwWi16YszxMudL1jhY"}]}

[absent]
{"challenge":"x3VBIWp04UWUzAU5qv8Mk0Q5MLYfs8tfTBcnjnXpcLM","rpId":"localhost","timeout":60000,"userVerification":"required","allowCredentials":[]}
```

**HTTP Status:** 200

---

### 🔴 2. Additional credential added without re-authentication

- **Rule ID:** `exploit.rogue-persist.add-credential`
- **Severity:** error
- **Category:** rogue-persistence
- **Endpoint:** `http://localhost:8099`

A second credential was registered to an existing account within the same session without any step-up re-authentication. An attacker with temporary session access can register their own authenticator and retain persistent access even after the password is changed or sessions are revoked. A hardened RP requires fresh user verification before enrolling a new credential and notifies the user.

**Payload:**
```
account="ppwn_persist_1792845127977", 2nd credential enrolled in-session
```

**Server Response:**
```
{"verified":true}
```

**HTTP Status:** 200

---

### 🔵 3. User-verification assurance downgrade at registration

- **Rule ID:** `exploit.downgrade.uv-not-performed`
- **Severity:** note
- **Category:** downgrade
- **Endpoint:** `http://localhost:8099`

Registration completed with the UV (User Verified) flag cleared although the RP policy requested userVerification=required. Accepting a credential enrolled without user verification downgrades the assurance level the RP believes it has, weakening every later authentication with that credential.

**Payload:**
```
flags=0x41 (UV cleared, AT set)
```

**Server Response:**
```
{"verified":true}
```

**HTTP Status:** 200

---

### 🔴 4. Cross-origin clientDataJSON accepted

- **Rule ID:** `fuzz.origin.cross-origin`
- **Severity:** error
- **Category:** origin-spoofing
- **Endpoint:** `http://localhost:8099/authentication/verification`

The assertion was sent with clientDataJSON.origin set to an attacker-controlled origin. A compliant RP MUST reject an assertion whose origin does not match an expected origin (WebAuthn §7.2 step 13).

**Payload:**
```
origin="https://passkeypwn-cross-origin.example"
```

**Server Response:**
```
{"verified":true}
```

**HTTP Status:** 200

---

### 🟡 5. Mismatched challenge accepted (replay)

- **Rule ID:** `fuzz.challenge.static`
- **Severity:** warning
- **Category:** challenge-replay
- **Endpoint:** `http://localhost:8099/authentication/verification`

The assertion carried a fixed challenge that the server never issued. A compliant RP MUST verify clientDataJSON.challenge equals the challenge it generated (WebAuthn §7.2 step 11). Acceptance indicates the challenge is not bound, enabling replay.

**Payload:**
```
challenge="QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE"
```

**Server Response:**
```
{"verified":true}
```

**HTTP Status:** 200

---

### 🟡 6. Signature counter regression accepted

- **Rule ID:** `fuzz.counter.regression`
- **Severity:** warning
- **Category:** counter-manipulation
- **Endpoint:** `http://localhost:8099/authentication/verification`

The assertion reported signCount=0 after a higher count had been established. An RP that stores signature counts SHOULD treat a non-increasing counter as a sign of a cloned authenticator (WebAuthn §7.2 step 21). Silent acceptance means cloned-credential detection is not in effect.

**Payload:**
```
signCount=0 (regressed)
```

**Server Response:**
```
{"verified":true}
```

**HTTP Status:** 200

---

### 🟡 7. Cleared User-Verified flag accepted

- **Rule ID:** `fuzz.flags.uv-cleared`
- **Severity:** warning
- **Category:** flag-manipulation
- **Endpoint:** `http://localhost:8099/authentication/verification`

The assertion was sent with the UV (User Verified) flag bit cleared while the RP requested userVerification=required. A compliant RP MUST verify the UV bit is set when it requires user verification (WebAuthn §7.2 step 17). 

**Payload:**
```
flags=0x01 (UP only, UV cleared)
```

**Server Response:**
```
{"verified":true}
```

**HTTP Status:** 200

---

### 🟡 8. "none" attestation accepted where attestation was requested

- **Rule ID:** `fuzz.attestation.none-substituted`
- **Severity:** warning
- **Category:** attestation-bypass
- **Endpoint:** `http://localhost:8099`

Registration was completed with fmt="none" and a zero AAGUID although the RP requested a non-none attestation. If the RP relies on attestation for authenticator provenance, it MUST validate the attestation statement rather than accept "none".

**Payload:**
```
attestationObject fmt="none", aaguid=00..00
```

**Server Response:**
```
{"verified":true}
```

**HTTP Status:** 200

---


*Generated by PasskeyPwn v1.0.0*