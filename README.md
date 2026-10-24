# PasskeyPwn

**A black-box offensive conformance tester for WebAuthn / Passkey relying parties.**

PasskeyPwn drives a real browser with a fully-controllable "shadow authenticator" and replays mutated WebAuthn ceremonies over HTTP to check whether a **relying party (the server)** correctly *rejects* malformed or forged ceremonies. It is a testing tool for the server side of WebAuthn — not an attack on authenticators or on correctly-implemented sites.

> ⚠️ **Authorized use only.** Run PasskeyPwn only against systems you own or are explicitly permitted to test (e.g. your own apps, a lab, or an in-scope bug-bounty target). WebAuthn is a defensive technology; this tool exists to help you verify your own relying-party implementation. You are responsible for how you use it.

---

## What it tests

A compliant relying party must verify every WebAuthn response it receives. PasskeyPwn submits ceremonies with exactly one field mutated and reports a **finding** when the server *accepts* something it should have *rejected*.

### `fuzz` — per-field validation (ceremony conformance)

| Module | Mutation | A secure RP… |
|---|---|---|
| `origin` | `clientDataJSON.origin` set to an attacker origin | rejects (WebAuthn §7.2 step 13) |
| `challenge` | fixed / unissued challenge | rejects (challenge binding, replay) |
| `counter` | signature counter regressed to 0 | flags cloned authenticator (§7.2 step 21) |
| `flags` | UV bit cleared while UV was required | rejects (§7.2 step 17) |
| `attestation` | `"none"` attestation where attestation was requested | validates, not accepts |
| `credid` | assertion from an unregistered credential ID | rejects (unknown credential) |

### `exploit` — higher-level relying-party weaknesses

| Module | Checks whether the RP… |
|---|---|
| `enum` | leaks account/credential existence via the auth options response |
| `rogue-persist` | lets a new credential be enrolled with no re-authentication (persistence vector) |
| `downgrade` | accepts a credential enrolled without user verification when UV is required |
| `recovery` | exposes a weaker non-passkey fallback that bypasses the passkey |

The `exploit` command **requires** an explicit `--authorized "<statement>"` flag, which is recorded in the results as an audit trail.

---

## How it works

- **Shadow authenticator** — injects a full override of `navigator.credentials.create/get` so every byte of `authenticatorData`, `clientDataJSON`, the attestation object, and the signature is built and signed in Node (ES256 / P-256, DER-encoded as WebAuthn requires).
- **Capture-replay (`--mode replay`)** — captures one real ceremony (the `options` + `finish` HTTP calls, with cookies/CSRF), then for each mutation rebuilds + **re-signs** the components and replays the `finish` request directly over HTTP. A structural **field locator** finds `clientDataJSON` / `authenticatorData` / `signature` / `credentialId` / `challenge` inside *any* JSON envelope by decoding and recognizing them — so replay is target-agnostic, not tied to one RP's field names.
- **Browser mode (`--mode browser`)** — drives the mutation through the live page for cases that are not replayable (e.g. registration-time attestation).

---

## Install

```bash
npm install
npx playwright install chromium
npm run build        # compile to dist/ (or use `npm run dev` / tsx for source)
```

Requires Node ≥ 20.

## Usage

```bash
# 1. Recon — register + authenticate once, record the baseline
npx tsx src/cli.ts recon \
  --url-register https://target.example --url-login https://target.example \
  --screenshots ./evidence --out ./baseline.json

# 2. Fuzz — mutate each field and check the server's verdict (HTTP replay)
npx tsx src/cli.ts fuzz \
  --module "origin,challenge,counter,flags,attestation,credid" \
  --mode replay --baseline ./baseline.json --out ./results

# 3. Exploit — higher-level weakness probes (authorization required)
npx tsx src/cli.ts exploit \
  --module "enum,rogue-persist,downgrade,recovery" \
  --authorized "I am authorized to test target.example under program XYZ" \
  --baseline ./baseline.json --out ./results

# 4. Report — render findings as Markdown or SARIF
npx tsx src/cli.ts report --format md   --results ./results --out report.md
npx tsx src/cli.ts report --format sarif --results ./results --out report.sarif
```

Global options: `--proxy http://127.0.0.1:8080` (route through Burp), `--no-headless` (watch the browser), `--screenshots <dir>` (evidence capture).

> ⚠️ **Report contents.** Result files and reports include excerpts of the server's HTTP responses, which may contain sensitive data. Treat `results/` and generated reports as sensitive. (Request cookies / session tokens are **not** persisted — they stay in memory only.)

---

## Output

Reports include a severity summary, a **full test matrix** (every case + verdict + the server's response), and detailed findings with rule IDs, categories, payloads, and HTTP evidence. SARIF output drops into CI / code-scanning dashboards.

![Example report](demo-vuln/screenshots/08-report.png)

---

## Vulnerable testbed

`testbed/vulnerable-rp.ts` is an **intentionally insecure** WebAuthn relying party for exercising PasskeyPwn and for demos. It binds to `localhost` only and deliberately skips origin / challenge / counter / UV / attestation checks (each toggleable via `PPWN_CHECK_*=1`) while still verifying the signature and credential ID.

```bash
npx tsx testbed/vulnerable-rp.ts          # http://localhost:8099
# then point recon/fuzz/exploit at http://localhost:8099
```

> ⚠️ **Never deploy the testbed.** It is broken on purpose.

**Example outcomes (reproducible):**
- Against **webauthn.io** (FIDO reference implementation): **0 findings** — every mutation is correctly rejected. This demonstrates the tool does not cry wolf.
- Against the **vulnerable testbed**: **8 findings** (5 fuzz + 3 exploit), with `credid` and `recovery` correctly reported as *not* vulnerable — the tool distinguishes real weaknesses from properly-enforced checks.

---

## Project layout

```
src/
  cli.ts                     CLI entry + subcommand registration
  cli-commands/              recon | fuzz | exploit | report
  core/
    cbor-builder.ts          authenticatorData / clientDataJSON / attestationObject / COSE (canonical CBOR)
    signer.ts                ES256 keygen + DER signing
    shadow-authenticator.ts  full navigator.credentials override
    baseline-authenticator.ts CDP virtual authenticator (recon only)
    cdp-session.ts           browser lifecycle, robust navigation, screenshots
    ceremony-runner.ts       drive a ceremony on a page, classify the verdict
    webauthn-locator.ts      structural WebAuthn-field locator (envelope-agnostic)
    replay.ts                capture-mutate-replay engine (cookie-jar aware)
  modules/                   recon | fuzz | exploit engines
  reporting/                 SARIF + Markdown writers, shared results store
testbed/vulnerable-rp.ts     intentionally insecure RP for testing
```

---

## Limitations (honest)

- Replay currently supports JSON `finish` endpoints; form-encoded / non-JSON envelopes fall back to browser mode or are unsupported.
- `attestation` is exercised in browser mode (registration ceremony), not via replay.
- `rogue-persist` flags credential enrollment without re-auth; on **stateless demos with no account model** (e.g. webauthn.io) this is not a real vulnerability — verify the target has an authenticated account/session model before treating it as one.
- Recon's live-policy capture (RP ID / UV / attestation preference) can be flaky on some SPAs; the ceremony itself still runs. Verdicts from `fuzz --mode replay` and `exploit` are based on real HTTP status and are reliable.
- The `--authorized` gate is an audit record, not an access control.

---

## Responsible use

PasskeyPwn is for authorized security testing, research, and CTF/education. Do not use it against systems you do not own or lack written permission to test. Unauthorized testing may be illegal.

## License

ISC. See `package.json`.
