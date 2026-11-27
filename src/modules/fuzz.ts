/**
 * fuzz.ts — Phase 2: Mutation Fuzzing
 *
 * Drives the ShadowAuthenticator to submit WebAuthn responses with one field
 * deliberately mutated, then observes whether the relying party ACCEPTS a
 * ceremony it should REJECT. Each accepted mutation is a finding: it means a
 * server-side validation step is missing or weak.
 *
 * This is a conformance check of the *server's* verification logic — the
 * mutations are only meaningful against a target you are authorized to test.
 *
 * Available modules: origin, challenge, counter, flags, attestation, credid
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createCDPSession, closeCDPSession, captureScreenshot, CDPSessionOptions } from '../core/cdp-session.js';
import { ShadowAuthenticator } from '../core/shadow-authenticator.js';
import { FLAGS, toBase64Url } from '../core/cbor-builder.js';
import { runRegister, runAuthenticate, CeremonyResult } from '../core/ceremony-runner.js';
import { KeyPairES256, AnyKeyPair } from '../core/signer.js';
import {
  captureAuthTranscript,
  replayAssertion,
  AssertionOverrides,
  CeremonyTranscript,
} from '../core/replay.js';
import { loadHarTranscript } from '../core/har-import.js';
import { CaseResult, RunResult, saveRunResult } from '../reporting/results-store.js';

export type FuzzMode = 'browser' | 'replay';

export interface FuzzOptions {
  modules: string[];
  baselinePath?: string;
  urlRegister?: string;
  urlLogin?: string;
  outDir?: string;
  mode?: FuzzMode;
  screenshotDir?: string;
  sessionOptions?: CDPSessionOptions;
  fromHar?: string;
}

interface Baseline {
  meta: { targetUrlRegister: string; targetUrlLogin: string; username: string };
  analysis: {
    rpId: string | null;
    attestationPreference: string | null;
    userVerificationRequirement: string | null;
  };
}

interface MutationSpec {
  id: string;
  module: string;
  name: string;
  ceremony: 'register' | 'authenticate';
  category: string;
  description: string;
  severity: 'error' | 'warning' | 'note';
  payload: string;
  /** Whether this case is meaningful given the baseline policy. */
  isApplicable: (b: Baseline) => boolean;
  /** Configure the shadow authenticator to produce the mutated response (browser mode). */
  apply: (shadow: ShadowAuthenticator, b: Baseline) => void;
  /** Whether this mutation can run via the HTTP replay engine. */
  replayable: boolean;
  /** Build the assertion overrides for replay mode (assertion-ceremony cases only). */
  replayOverrides?: (b: Baseline) => AssertionOverrides;
}

const BOGUS_ORIGIN = 'https://passkeypwn-cross-origin.example';
const BOGUS_CHALLENGE = toBase64Url(Buffer.alloc(32, 0x41)); // 32 bytes of 'A'

/**
 * Mutation catalog. Each entry mutates exactly one field; a secure relying
 * party rejects all of them.
 */
const MUTATIONS: Record<string, MutationSpec> = {
  origin: {
    id: 'fuzz.origin.cross-origin',
    module: 'origin',
    name: 'Cross-origin clientDataJSON accepted',
    ceremony: 'authenticate',
    category: 'origin-spoofing',
    description:
      'The assertion was sent with clientDataJSON.origin set to an attacker-controlled origin. ' +
      'A compliant RP MUST reject an assertion whose origin does not match an expected origin (WebAuthn §7.2 step 13).',
    severity: 'error',
    payload: `origin="${BOGUS_ORIGIN}"`,
    isApplicable: () => true,
    apply: (shadow) => shadow.setGetOverrides({ origin: BOGUS_ORIGIN }),
    replayable: true,
    replayOverrides: () => ({ origin: BOGUS_ORIGIN }),
  },

  challenge: {
    id: 'fuzz.challenge.static',
    module: 'challenge',
    name: 'Mismatched challenge accepted (replay)',
    ceremony: 'authenticate',
    category: 'challenge-replay',
    description:
      'The assertion carried a fixed challenge that the server never issued. ' +
      'A compliant RP MUST verify clientDataJSON.challenge equals the challenge it generated (WebAuthn §7.2 step 11). ' +
      'Acceptance indicates the challenge is not bound, enabling replay.',
    severity: 'warning',
    payload: `challenge="${BOGUS_CHALLENGE}"`,
    isApplicable: () => true,
    apply: (shadow) => shadow.setGetOverrides({ challenge: BOGUS_CHALLENGE }),
    replayable: true,
    replayOverrides: () => ({ challenge: BOGUS_CHALLENGE }),
  },

  'rpid-scope': {
    id: 'fuzz.rpid.scope-confusion',
    module: 'rpid-scope',
    name: 'Assertion for a different rpId (scope confusion) accepted',
    ceremony: 'authenticate',
    category: 'rpid-scoping',
    description:
      'The assertion authenticatorData.rpIdHash was computed for a DIFFERENT rpId (parent/foreign domain). ' +
      'A compliant RP MUST verify rpIdHash == SHA-256(own rpId) (WebAuthn §7.2 step 15).',
    severity: 'error',
    payload: 'authenticatorData.rpIdHash = SHA-256(<parent/foreign domain>)',
    isApplicable: () => true,
    apply: (shadow, b) => {
      const rpId = b.analysis.rpId ?? '';
      const labels = rpId.split('.');
      const confused = labels.length >= 3 ? labels.slice(1).join('.') : `evil-${rpId}`;
      shadow.setGetOverrides({ rpId: confused });
    },
    replayable: true,
    replayOverrides: (b: Baseline) => {
      const rpId = b.analysis.rpId ?? '';
      const labels = rpId.split('.');
      const confused = labels.length >= 3 ? labels.slice(1).join('.') : `evil-${rpId}`;
      return { rpId: confused };
    },
  },

  'cdj-type': {
    id: 'fuzz.clientdata.type-confusion',
    module: 'cdj-type',
    name: 'Wrong clientDataJSON.type accepted',
    ceremony: 'authenticate',
    category: 'clientdata-validation',
    description:
      'clientDataJSON.type="webauthn.create" sent on an authenticate ceremony. RP MUST verify type matches ceremony (§7.2 step 11).',
    severity: 'warning',
    payload: 'clientDataJSON.type="webauthn.create"',
    isApplicable: () => true,
    apply: () => {},
    replayable: true,
    replayOverrides: () => ({ clientDataType: 'webauthn.create' }),
  },

  'cdj-crossorigin': {
    id: 'fuzz.clientdata.cross-origin-true',
    module: 'cdj-crossorigin',
    name: 'clientDataJSON.crossOrigin=true accepted',
    ceremony: 'authenticate',
    category: 'clientdata-validation',
    description:
      'Assertion produced inside a cross-origin iframe (crossOrigin=true). RP SHOULD reject for phishing resistance.',
    severity: 'note',
    payload: 'clientDataJSON.crossOrigin=true',
    isApplicable: () => true,
    apply: () => {},
    replayable: true,
    replayOverrides: () => ({ crossOrigin: true }),
  },

  'cdj-dupkey': {
    id: 'fuzz.clientdata.duplicate-challenge',
    module: 'cdj-dupkey',
    name: 'Duplicate clientDataJSON.challenge accepted (parser confusion)',
    ceremony: 'authenticate',
    category: 'clientdata-validation',
    description:
      'clientDataJSON contains two "challenge" members (real + attacker). Lax parser disagreement = smuggling vector.',
    severity: 'warning',
    payload: '{"challenge":"<real>","challenge":"<attacker>"}',
    isApplicable: () => true,
    apply: () => {},
    replayable: true,
    replayOverrides: () => ({ duplicateChallenge: BOGUS_CHALLENGE }),
  },

  'cdj-trailing': {
    id: 'fuzz.clientdata.trailing-bytes',
    module: 'cdj-trailing',
    name: 'Trailing bytes after clientDataJSON accepted',
    ceremony: 'authenticate',
    category: 'clientdata-validation',
    description:
      'Raw bytes appended after the clientDataJSON document — lenient parser indicator.',
    severity: 'note',
    payload: 'clientDataJSON = <json> || <trailing bytes>',
    isApplicable: () => true,
    apply: () => {},
    replayable: true,
    replayOverrides: () => ({ trailingBytes: Buffer.from('/*passkeypwn*/') }),
  },

  'flags-backup': {
    id: 'fuzz.flags.backup-state-invalid',
    module: 'flags-backup',
    name: 'Invalid backup flags (BS set, BE clear) accepted',
    ceremony: 'authenticate',
    category: 'flag-manipulation',
    description:
      'BS bit set while BE clear — spec-impossible combo (§6.1.3). RP tracking backup state MUST reject.',
    severity: 'note',
    payload: `flags=0x${(FLAGS.UP | FLAGS.UV | FLAGS.BS).toString(16).padStart(2, '0')} (UP|UV|BS, BE cleared)`,
    isApplicable: () => true,
    apply: (shadow) => shadow.setGetOverrides({ flags: FLAGS.UP | FLAGS.UV | FLAGS.BS }),
    replayable: true,
    replayOverrides: () => ({ flags: FLAGS.UP | FLAGS.UV | FLAGS.BS }),
  },

  counter: {
    id: 'fuzz.counter.regression',
    module: 'counter',
    name: 'Signature counter regression accepted',
    ceremony: 'authenticate',
    category: 'counter-manipulation',
    description:
      'The assertion reported signCount=0 after a higher count had been established. ' +
      'An RP that stores signature counts SHOULD treat a non-increasing counter as a sign of a cloned authenticator ' +
      '(WebAuthn §7.2 step 21). Silent acceptance means cloned-credential detection is not in effect.',
    severity: 'warning',
    payload: 'signCount=1 (regressed from 1000)',
    isApplicable: () => true,
    apply: (shadow) => shadow.setGetOverrides({ signCount: 1 }),
    replayable: true,
    replayOverrides: () => ({ signCount: 1 }),
  },

  flags: {
    id: 'fuzz.flags.uv-cleared',
    module: 'flags',
    name: 'Cleared User-Verified flag accepted',
    ceremony: 'authenticate',
    category: 'flag-manipulation',
    description:
      'The assertion was sent with the UV (User Verified) flag bit cleared while the RP requested userVerification=required. ' +
      'A compliant RP MUST verify the UV bit is set when it requires user verification (WebAuthn §7.2 step 17). ',
    severity: 'warning',
    payload: `flags=0x${(FLAGS.UP).toString(16).padStart(2, '0')} (UP only, UV cleared)`,
    isApplicable: (b) => b.analysis.userVerificationRequirement === 'required',
    apply: (shadow) => shadow.setGetOverrides({ flags: FLAGS.UP }),
    replayable: true,
    replayOverrides: () => ({ flags: FLAGS.UP }),
  },

  attestation: {
    id: 'fuzz.attestation.none-substituted',
    module: 'attestation',
    name: '"none" attestation accepted where attestation was requested',
    ceremony: 'register',
    category: 'attestation-bypass',
    description:
      'Registration was completed with fmt="none" and a zero AAGUID although the RP requested a non-none attestation. ' +
      'If the RP relies on attestation for authenticator provenance, it MUST validate the attestation statement rather than accept "none".',
    severity: 'warning',
    payload: 'attestationObject fmt="none", aaguid=00..00',
    isApplicable: (b) =>
      b.analysis.attestationPreference !== null && b.analysis.attestationPreference !== 'none',
    apply: (shadow) =>
      shadow.setCreateOverrides({ attestationFmt: 'none', aaguid: Buffer.alloc(16) }),
    replayable: false,
  },

  'attestation-packed': {
    id: 'fuzz.attestation.packed-bad-signature',
    module: 'attestation-packed',
    name: 'Packed attestation with invalid signature accepted',
    ceremony: 'register',
    category: 'attestation-bypass',
    description:
      'Registration completed with fmt="packed" self-attestation whose signature is computed over tampered authData. ' +
      'RP MUST verify the attestation signature against the embedded public key (WebAuthn §7.1 step 20).',
    severity: 'error',
    payload: 'attestationObject fmt="packed", sig=sign(tampered authData)',
    isApplicable: (b) =>
      b.analysis.attestationPreference !== null && b.analysis.attestationPreference !== 'none',
    apply: (shadow) =>
      shadow.setCreateOverrides({ attestationFmt: 'packed', selfAttestation: true, aaguid: Buffer.alloc(16) }),
    replayable: false,
  },

  credid: {
    id: 'fuzz.credid.unknown',
    module: 'credid',
    name: 'Assertion with unregistered credential ID accepted',
    ceremony: 'authenticate',
    category: 'credential-fuzzing',
    description:
      'The assertion was signed by a freshly generated credential whose ID was never registered for this user. ' +
      'A compliant RP MUST look up the credential by ID and verify the signature against the stored public key ' +
      '(WebAuthn §7.2 steps 3 & 16). Acceptance indicates the credential is not bound to the account.',
    severity: 'note',
    payload: 'credentialId=<random, unregistered>',
    isApplicable: () => true,
    // Configured per-run in runFuzz (needs a second credential index).
    apply: () => {},
    replayable: true,
    replayOverrides: () => ({ credentialId: randomBytes(32) }),
  },
};

function loadBaseline(path: string): Baseline {
  if (!existsSync(path)) {
    throw new Error(`Baseline not found at ${path}. Run "passkeypwn recon" first.`);
  }
  const parsed = JSON.parse(readFileSync(path, 'utf-8')) as Baseline;
  if (!parsed.meta || !parsed.analysis) {
    throw new Error(`Baseline at ${path} is malformed (missing meta/analysis).`);
  }
  return parsed;
}

function excerpt(body: string | null): string | null {
  if (!body) return null;
  return body.length > 500 ? body.slice(0, 500) : body;
}

/**
 * Run a single mutation case in a fresh browser session.
 */
async function runCase(
  spec: MutationSpec,
  baseline: Baseline,
  urlRegister: string,
  urlLogin: string,
  sessionOptions: CDPSessionOptions | undefined,
): Promise<CaseResult> {
  const rpId = baseline.analysis.rpId ?? new URL(urlRegister).hostname;
  const username = `ppwn_${spec.module}_${Date.now()}`;
  const endpoint = spec.ceremony === 'register' ? urlRegister : urlLogin;

  const base: Omit<CaseResult, 'classification' | 'isFinding' | 'statusCode' | 'responseExcerpt'> = {
    id: spec.id,
    module: spec.module,
    name: spec.name,
    ceremony: spec.ceremony,
    category: spec.category,
    description: spec.description,
    applicable: spec.isApplicable(baseline),
    severity: spec.severity,
    payload: spec.payload,
    endpoint,
  };

  const conn = await createCDPSession(sessionOptions);
  try {
    const shadow = new ShadowAuthenticator();
    shadow.generateCredential(rpId);
    await shadow.install(conn.page);

    if (spec.ceremony === 'register') {
      // Mutated registration.
      shadow.setCreateOverrides({});
      spec.apply(shadow, baseline);
      const reg = await runRegister(conn.page, urlRegister, username);
      return finalize(base, reg, spec.severity);
    }

    // Authentication-ceremony cases: first establish a clean, registered
    // credential, then submit a mutated assertion.
    shadow.clearOverrides();
    const reg = await runRegister(conn.page, urlRegister, username);
    if (reg.classification !== 'ACCEPTED') {
      return {
        ...base,
        classification: 'SKIPPED',
        isFinding: false,
        statusCode: reg.statusCode,
        responseExcerpt: `Baseline registration not accepted (${reg.classification}); cannot test assertion.`,
      };
    }

    if (spec.module === 'credid') {
      // Authenticate with a brand-new, unregistered credential.
      shadow.generateCredential(rpId);
      shadow.setGetOverrides({ credentialIndex: shadow.getCredentials().length - 1 });
    } else {
      shadow.clearOverrides();
      spec.apply(shadow, baseline);
    }

    const auth = await runAuthenticate(conn.page, urlLogin, username);
    return finalize(base, auth, spec.severity);
  } finally {
    await closeCDPSession(conn).catch(() => {});
  }
}

function finalize(
  base: Omit<CaseResult, 'classification' | 'isFinding' | 'statusCode' | 'responseExcerpt'>,
  res: CeremonyResult,
  severity: 'error' | 'warning' | 'note',
): CaseResult {
  // A secure RP rejects the mutation. Acceptance of an applicable mutation is a finding.
  const isFinding = base.applicable && res.classification === 'ACCEPTED';
  return {
    ...base,
    severity,
    classification: res.classification,
    isFinding,
    statusCode: res.statusCode,
    responseExcerpt: excerpt(res.body),
  };
}

interface ReplayContext {
  transcript: CeremonyTranscript;
  keyPair: AnyKeyPair;
  credentialId: Buffer;
}

/**
 * Register a credential and capture one authentication ceremony so that later
 * mutations can be rebuilt, re-signed, and replayed directly over HTTP.
 */
async function setupReplay(
  baseline: Baseline,
  urlRegister: string,
  urlLogin: string,
  sessionOptions: CDPSessionOptions | undefined,
  screenshotDir?: string,
): Promise<ReplayContext> {
  const rpId = baseline.analysis.rpId ?? new URL(urlRegister).hostname;
  const origin = new URL(urlLogin).origin;
  const username = `ppwn_replay_${Date.now()}`;

  const conn = await createCDPSession(sessionOptions);
  try {
    const shadow = new ShadowAuthenticator();
    const cred = shadow.generateCredential(rpId);
    await shadow.install(conn.page);

    const reg = await runRegister(conn.page, urlRegister, username);
    if (screenshotDir) {
      const p = await captureScreenshot(conn.page, screenshotDir, '05-fuzz-capture-register');
      console.log(`[fuzz] 📸 ${p}`);
    }
    // Only abort on an explicit rejection. DOM-based accept/reject detection is
    // unreliable across sites (SPA timing); the replay step verifies the real
    // outcome via direct HTTP status, so an ambiguous UNKNOWN should not block it.
    if (reg.classification === 'REJECTED') {
      throw new Error(`baseline registration was rejected (${reg.statusCode ?? 'no status'})`);
    }

    const transcript = await captureAuthTranscript(conn.page, urlLogin, username, rpId, origin);
    if (screenshotDir) {
      const p = await captureScreenshot(conn.page, screenshotDir, '06-fuzz-capture-authenticate');
      console.log(`[fuzz] 📸 ${p}`);
    }
    if (!transcript) {
      throw new Error('could not capture an authentication transcript');
    }
    return { transcript, keyPair: cred.keyPair, credentialId: cred.credentialId };
  } finally {
    await closeCDPSession(conn).catch(() => {});
  }
}

/**
 * Run a single assertion mutation via the HTTP replay engine (no browser).
 */
async function runReplayCase(
  spec: MutationSpec,
  replay: ReplayContext,
  baseline: Baseline,
): Promise<CaseResult> {
  const overrides: AssertionOverrides = spec.replayOverrides ? spec.replayOverrides(baseline) : {};
  const res = await replayAssertion(replay.transcript, replay.keyPair, replay.credentialId, overrides);
  (res as any).__poc = res.request;

  const applicable = spec.isApplicable(baseline);
  const isFinding = applicable && res.classification === 'ACCEPTED';
  return {
    id: spec.id,
    module: spec.module,
    name: spec.name,
    ceremony: spec.ceremony,
    category: spec.category,
    description: spec.description,
    applicable,
    severity: spec.severity,
    classification: res.classification,
    isFinding,
    statusCode: res.statusCode,
    responseExcerpt: excerpt(res.body),
    payload: spec.payload,
    endpoint: replay.transcript.finishRequest.url,
    poc: res.request as any,
  };
}

/**
 * Run the selected fuzz modules against the target and persist results.
 */
export async function runFuzz(opts: FuzzOptions): Promise<RunResult> {
  const baselinePath = resolve(opts.baselinePath ?? resolve(process.cwd(), 'baseline.json'));
  const baseline = loadBaseline(baselinePath);

  const urlRegister = opts.urlRegister ?? baseline.meta.targetUrlRegister;
  const urlLogin = opts.urlLogin ?? baseline.meta.targetUrlLogin;

  const requested = opts.modules.map((m) => m.trim().toLowerCase()).filter(Boolean);
  const unknown = requested.filter((m) => !(m in MUTATIONS));
  if (unknown.length > 0) {
    throw new Error(
      `Unknown fuzz module(s): ${unknown.join(', ')}. ` +
        `Available: ${Object.keys(MUTATIONS).join(', ')}`,
    );
  }

  const mode: FuzzMode = opts.mode ?? 'browser';

  console.log(`[fuzz] 🎯 Target register: ${urlRegister}`);
  console.log(`[fuzz] 🎯 Target login:    ${urlLogin}`);
  console.log(`[fuzz] 🧬 Modules:         ${requested.join(', ')}`);
  console.log(`[fuzz] ⚙️  Mode:            ${mode}`);
  console.log('');

  // In replay mode, capture one ceremony up front so every assertion mutation
  // can be rebuilt and replayed over HTTP without re-driving the browser.
  let replay: ReplayContext | null = null;
  if (mode === 'replay') {
    const needsReplay = requested.some(
      (m) => MUTATIONS[m]!.replayable && MUTATIONS[m]!.isApplicable(baseline),
    );
    if (needsReplay) {
      console.log('[fuzz] 🧵 Capturing one authentication transcript for replay...');
      try {
        if (opts.fromHar) {
          replay = { transcript: loadHarTranscript(opts.fromHar), keyPair: (await import('../core/signer.js')).generateES256KeyPair(), credentialId: Buffer.alloc(32) };
        } else {
          replay = await setupReplay(baseline, urlRegister, urlLogin, opts.sessionOptions, opts.screenshotDir);
        }
        console.log(`[fuzz]   ✅ Transcript captured (finish: ${replay.transcript.finishRequest.url})`);
      } catch (err) {
        console.log(
          `[fuzz]   ⚠️  Replay setup failed (${err instanceof Error ? err.message : String(err)}); ` +
            `falling back to browser mode.`,
        );
      }
      console.log('');
    }
  }

  const cases: CaseResult[] = [];
  for (const module of requested) {
    const spec = MUTATIONS[module]!;
    const useReplay = mode === 'replay' && spec.replayable && replay !== null;
    console.log(`[fuzz] ▶ ${spec.module}: ${spec.name}${useReplay ? ' [replay]' : ''}`);

    if (mode === 'replay' && !spec.replayable) {
      console.log(`[fuzz]   ↩  Not replayable (${spec.ceremony} ceremony) — using browser for this case.`);
    }

    if (!spec.isApplicable(baseline)) {
      console.log(`[fuzz]   ⏭  Not applicable to this target's baseline policy — recording as N/A.`);
      cases.push({
        id: spec.id,
        module: spec.module,
        name: spec.name,
        ceremony: spec.ceremony,
        category: spec.category,
        description: spec.description,
        applicable: false,
        severity: spec.severity,
        classification: 'SKIPPED',
        isFinding: false,
        statusCode: null,
        responseExcerpt: 'Mutation not meaningful for the observed baseline policy.',
        payload: spec.payload,
        endpoint: spec.ceremony === 'register' ? urlRegister : urlLogin,
      });
      continue;
    }

    try {
      const result = useReplay
        ? await runReplayCase(spec, replay!, baseline)
        : await runCase(spec, baseline, urlRegister, urlLogin, opts.sessionOptions);
      cases.push(result);
      const verdict = result.isFinding
        ? `🔴 FINDING (server accepted the mutation, status ${result.statusCode})`
        : result.classification === 'REJECTED'
          ? `✅ rejected (secure)`
          : `• ${result.classification}`;
      console.log(`[fuzz]   ${verdict}`);
    } catch (err) {
      console.log(`[fuzz]   ❌ Error: ${err instanceof Error ? err.message : String(err)}`);
      cases.push({
        id: spec.id,
        module: spec.module,
        name: spec.name,
        ceremony: spec.ceremony,
        category: spec.category,
        description: spec.description,
        applicable: true,
        severity: spec.severity,
        classification: 'ERROR',
        isFinding: false,
        statusCode: null,
        responseExcerpt: err instanceof Error ? err.message : String(err),
        payload: spec.payload,
        endpoint: spec.ceremony === 'register' ? urlRegister : urlLogin,
      });
    }
    console.log('');
  }

  const run: RunResult = {
    meta: {
      tool: 'PasskeyPwn',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      phase: 'fuzz',
      target: urlLogin,
      modules: requested,
    },
    cases,
  };

  const path = saveRunResult(run, opts.outDir);
  console.log(`[fuzz] 📄 Results saved to: ${path}`);

  const findings = cases.filter((c) => c.isFinding).length;
  console.log(
    findings > 0
      ? `[fuzz] ⚠️  ${findings} finding(s): the server accepted mutations it should reject.`
      : `[fuzz] ✅ No findings: all applicable mutations were rejected.`,
  );

  return run;
}
