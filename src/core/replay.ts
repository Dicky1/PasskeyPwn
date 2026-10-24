/**
 * replay.ts
 *
 * Capture-mutate-replay engine. Instead of driving the browser UI for every
 * mutation, we capture a single real assertion ceremony (the options POST and
 * the finish POST), then rebuild + re-sign the WebAuthn components in Node and
 * replay the finish request directly over HTTP for each mutation.
 *
 * This makes fuzzing target-agnostic (no per-site DOM selectors) and
 * deterministic. Re-signing is possible because the credential's private key is
 * held by the ShadowAuthenticator that performed the captured ceremony.
 */

import { Page, Request } from 'playwright';
import { buildAuthenticatorData, buildClientDataJSON } from './cbor-builder.js';
import { KeyPairES256, signAssertion } from './signer.js';
import {
  locateWebAuthnFields,
  getAtPath,
  setAtPath,
  encodeAs,
  LocatedFields,
} from './webauthn-locator.js';
import {
  fillUsername,
  clickAuthenticate,
  LOGIN_URL_KEYWORDS,
} from './ceremony-runner.js';
import { gotoSettled } from './cdp-session.js';

export interface CapturedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
}

export interface CeremonyTranscript {
  rpId: string;
  origin: string;
  /** The first ceremony POST — typically the "options"/"start" call. */
  optionsRequest: CapturedRequest | null;
  /** The last ceremony POST — the "finish"/"verify" call carrying the assertion. */
  finishRequest: CapturedRequest;
}

export interface AssertionOverrides {
  rpId?: string;
  origin?: string;
  /** base64url challenge; when omitted a fresh one is fetched from the options endpoint. */
  challenge?: string;
  flags?: number;
  signCount?: number;
  credentialId?: Buffer;
  userHandle?: Buffer;
}

export interface ReplayResult {
  classification: 'ACCEPTED' | 'REJECTED' | 'ERROR' | 'UNKNOWN';
  statusCode: number | null;
  body: string | null;
}

/**
 * Capture an assertion ceremony's HTTP exchange while the ShadowAuthenticator
 * (already installed on the page, with a registered credential) performs it.
 */
export async function captureAuthTranscript(
  page: Page,
  urlLogin: string,
  username: string,
  rpId: string,
  origin: string,
): Promise<CeremonyTranscript | null> {
  const reqs: Request[] = [];

  const handler = (req: Request) => {
    if (req.method() !== 'POST') return;
    const u = req.url().toLowerCase();
    if (!LOGIN_URL_KEYWORDS.some((k) => u.includes(k))) return;
    reqs.push(req);
  };

  page.on('request', handler);
  try {
    await gotoSettled(page, urlLogin);
    await fillUsername(page, username);
    await clickAuthenticate(page);
    await page.waitForTimeout(8000);
  } finally {
    page.off('request', handler);
  }

  if (reqs.length === 0) return null;

  // Use allHeaders() (async) — unlike headers(), it includes cookie and
  // CSRF headers added by the network layer, which the replay needs.
  const posts: CapturedRequest[] = [];
  for (const req of reqs) {
    posts.push({
      url: req.url(),
      method: req.method(),
      headers: await req.allHeaders(),
      body: req.postData(),
    });
  }
  // Prefer a finish request that actually carries an assertion payload.
  const finish =
    [...posts].reverse().find((p) => p.body && /clientdata|signature|authenticator/i.test(p.body)) ??
    posts[posts.length - 1]!;
  const options = posts.find((p) => p !== finish) ?? null;

  return { rpId, origin, optionsRequest: options, finishRequest: finish };
}

function sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (lk === 'content-length' || lk === 'host' || lk === 'connection' || lk === 'accept-encoding') {
      continue;
    }
    if (lk.startsWith(':')) continue; // HTTP/2 pseudo-headers
    out[k] = v;
  }
  return out;
}

function classify(status: number): ReplayResult['classification'] {
  if (status >= 200 && status < 300) return 'ACCEPTED';
  if (status >= 400) return 'REJECTED';
  return 'ERROR';
}

// ─── cookie jar ───
// Many RPs (webauthn.io among them) bind the ceremony challenge to a server-side
// session keyed by cookie. A replay must therefore call the options endpoint to
// establish a fresh session+challenge, then send the finish on that SAME session.

function headerGet(headers: Record<string, string>, name: string): string | undefined {
  const lk = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) if (k.toLowerCase() === lk) return v;
  return undefined;
}

function parseCookieHeader(h: string | undefined): Map<string, string> {
  const jar = new Map<string, string>();
  if (!h) return jar;
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) jar.set(part.slice(0, i).trim(), part.slice(i + 1).trim());
  }
  return jar;
}

function applySetCookies(jar: Map<string, string>, setCookies: string[]): void {
  for (const sc of setCookies) {
    const first = sc.split(';')[0] ?? '';
    const i = first.indexOf('=');
    if (i > 0) jar.set(first.slice(0, i).trim(), first.slice(i + 1).trim());
  }
}

function serializeJar(jar: Map<string, string>): string {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}

function withCookie(headers: Record<string, string>, cookie: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) if (k.toLowerCase() !== 'cookie') out[k] = v;
  if (cookie) out['cookie'] = cookie;
  return out;
}

function getSetCookies(resp: { headers: { getSetCookie?: () => string[]; get?: (n: string) => string | null } }): string[] {
  if (typeof resp.headers.getSetCookie === 'function') return resp.headers.getSetCookie();
  const sc = resp.headers.get?.('set-cookie');
  return sc ? [sc] : [];
}

function decodeToB64Url(raw: string, encoding: string): string {
  const bytes = encoding === 'base64' ? Buffer.from(raw, 'base64') : Buffer.from(raw, 'base64url');
  return bytes.toString('base64url');
}

/**
 * Establish a fresh session by replaying the options request, carrying cookies,
 * and return the server-issued challenge (base64url) plus the live cookie jar.
 */
async function establishSession(
  transcript: CeremonyTranscript,
  jar: Map<string, string>,
): Promise<string | null> {
  if (!transcript.optionsRequest) return null;
  const opt = transcript.optionsRequest;
  try {
    const resp = await fetch(opt.url, {
      method: opt.method,
      headers: withCookie(sanitizeHeaders(opt.headers), serializeJar(jar)),
      body: opt.body ?? undefined,
    });
    applySetCookies(jar, getSetCookies(resp));
    const text = await resp.text();
    const json = JSON.parse(text);
    const fields = locateWebAuthnFields(json);
    if (!fields.challenge) return null;
    const raw = getAtPath(json, fields.challenge.path);
    if (typeof raw !== 'string') return null;
    return decodeToB64Url(raw, fields.challenge.encoding);
  } catch {
    return null;
  }
}

/**
 * Rebuild the assertion with the given overrides, re-sign it, splice it into the
 * captured finish request body, and replay it over HTTP on a fresh session.
 */
export async function replayAssertion(
  transcript: CeremonyTranscript,
  keyPair: KeyPairES256,
  baseCredentialId: Buffer,
  overrides: AssertionOverrides,
): Promise<ReplayResult> {
  const finish = transcript.finishRequest;
  if (!finish.body) {
    return { classification: 'ERROR', statusCode: null, body: 'Captured finish request had no body to replay.' };
  }

  let json: any;
  try {
    json = JSON.parse(finish.body);
  } catch {
    return { classification: 'ERROR', statusCode: null, body: 'Finish request body is not JSON; replay unsupported.' };
  }

  const fields: LocatedFields = locateWebAuthnFields(json);
  if (!fields.clientDataJSON || !fields.authenticatorData || !fields.signature) {
    return {
      classification: 'ERROR',
      statusCode: null,
      body:
        'Could not locate clientDataJSON / authenticatorData / signature in the finish payload. ' +
        'This RP envelope is not yet supported by replay mode; use --mode browser.',
    };
  }

  const rpId = overrides.rpId ?? transcript.rpId;
  const origin = overrides.origin ?? transcript.origin;
  const flags = overrides.flags ?? 0x05; // UP | UV
  const signCount = overrides.signCount ?? 0;
  const credentialId = overrides.credentialId ?? baseCredentialId;

  // Start from the captured session cookies, then establish a fresh session so
  // the server has a stored challenge bound to this cookie jar.
  const jar = parseCookieHeader(headerGet(finish.headers, 'cookie'));
  const realChallenge = await establishSession(transcript, jar);

  // Default: echo the server's fresh challenge. The challenge mutation overrides
  // it with a wrong value, but the session is still valid so the server reaches
  // the challenge-comparison step (and should reject).
  const challengeB64Url = overrides.challenge ?? realChallenge;
  if (!challengeB64Url) {
    return {
      classification: 'ERROR',
      statusCode: null,
      body: 'Could not obtain a challenge for replay (no options request captured or challenge not found).',
    };
  }

  const authData = buildAuthenticatorData({ rpId, flags, signCount });
  const clientDataJSON = buildClientDataJSON({ type: 'webauthn.get', challenge: challengeB64Url, origin });
  const signature = signAssertion(keyPair, authData, clientDataJSON);

  // Splice rebuilt components back into the envelope, preserving each field's encoding.
  setAtPath(json, fields.clientDataJSON.path, encodeAs(clientDataJSON, fields.clientDataJSON.encoding));
  setAtPath(json, fields.authenticatorData.path, encodeAs(authData, fields.authenticatorData.encoding));
  setAtPath(json, fields.signature.path, encodeAs(signature, fields.signature.encoding));
  if (fields.credentialId) {
    setAtPath(json, fields.credentialId.path, encodeAs(credentialId, fields.credentialId.encoding));
  }
  if (fields.userHandle && overrides.userHandle) {
    setAtPath(json, fields.userHandle.path, encodeAs(overrides.userHandle, fields.userHandle.encoding));
  }

  try {
    const resp = await fetch(finish.url, {
      method: finish.method,
      headers: withCookie(sanitizeHeaders(finish.headers), serializeJar(jar)),
      body: JSON.stringify(json),
    });
    const body = await resp.text().catch(() => null);
    return { classification: classify(resp.status), statusCode: resp.status, body };
  } catch (err) {
    return {
      classification: 'ERROR',
      statusCode: null,
      body: `Replay request failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}
