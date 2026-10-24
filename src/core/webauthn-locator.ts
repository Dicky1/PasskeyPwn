/**
 * webauthn-locator.ts
 *
 * Finds WebAuthn fields inside an arbitrary JSON envelope by decoding candidate
 * strings and recognizing their structure — NOT by hard-coded field names.
 *
 * Different relying parties wrap the ceremony payload differently (SimpleWebAuthn,
 * py_webauthn, custom shapes, nested under `response`/`publicKey`, etc.). To replay
 * a mutated ceremony against any of them, we must locate clientDataJSON,
 * authenticatorData, attestationObject, signature, the credential id and the
 * challenge wherever they live. We do that structurally so the replay engine is
 * target-agnostic.
 */

import { decode as cborDecode } from 'cbor-x';

export type Encoding = 'base64url' | 'base64' | 'utf8json';

export type JsonPath = Array<string | number>;

export interface Located {
  path: JsonPath;
  encoding: Encoding;
}

export interface LocatedFields {
  clientDataJSON?: Located;
  authenticatorData?: Located;
  attestationObject?: Located;
  signature?: Located;
  userHandle?: Located;
  credentialId?: Located;
  /** Only meaningful for options/start responses. */
  challenge?: Located;
}

interface Candidate {
  path: JsonPath;
  key: string; // the object key this value sits under ('' for array elements / root)
  raw: string;
  bytes: Buffer;
  encoding: Encoding;
}

/** Detect the binary string encoding, or null if it is not a plausible blob. */
function detectEncoding(s: string): Encoding | null {
  if (s.length < 4) return null;
  // base64url is distinguished by - or _ (and is conventionally unpadded).
  if (/[-_]/.test(s) && /^[A-Za-z0-9_-]+={0,2}$/.test(s)) return 'base64url';
  // Standard base64 is signalled by + / or by '=' padding.
  if (/[+/=]/.test(s) && /^[A-Za-z0-9+/]+={0,2}$/.test(s)) return 'base64';
  // Pure alphanumeric, unpadded: WebAuthn convention is base64url.
  if (/^[A-Za-z0-9]+$/.test(s)) return 'base64url';
  return null;
}

function decodeBytes(s: string, enc: Encoding): Buffer | null {
  try {
    return enc === 'base64' ? Buffer.from(s, 'base64') : Buffer.from(s, 'base64url');
  } catch {
    return null;
  }
}

/** Is this buffer a UTF-8 JSON object with the clientData shape? */
function looksLikeClientData(bytes: Buffer): boolean {
  try {
    const txt = bytes.toString('utf-8');
    if (!txt.trimStart().startsWith('{')) return false;
    const obj = JSON.parse(txt);
    return (
      typeof obj === 'object' &&
      obj !== null &&
      typeof obj.type === 'string' &&
      'challenge' in obj &&
      'origin' in obj
    );
  } catch {
    return false;
  }
}

/** Is this buffer a CBOR attestationObject? */
function looksLikeAttestationObject(bytes: Buffer): boolean {
  try {
    const obj = cborDecode(bytes);
    return (
      typeof obj === 'object' &&
      obj !== null &&
      'fmt' in obj &&
      'authData' in obj &&
      'attStmt' in obj
    );
  } catch {
    return false;
  }
}

/** Plausible assertion authenticatorData: >=37 bytes, flags byte sane, not DER. */
function looksLikeAuthenticatorData(bytes: Buffer): boolean {
  if (bytes.length < 37) return false;
  if (bytes[0] === 0x30) return false; // DER signature
  const flags = bytes[32]!;
  // UP is almost always set; reserved bits 1 and 5 should be clear for typical assertions.
  return (flags & 0x01) !== 0;
}

/** Plausible ECDSA signature: DER SEQUENCE. */
function looksLikeDerSignature(bytes: Buffer): boolean {
  return bytes.length >= 8 && bytes.length <= 144 && bytes[0] === 0x30;
}

function collectCandidates(value: unknown, path: JsonPath, key: string, out: Candidate[]): void {
  if (typeof value === 'string') {
    const enc = detectEncoding(value);
    if (enc) {
      const bytes = decodeBytes(value, enc);
      if (bytes && bytes.length >= 2) {
        out.push({ path: [...path], key, raw: value, bytes, encoding: enc });
      }
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => collectCandidates(v, [...path, i], key, out));
    return;
  }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      collectCandidates(v, [...path, k], k, out);
    }
  }
}

const keyHint = {
  clientData: /clientdata/i,
  attestationObject: /attestation.?object/i,
  authenticatorData: /authenticator.?data|^authdata$/i,
  signature: /^(signature|sig)$/i,
  userHandle: /user.?handle/i,
  credentialId: /^(id|rawid|credential.?id|keyid)$/i,
  challenge: /challenge/i,
};

/**
 * Locate WebAuthn fields in a parsed finish-ceremony request body.
 * Field names are used as a hint, but assignment is confirmed by structure so
 * that unusual envelopes still resolve correctly.
 */
export function locateWebAuthnFields(body: unknown): LocatedFields {
  const candidates: Candidate[] = [];
  collectCandidates(body, [], '', candidates);

  const result: LocatedFields = {};
  const taken = new Set<Candidate>();

  const assign = (field: keyof LocatedFields, c: Candidate) => {
    if (result[field]) return;
    result[field] = { path: c.path, encoding: c.encoding };
    taken.add(c);
  };

  // 1) Structural recognition (most reliable, name-independent).
  for (const c of candidates) {
    if (taken.has(c)) continue;
    if (!result.clientDataJSON && looksLikeClientData(c.bytes)) {
      assign('clientDataJSON', c);
    } else if (!result.attestationObject && looksLikeAttestationObject(c.bytes)) {
      assign('attestationObject', c);
    }
  }
  for (const c of candidates) {
    if (taken.has(c)) continue;
    if (!result.signature && looksLikeDerSignature(c.bytes)) {
      assign('signature', c);
    }
  }
  for (const c of candidates) {
    if (taken.has(c)) continue;
    if (!result.authenticatorData && looksLikeAuthenticatorData(c.bytes)) {
      assign('authenticatorData', c);
    }
  }

  // 2) Name hints for fields with no reliable structural signature.
  for (const c of candidates) {
    if (!result.credentialId && keyHint.credentialId.test(c.key)) assign('credentialId', c);
    if (!result.userHandle && keyHint.userHandle.test(c.key)) assign('userHandle', c);
    if (!result.challenge && keyHint.challenge.test(c.key)) assign('challenge', c);
    if (!result.clientDataJSON && keyHint.clientData.test(c.key)) assign('clientDataJSON', c);
    if (!result.authenticatorData && keyHint.authenticatorData.test(c.key)) assign('authenticatorData', c);
    if (!result.signature && keyHint.signature.test(c.key)) assign('signature', c);
    if (!result.attestationObject && keyHint.attestationObject.test(c.key)) assign('attestationObject', c);
  }

  return result;
}

// ─── JSON path get/set + re-encoding ───

export function getAtPath(obj: unknown, path: JsonPath): unknown {
  let cur: any = obj;
  for (const seg of path) {
    if (cur == null) return undefined;
    cur = cur[seg as any];
  }
  return cur;
}

export function setAtPath(obj: unknown, path: JsonPath, value: unknown): void {
  if (path.length === 0) return;
  let cur: any = obj;
  for (let i = 0; i < path.length - 1; i++) {
    cur = cur[path[i] as any];
    if (cur == null) throw new Error(`setAtPath: broken path at segment ${String(path[i])}`);
  }
  cur[path[path.length - 1] as any] = value;
}

export function encodeAs(bytes: Buffer, enc: Encoding): string {
  switch (enc) {
    case 'base64':
      return bytes.toString('base64');
    case 'base64url':
      return bytes.toString('base64url');
    case 'utf8json':
      return bytes.toString('utf-8');
  }
}
