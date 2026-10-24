/**
 * cbor-builder.ts
 * 
 * Manual byte-level builder for WebAuthn data structures:
 * - authenticatorData
 * - clientDataJSON
 * - attestationObject
 * 
 * This gives us full control over every byte, enabling mutation testing
 * where we need to produce intentionally malformed or spoofed data.
 */

import { createHash } from 'node:crypto';
import { Encoder } from 'cbor-x';

/**
 * WebAuthn structures must be *standard* canonical CBOR: plain maps and plain
 * byte strings. cbor-x defaults to `useRecords: true` (emits non-standard record
 * tags for plain objects) and tags typed arrays — both produce CBOR that strict
 * server decoders (e.g. py_webauthn's cbor2) reject with
 * "'CBORTag' object is not subscriptable". This encoder forces spec-compliant output.
 */
const cbor = new Encoder({ useRecords: false, mapsAsObjects: false, tagUint8Array: false });
function cborEncode(value: unknown): Buffer {
  return Buffer.from(cbor.encode(value));
}

// ─── Flag bit positions (per WebAuthn spec §6.1) ───
export const FLAGS = {
  UP: 0x01,        // bit 0: User Present
  // bit 1: Reserved
  UV: 0x04,        // bit 2: User Verified
  BE: 0x08,        // bit 3: Backup Eligibility
  BS: 0x10,        // bit 4: Backup State
  // bit 5: Reserved
  AT: 0x40,        // bit 6: Attested credential data included
  ED: 0x80,        // bit 7: Extension data included
} as const;

export interface AuthenticatorDataOptions {
  /** The Relying Party ID (e.g., "webauthn.io"). SHA-256 is computed from this. */
  rpId: string;
  /** Override rpIdHash directly (32 bytes). If set, rpId is ignored for hashing. */
  rpIdHash?: Buffer;
  /** Flags byte. Use FLAGS constants combined with bitwise OR. */
  flags: number;
  /** Sign count (4-byte big-endian unsigned integer). */
  signCount: number;
  /** Attested credential data (only for registration). */
  attestedCredentialData?: {
    aaguid: Buffer;           // 16 bytes
    credentialId: Buffer;     // variable length
    cosePublicKey: Buffer;    // CBOR-encoded COSE key
  };
  /** Raw extension data (CBOR-encoded). */
  extensions?: Buffer;
}

/**
 * Build authenticatorData from individual fields.
 * Layout per WebAuthn spec §6.1:
 *   rpIdHash (32) | flags (1) | signCount (4) | [attestedCredData] | [extensions]
 */
export function buildAuthenticatorData(opts: AuthenticatorDataOptions): Buffer {
  // rpIdHash: either provided directly or computed from rpId
  const rpIdHash = opts.rpIdHash ?? sha256(opts.rpId);

  if (rpIdHash.length !== 32) {
    throw new Error(`rpIdHash must be exactly 32 bytes, got ${rpIdHash.length}`);
  }

  // flags: 1 byte
  const flagsBuf = Buffer.alloc(1);
  flagsBuf[0] = opts.flags;

  // signCount: 4 bytes big-endian
  const signCountBuf = Buffer.alloc(4);
  signCountBuf.writeUInt32BE(opts.signCount);

  const parts: Buffer[] = [rpIdHash, flagsBuf, signCountBuf];

  // Attested credential data (present during registration)
  if (opts.attestedCredentialData) {
    const acd = opts.attestedCredentialData;

    if (acd.aaguid.length !== 16) {
      throw new Error(`AAGUID must be exactly 16 bytes, got ${acd.aaguid.length}`);
    }

    // credIdLen: 2 bytes big-endian
    const credIdLenBuf = Buffer.alloc(2);
    credIdLenBuf.writeUInt16BE(acd.credentialId.length);

    parts.push(acd.aaguid, credIdLenBuf, acd.credentialId, acd.cosePublicKey);
  }

  // Extensions
  if (opts.extensions) {
    parts.push(opts.extensions);
  }

  return Buffer.concat(parts);
}

/**
 * Build clientDataJSON as a JSON string (UTF-8 encoded).
 * This is what the browser normally constructs.
 */
export function buildClientDataJSON(opts: {
  type: 'webauthn.create' | 'webauthn.get';
  challenge: string;          // base64url-encoded challenge from server
  origin: string;             // e.g., "https://webauthn.io"
  crossOrigin?: boolean;
  tokenBinding?: { status: string; id?: string };
}): Buffer {
  const obj: Record<string, unknown> = {
    type: opts.type,
    challenge: opts.challenge,
    origin: opts.origin,
  };

  if (opts.crossOrigin !== undefined) {
    obj.crossOrigin = opts.crossOrigin;
  }

  if (opts.tokenBinding) {
    obj.tokenBinding = opts.tokenBinding;
  }

  return Buffer.from(JSON.stringify(obj), 'utf-8');
}

/**
 * Build a CBOR-encoded attestation object.
 * For "none" attestation: { fmt: "none", attStmt: {}, authData: <bytes> }
 * For "packed" self-attestation: { fmt: "packed", attStmt: { alg, sig }, authData: <bytes> }
 */
export function buildAttestationObject(opts: {
  fmt: 'none' | 'packed' | 'fido-u2f';
  authData: Buffer;
  attStmt?: Record<string, unknown>;
}): Buffer {
  const obj = {
    fmt: opts.fmt,
    attStmt: opts.attStmt ?? {},
    authData: opts.authData,
  };

  return Buffer.from(cborEncode(obj));
}

/**
 * Build a COSE public key (EC2, P-256) in CBOR format.
 * COSE Key parameters for EC2/P-256:
 *   1 (kty): 2 (EC2)
 *   3 (alg): -7 (ES256)
 *  -1 (crv): 1 (P-256)
 *  -2 (x): 32-byte x coordinate
 *  -3 (y): 32-byte y coordinate
 */
export function buildCoseES256PublicKey(x: Buffer, y: Buffer): Buffer {
  if (x.length !== 32 || y.length !== 32) {
    throw new Error('EC2 P-256 coordinates must be 32 bytes each');
  }

  const coseKey = new Map<number, number | Buffer>();
  coseKey.set(1, 2);     // kty: EC2
  coseKey.set(3, -7);    // alg: ES256
  coseKey.set(-1, 1);    // crv: P-256
  coseKey.set(-2, x);    // x coordinate
  coseKey.set(-3, y);    // y coordinate

  return Buffer.from(cborEncode(coseKey));
}

// ─── Utility ───

export function sha256(data: string | Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}

/**
 * base64url encode (no padding).
 */
export function toBase64Url(buf: Buffer): string {
  return buf.toString('base64url');
}

