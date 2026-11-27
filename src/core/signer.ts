/**
 * signer.ts
 *
 * ES256 (P-256 / ECDSA) key generation and signing using Node's native crypto.
 * These keys back the ShadowAuthenticator, which produces valid (or deliberately
 * mutated) WebAuthn signatures. WebAuthn's most widely supported algorithm is
 * ES256 (COSE alg -7), which is all this tool needs.
 */

import { generateKeyPairSync, createSign, KeyObject, sign as cryptoSign } from 'node:crypto';
import { sha256 } from './cbor-builder.js';

export interface KeyPairES256 {
  alg: 'ES256';
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicKeyRaw: Buffer;
  x: Buffer;
  y: Buffer;
}

export interface KeyPairRS256 {
  alg: 'RS256';
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicKeySpki: Buffer;
  /** RSA modulus */
  n: Buffer;
  /** RSA public exponent */
  e: Buffer;
}

export interface KeyPairEdDSA {
  alg: 'EdDSA';
  privateKey: KeyObject;
  publicKey: KeyObject;
  /** Raw 32-byte Ed25519 public key */
  publicKeyRaw: Buffer;
}

export type AnyKeyPair = KeyPairES256 | KeyPairRS256 | KeyPairEdDSA;

export function generateRS256KeyPair(): KeyPairRS256 {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  const publicKeySpki = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
  const n = Buffer.from(jwk.n!, 'base64url');
  const e = Buffer.from(jwk.e!, 'base64url');
  return { alg: 'RS256', privateKey, publicKey, publicKeySpki: Buffer.from(publicKeySpki), n, e };
}

export function generateEdDSAKeyPair(): KeyPairEdDSA {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pubDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  // Last 32 bytes are the raw Ed25519 public key
  const raw = pubDer.subarray(pubDer.length - 32);
  return { alg: 'EdDSA', privateKey, publicKey, publicKeyRaw: Buffer.from(raw) };
}

export function signRS256(privateKey: KeyObject, data: Buffer): Buffer {
  const sign = createSign('RSA-SHA256');
  sign.update(data);
  return sign.sign(privateKey);
}

export function signEdDSA(privateKey: KeyObject, data: Buffer): Buffer {
  // Ed25519 signs the raw message (no hash).
  return cryptoSign(null, data, privateKey);
}

/**
 * Generate an ES256 (ECDSA P-256) key pair.
 */
export function generateES256KeyPair(): KeyPairES256 {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });

  // Export public key in uncompressed format to extract x,y coordinates.
  const pubDer = publicKey.export({ type: 'spki', format: 'der' });
  // For P-256 SPKI, the last 65 bytes are the uncompressed point (0x04 || x || y).
  const uncompressed = pubDer.subarray(pubDer.length - 65);
  const x = uncompressed.subarray(1, 33);
  const y = uncompressed.subarray(33, 65);

  return {
    alg: 'ES256',
    privateKey,
    publicKey,
    publicKeyRaw: Buffer.from(uncompressed),
    x: Buffer.from(x),
    y: Buffer.from(y),
  };
}

/**
 * Sign data with ES256 (SHA-256 + ECDSA).
 * Returns the signature in the format expected by WebAuthn for COSE alg -7:
 * ASN.1 DER-encoded ECDSA signature (SEQUENCE of r, s) — what a real
 * authenticator emits and what a compliant RP verifies, NOT raw r||s.
 */
export function signES256(privateKey: KeyObject, data: Buffer): Buffer {
  const sign = createSign('SHA256');
  sign.update(data);
  // Node returns the DER encoding by default, which is exactly what WebAuthn wants.
  return sign.sign(privateKey);
}

/**
 * Sign a WebAuthn assertion: sign authenticatorData || SHA-256(clientDataJSON).
 * This is the standard signing procedure for navigator.credentials.get().
 */
export function signAssertion(
  keyPair: KeyPairES256,
  authenticatorData: Buffer,
  clientDataJSON: Buffer,
): Buffer {
  const signedData = Buffer.concat([authenticatorData, sha256(clientDataJSON)]);
  return signES256(keyPair.privateKey, signedData);
}

/**
 * Sign for attestation (registration): same procedure as an assertion.
 */
export function signAttestation(
  keyPair: KeyPairES256,
  authenticatorData: Buffer,
  clientDataJSON: Buffer,
): Buffer {
  return signAssertion(keyPair, authenticatorData, clientDataJSON);
}
