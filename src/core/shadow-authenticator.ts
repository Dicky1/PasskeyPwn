/**
 * shadow-authenticator.ts
 * 
 * Phase 2 authenticator: Full JavaScript override of navigator.credentials.create/get.
 * 
 * Unlike BaselineAuthenticator (which delegates to Chrome's CDP virtual authenticator),
 * ShadowAuthenticator injects a script via Page.addInitScript that
 * completely replaces the WebAuthn API with our own implementation.
 * 
 * This allows TOTAL control over:
 * - authenticatorData bytes (rpIdHash, flags, signCount, attestedCredData)
 * - clientDataJSON contents (origin, type, challenge)
 * - attestationObject format and contents
 * - signature generation
 * 
 * Used by ALL mutate-*.ts and exploit-*.ts modules.
 */

import { Page } from 'playwright';
import {
  buildAuthenticatorData,
  buildClientDataJSON,
  buildAttestationObject,
  buildCoseES256PublicKey,
  buildCoseRS256PublicKey,
  buildCoseEdDSAPublicKey,
  FLAGS,
  sha256,
} from './cbor-builder.js';
import {
  generateES256KeyPair,
  generateRS256KeyPair,
  generateEdDSAKeyPair,
  signAssertion,
  signAttestation,
  signRS256,
  signEdDSA,
  KeyPairES256,
  KeyPairRS256,
  KeyPairEdDSA,
  AnyKeyPair,
} from './signer.js';
import { randomBytes } from 'node:crypto';

/**
 * Normalize a challenge string to base64url (no padding), accepting either
 * standard base64 (what the browser bridge produces via btoa) or base64url
 * (what mutation overrides supply). WebAuthn clientDataJSON.challenge MUST be
 * base64url, so without this a strict relying party rejects every ceremony.
 */
function toChallengeB64Url(input: string): string {
  const std = input.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(std, 'base64').toString('base64url');
}

export interface ShadowCredential {
  credentialId: Buffer;
  rpId: string;
  keyPair: AnyKeyPair;
  alg: 'ES256' | 'RS256' | 'EdDSA';
  signCount: number;
  userHandle?: Buffer;
}

export interface ShadowCreateOverrides {
  rpId?: string;
  rpIdHash?: Buffer;
  origin?: string;
  flags?: number;
  signCount?: number;
  aaguid?: Buffer;
  credentialId?: Buffer;
  challenge?: string;
  attestationFmt?: 'none' | 'packed';
  selfAttestation?: boolean;
  /** Algorithm to use for the credential (default ES256). */
  alg?: 'ES256' | 'RS256' | 'EdDSA';
}

export interface ShadowGetOverrides {
  /** Override rpId (for rpIdHash computation) */
  rpId?: string;
  /** Override rpIdHash directly */
  rpIdHash?: Buffer;
  /** Override origin in clientDataJSON */
  origin?: string;
  /** Override flags byte */
  flags?: number;
  /** Override signCount */
  signCount?: number;
  /** Override challenge in clientDataJSON */
  challenge?: string;
  /** Which credential to use (by index in stored creds). Default: 0 */
  credentialIndex?: number;
  /** Override userHandle */
  userHandle?: Buffer;
}

/**
 * ShadowAuthenticator: completely overrides navigator.credentials in the browser.
 * 
 * All cryptographic operations happen in Node.js (not in the browser).
 * The browser script calls back to Node via page.exposeFunction() to get
 * the pre-built response buffers.
 */
export class ShadowAuthenticator {
  /** Real page origin (e.g. https://localhost:8099). Used as default clientDataJSON.origin. */
  pageOrigin: string | null = null;
  private credentials: ShadowCredential[] = [];
  private createOverrides: ShadowCreateOverrides = {};
  private getOverrides: ShadowGetOverrides = {};
  private installed = false;

  /**
   * Store a credential (generated during registration or loaded from baseline).
   */
  addCredential(cred: ShadowCredential): void {
    this.credentials.push(cred);
  }

  /**
   * Generate a new credential with a fresh ES256 key pair.
   */
  generateCredential(rpId: string, userHandle?: Buffer, alg: 'ES256' | 'RS256' | 'EdDSA' = 'ES256'): ShadowCredential {
    let keyPair: AnyKeyPair;
    if (alg === 'RS256') keyPair = generateRS256KeyPair();
    else if (alg === 'EdDSA') keyPair = generateEdDSAKeyPair();
    else keyPair = generateES256KeyPair();
    const credentialId = randomBytes(32);

    const cred: ShadowCredential = {
      credentialId,
      rpId,
      keyPair,
      alg,
      signCount: 1000,
      userHandle,
    };

    this.credentials.push(cred);
    return cred;
  }

  /**
   * Set overrides for the next navigator.credentials.create() call.
   */
  setCreateOverrides(overrides: ShadowCreateOverrides): void {
    this.createOverrides = overrides;
  }

  /**
   * Set overrides for the next navigator.credentials.get() call.
   */
  setGetOverrides(overrides: ShadowGetOverrides): void {
    this.getOverrides = overrides;
  }

  /**
   * Clear all overrides.
   */
  clearOverrides(): void {
    this.createOverrides = {};
    this.getOverrides = {};
  }

  /**
   * Install the shadow authenticator on a page.
   * This exposes callback functions and injects the override script.
   */
  async install(page: Page): Promise<void> {
    try { this.pageOrigin = new URL(page.url()).origin; } catch { /* keep default */ }
    // Expose Node.js callbacks to the browser
    await page.exposeFunction('__ppwn_shadowCreate', async (optionsJson: string) => {
      return this.handleCreate(optionsJson);
    });

    await page.exposeFunction('__ppwn_shadowGet', async (optionsJson: string) => {
      return this.handleGet(optionsJson);
    });

    // Inject the override script
    await page.addInitScript(`
      (function() {
        // Helper: ArrayBuffer to base64
        function ab2b64(buffer) {
          return btoa(String.fromCharCode(...new Uint8Array(buffer)));
        }
        // Helper: base64 to ArrayBuffer
        function b642ab(base64) {
          const binary = atob(base64);
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
          return bytes.buffer;
        }

        // Override navigator.credentials.create
        const origCreate = navigator.credentials.create.bind(navigator.credentials);
        navigator.credentials.create = async function(options) {
          if (!options || !options.publicKey) return origCreate(options);

          const pk = options.publicKey;
          const serialized = JSON.stringify({
            rp: pk.rp,
            challenge: pk.challenge ? ab2b64(pk.challenge) : null,
            user: pk.user ? {
              id: pk.user.id ? ab2b64(pk.user.id) : null,
              name: pk.user.name,
              displayName: pk.user.displayName,
            } : null,
            pubKeyCredParams: pk.pubKeyCredParams,
            attestation: pk.attestation,
            authenticatorSelection: pk.authenticatorSelection,
          });

          const resultJson = await window.__ppwn_shadowCreate(serialized);
          const result = JSON.parse(resultJson);

          // Construct a PublicKeyCredential-like response
          const response = {
            id: result.id,
            rawId: b642ab(result.rawId),
            type: 'public-key',
            response: {
              clientDataJSON: b642ab(result.clientDataJSON),
              attestationObject: b642ab(result.attestationObject),
              getTransports: () => ['internal'],
              getPublicKey: () => b642ab(result.publicKey),
              getPublicKeyAlgorithm: () => result.publicKeyAlgorithm,
              getAuthenticatorData: () => b642ab(result.authenticatorData),
            },
            authenticatorAttachment: 'platform',
            getClientExtensionResults: () => ({}),
          };

          return response;
        };

        // Override navigator.credentials.get
        const origGet = navigator.credentials.get.bind(navigator.credentials);
        navigator.credentials.get = async function(options) {
          if (!options || !options.publicKey) return origGet(options);

          const pk = options.publicKey;
          const serialized = JSON.stringify({
            challenge: pk.challenge ? ab2b64(pk.challenge) : null,
            rpId: pk.rpId,
            allowCredentials: pk.allowCredentials?.map(c => ({
              type: c.type,
              id: c.id ? ab2b64(c.id) : null,
            })),
            userVerification: pk.userVerification,
          });

          const resultJson = await window.__ppwn_shadowGet(serialized);
          const result = JSON.parse(resultJson);

          const response = {
            id: result.id,
            rawId: b642ab(result.rawId),
            type: 'public-key',
            response: {
              clientDataJSON: b642ab(result.clientDataJSON),
              authenticatorData: b642ab(result.authenticatorData),
              signature: b642ab(result.signature),
              userHandle: result.userHandle ? b642ab(result.userHandle) : null,
            },
            authenticatorAttachment: 'platform',
            getClientExtensionResults: () => ({}),
          };

          return response;
        };

        console.log('[PasskeyPwn] Shadow authenticator installed');
      })();
    `);

    this.installed = true;
  }

  /**
   * Handle a navigator.credentials.create() call from the browser.
   * Returns a JSON string with the response fields.
   */
  private async handleCreate(optionsJson: string): Promise<string> {
    const options = JSON.parse(optionsJson);
    const ov = this.createOverrides;

    // Determine rpId
    const rpId = ov.rpId ?? options.rp?.id ?? new URL(`https://${options.rp?.name ?? 'localhost'}`).hostname;
    const origin = ov.origin ?? this.pageOrigin ?? `https://${rpId}`;
    const challenge = toChallengeB64Url(ov.challenge ?? options.challenge);

    const alg = ov.alg ?? 'ES256';
    let cred: ShadowCredential;
    if (this.credentials.length > 0 && !ov.credentialId && !ov.alg) {
      cred = this.credentials[this.credentials.length - 1]!;
    } else {
      cred = this.generateCredential(rpId, undefined, alg);
    }

    const credentialId = ov.credentialId ?? cred.credentialId;
    const signCount = ov.signCount ?? cred.signCount;
    const flags = ov.flags ?? (FLAGS.UP | FLAGS.UV | FLAGS.AT);
    const aaguid = ov.aaguid ?? Buffer.alloc(16);

    // Build COSE public key based on alg
    let cosePublicKey: Buffer;
    let publicKeyAlgorithm: number;
    if (cred.alg === 'RS256') {
      const r = cred.keyPair as KeyPairRS256;
      cosePublicKey = buildCoseRS256PublicKey(r.n, r.e);
      publicKeyAlgorithm = -257;
    } else if (cred.alg === 'EdDSA') {
      const e = cred.keyPair as KeyPairEdDSA;
      cosePublicKey = buildCoseEdDSAPublicKey(e.publicKeyRaw);
      publicKeyAlgorithm = -8;
    } else {
      const es = cred.keyPair as KeyPairES256;
      cosePublicKey = buildCoseES256PublicKey(es.x, es.y);
      publicKeyAlgorithm = -7;
    }

    // Build authenticatorData
    const authData = buildAuthenticatorData({
      rpId,
      rpIdHash: ov.rpIdHash,
      flags,
      signCount,
      attestedCredentialData: {
        aaguid,
        credentialId,
        cosePublicKey,
      },
    });

    // Build clientDataJSON
    const clientDataJSON = buildClientDataJSON({
      type: 'webauthn.create',
      challenge,
      origin,
    });

    // Build attestation object
    const fmt = ov.attestationFmt ?? 'none';
    let attStmt: Record<string, unknown> = {};

    if (fmt === 'packed' && ov.selfAttestation) {
      let sig: Buffer;
      if (cred.alg === 'RS256') sig = signRS256((cred.keyPair as KeyPairRS256).privateKey, Buffer.concat([authData, sha256(clientDataJSON)]));
      else if (cred.alg === 'EdDSA') sig = signEdDSA((cred.keyPair as KeyPairEdDSA).privateKey, Buffer.concat([authData, sha256(clientDataJSON)]));
      else sig = signAttestation(cred.keyPair as KeyPairES256, authData, clientDataJSON);
      attStmt = { alg: publicKeyAlgorithm, sig };
    }

    const attestationObject = buildAttestationObject({
      fmt,
      authData,
      attStmt,
    });

    // Update signCount
    cred.signCount = signCount + 1;

    const credIdB64 = credentialId.toString('base64');
    const credIdB64Url = credentialId.toString('base64url');

    return JSON.stringify({
      id: credIdB64Url,
      rawId: credIdB64,
      clientDataJSON: clientDataJSON.toString('base64'),
      attestationObject: attestationObject.toString('base64'),
      publicKey: cosePublicKey.toString('base64'),
      publicKeyAlgorithm,
      authenticatorData: authData.toString('base64'),
    });
  }

  /**
   * Handle a navigator.credentials.get() call from the browser.
   */
  private async handleGet(optionsJson: string): Promise<string> {
    const options = JSON.parse(optionsJson);
    const ov = this.getOverrides;

    if (this.credentials.length === 0) {
      throw new Error('ShadowAuthenticator: No credentials available for assertion');
    }

    const credIndex = ov.credentialIndex ?? 0;
    const cred = this.credentials[credIndex]!;

    const rpId = ov.rpId ?? options.rpId ?? cred.rpId;
    const origin = ov.origin ?? this.pageOrigin ?? `https://${rpId}`;
    const challenge = toChallengeB64Url(ov.challenge ?? options.challenge);
    const signCount = ov.signCount ?? cred.signCount;
    const flags = ov.flags ?? (FLAGS.UP | FLAGS.UV);

    // Build authenticatorData (no attestedCredData for assertions)
    const authData = buildAuthenticatorData({
      rpId,
      rpIdHash: ov.rpIdHash,
      flags,
      signCount,
    });

    // Build clientDataJSON
    const clientDataJSON = buildClientDataJSON({
      type: 'webauthn.get',
      challenge,
      origin,
    });

    // Sign the assertion based on alg
    let signature: Buffer;
    if (cred.alg === 'RS256') {
      const r = cred.keyPair as KeyPairRS256;
      signature = signRS256(r.privateKey, Buffer.concat([authData, sha256(clientDataJSON)]));
    } else if (cred.alg === 'EdDSA') {
      const e = cred.keyPair as KeyPairEdDSA;
      signature = signEdDSA(e.privateKey, Buffer.concat([authData, sha256(clientDataJSON)]));
    } else {
      signature = signAssertion(cred.keyPair as KeyPairES256, authData, clientDataJSON);
    }

    // Update signCount
    cred.signCount = signCount + 1;

    const userHandle = ov.userHandle ?? cred.userHandle;

    return JSON.stringify({
      id: cred.credentialId.toString('base64url'),
      rawId: cred.credentialId.toString('base64'),
      clientDataJSON: clientDataJSON.toString('base64'),
      authenticatorData: authData.toString('base64'),
      signature: signature.toString('base64'),
      userHandle: userHandle ? userHandle.toString('base64') : null,
    });
  }

  /**
   * Get all stored credentials.
   */
  getCredentials(): ShadowCredential[] {
    return [...this.credentials];
  }

  /**
   * Check if installed on a page.
   */
  isInstalled(): boolean {
    return this.installed;
  }
}
