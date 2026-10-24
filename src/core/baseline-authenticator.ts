/**
 * baseline-authenticator.ts
 * 
 * Phase 1 authenticator: Uses Chrome DevTools Protocol's native WebAuthn domain.
 * This leverages CDP's `WebAuthn.enable`, `WebAuthn.addVirtualAuthenticator`, etc.
 * 
 * LIMITATION: The CDP native virtual authenticator auto-increments signCount and
 * does not allow arbitrary byte-level manipulation of authenticatorData.
 * Therefore this authenticator is ONLY suitable for the recon phase — recording
 * what a normal, well-behaved passkey flow looks like.
 * 
 * For mutation/exploit testing, use ShadowAuthenticator instead.
 */

import { CDPSession } from 'playwright';

export interface VirtualAuthenticatorOptions {
  protocol?: 'ctap2' | 'u2f';
  transport?: 'usb' | 'nfc' | 'ble' | 'internal';
  hasResidentKey?: boolean;
  hasUserVerification?: boolean;
  isUserVerified?: boolean;
  automaticPresenceSimulation?: boolean;
}

export interface RegisteredCredential {
  credentialId: string;      // base64-encoded
  rpId: string;
  privateKey: string;        // base64-encoded PKCS#8
  signCount: number;
  isResidentCredential: boolean;
  userHandle?: string;       // base64-encoded
}

export class BaselineAuthenticator {
  private cdp: CDPSession;
  private authenticatorId: string | null = null;

  constructor(cdp: CDPSession) {
    this.cdp = cdp;
  }

  /**
   * Enable the WebAuthn domain and add a virtual authenticator.
   * This intercepts all WebAuthn API calls in the browser and routes them
   * through Chrome's built-in virtual authenticator.
   */
  async enable(opts: VirtualAuthenticatorOptions = {}): Promise<string> {
    // Enable WebAuthn domain — this is required before any other WebAuthn CDP commands
    await this.cdp.send('WebAuthn.enable' as any, {
      enableUI: false,
    });

    // Add a virtual authenticator with the specified options
    const result = await this.cdp.send('WebAuthn.addVirtualAuthenticator' as any, {
      options: {
        protocol: opts.protocol ?? 'ctap2',
        transport: opts.transport ?? 'internal',
        hasResidentKey: opts.hasResidentKey ?? true,
        hasUserVerification: opts.hasUserVerification ?? true,
        isUserVerified: opts.isUserVerified ?? true,
        automaticPresenceSimulation: opts.automaticPresenceSimulation ?? true,
      },
    });

    this.authenticatorId = (result as any).authenticatorId;
    return this.authenticatorId!;
  }

  /**
   * Retrieve all credentials stored in the virtual authenticator.
   * Useful for inspecting what credentials were registered during recon.
   */
  async getCredentials(): Promise<RegisteredCredential[]> {
    this.ensureEnabled();

    const result = await this.cdp.send('WebAuthn.getCredentials' as any, {
      authenticatorId: this.authenticatorId,
    });

    return ((result as any).credentials ?? []).map((cred: any) => ({
      credentialId: cred.credentialId,
      rpId: cred.rpId,
      privateKey: cred.privateKey,
      signCount: cred.signCount,
      isResidentCredential: cred.isResidentCredential,
      userHandle: cred.userHandle,
    }));
  }

  /**
   * Add a credential directly (useful for pre-seeding the authenticator).
   */
  async addCredential(credential: {
    credentialId: string;
    rpId: string;
    privateKey: string;
    signCount: number;
    isResidentCredential: boolean;
    userHandle?: string;
  }): Promise<void> {
    this.ensureEnabled();

    await this.cdp.send('WebAuthn.addCredential' as any, {
      authenticatorId: this.authenticatorId,
      credential: {
        credentialId: credential.credentialId,
        isResidentCredential: credential.isResidentCredential,
        rpId: credential.rpId,
        privateKey: credential.privateKey,
        signCount: credential.signCount,
        userHandle: credential.userHandle,
      },
    });
  }

  /**
   * Remove a credential by its ID.
   */
  async removeCredential(credentialId: string): Promise<void> {
    this.ensureEnabled();

    await this.cdp.send('WebAuthn.removeCredential' as any, {
      authenticatorId: this.authenticatorId,
      credentialId,
    });
  }

  /**
   * Clear all credentials from the virtual authenticator.
   */
  async clearCredentials(): Promise<void> {
    this.ensureEnabled();

    await this.cdp.send('WebAuthn.clearCredentials' as any, {
      authenticatorId: this.authenticatorId,
    });
  }

  /**
   * Set whether user verification succeeds or fails.
   * Useful for testing UV policy enforcement.
   */
  async setUserVerified(isVerified: boolean): Promise<void> {
    this.ensureEnabled();

    await this.cdp.send('WebAuthn.setUserVerified' as any, {
      authenticatorId: this.authenticatorId,
      isUserVerified: isVerified,
    });
  }

  /**
   * Disable the WebAuthn domain and remove the virtual authenticator.
   */
  async disable(): Promise<void> {
    if (this.authenticatorId) {
      try {
        await this.cdp.send('WebAuthn.removeVirtualAuthenticator' as any, {
          authenticatorId: this.authenticatorId,
        });
      } catch {
        // Authenticator may already be removed
      }
      this.authenticatorId = null;
    }

    try {
      await this.cdp.send('WebAuthn.disable' as any);
    } catch {
      // Domain may already be disabled
    }
  }

  /**
   * Get the authenticator ID (for direct CDP commands if needed).
   */
  getAuthenticatorId(): string | null {
    return this.authenticatorId;
  }

  private ensureEnabled(): void {
    if (!this.authenticatorId) {
      throw new Error(
        'BaselineAuthenticator not enabled. Call enable() first.',
      );
    }
  }
}
