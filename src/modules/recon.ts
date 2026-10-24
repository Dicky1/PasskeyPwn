/**
 * recon.ts — Phase 1: Reconnaissance Module
 * 
 * Records the baseline WebAuthn configuration of a target site.
 * Uses the BaselineAuthenticator (CDP native virtual authenticator) to perform
 * a real registration + authentication cycle, capturing:
 * 
 * - rp.id, rp.name
 * - pubKeyCredParams (supported algorithms)
 * - authenticatorSelection (residentKey, userVerification, etc.)
 * - attestation preference
 * - challenge format & entropy
 * - timeout values
 * - credential details post-registration
 * - authentication options
 * - response status codes and bodies
 * 
 * Output: baseline.json in the working directory.
 */

import { Page } from 'playwright';
import { createCDPSession, closeCDPSession, captureScreenshot, gotoSettled, CDPSessionOptions, CDPConnection } from '../core/cdp-session.js';
import { BaselineAuthenticator } from '../core/baseline-authenticator.js';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

export interface ReconOptions {
  /** URL of the registration page */
  urlRegister: string;
  /** URL of the login/authentication page */
  urlLogin: string;
  /** Username to use for registration */
  username?: string;
  /** Output file path for baseline.json */
  outFile?: string;
  /** CDP session options (headless, proxy, etc.) */
  sessionOptions?: CDPSessionOptions;
  /** Whether to keep the browser open after recon (for debugging) */
  keepOpen?: boolean;
  /** If set, capture full-page screenshots of each step into this directory. */
  screenshotDir?: string;
}

export interface BaselineReport {
  meta: {
    tool: string;
    version: string;
    timestamp: string;
    targetUrlRegister: string;
    targetUrlLogin: string;
    username: string;
  };
  registration: {
    publicKeyOptions: PublicKeyCredentialCreationOptionsJSON | null;
    response: {
      statusCode: number | null;
      body: string | null;
      classification: 'ACCEPTED' | 'REJECTED' | 'ERROR' | null;
    };
    credential: {
      credentialId: string | null;
      publicKeyAlgorithm: number | null;
      transports: string[];
    };
  };
  authentication: {
    publicKeyOptions: PublicKeyCredentialRequestOptionsJSON | null;
    response: {
      statusCode: number | null;
      body: string | null;
      classification: 'ACCEPTED' | 'REJECTED' | 'ERROR' | null;
    };
  };
  analysis: {
    rpId: string | null;
    rpName: string | null;
    supportedAlgorithms: number[];
    attestationPreference: string | null;
    userVerificationRequirement: string | null;
    residentKeyRequirement: string | null;
    challengeEntropyBits: number | null;
    timeoutMs: number | null;
    observations: string[];
  };
}

// JSON-safe versions of PublicKeyCredential*Options
interface PublicKeyCredentialCreationOptionsJSON {
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: Array<{ type: string; alg: number }>;
  timeout?: number;
  excludeCredentials?: Array<{ type: string; id: string; transports?: string[] }>;
  authenticatorSelection?: {
    authenticatorAttachment?: string;
    residentKey?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  };
  attestation?: string;
  extensions?: Record<string, unknown>;
}

interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: Array<{ type: string; id: string; transports?: string[] }>;
  userVerification?: string;
  extensions?: Record<string, unknown>;
}

/**
 * Run the recon phase: register a passkey and authenticate with it,
 * recording all WebAuthn options and server responses.
 */
export async function runRecon(opts: ReconOptions): Promise<BaselineReport> {
  const username = opts.username ?? `ppwn_recon_${Date.now()}`;
  const outFile = opts.outFile ?? resolve(process.cwd(), 'baseline.json');

  console.log(`[recon] 🔍 Starting reconnaissance`);
  console.log(`[recon]    Registration URL: ${opts.urlRegister}`);
  console.log(`[recon]    Login URL:        ${opts.urlLogin}`);
  console.log(`[recon]    Username:         ${username}`);

  const report: BaselineReport = {
    meta: {
      tool: 'PasskeyPwn',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      targetUrlRegister: opts.urlRegister,
      targetUrlLogin: opts.urlLogin,
      username,
    },
    registration: {
      publicKeyOptions: null,
      response: { statusCode: null, body: null, classification: null },
      credential: { credentialId: null, publicKeyAlgorithm: null, transports: [] },
    },
    authentication: {
      publicKeyOptions: null,
      response: { statusCode: null, body: null, classification: null },
    },
    analysis: {
      rpId: null,
      rpName: null,
      supportedAlgorithms: [],
      attestationPreference: null,
      userVerificationRequirement: null,
      residentKeyRequirement: null,
      challengeEntropyBits: null,
      timeoutMs: null,
      observations: [],
    },
  };

  let conn: CDPConnection | null = null;

  try {
    // Launch browser + CDP
    conn = await createCDPSession(opts.sessionOptions);
    const { page, cdp } = conn;

    let shotIndex = 0;
    const shot = async (name: string) => {
      if (!opts.screenshotDir) return;
      const p = await captureScreenshot(page, opts.screenshotDir, `${String(++shotIndex).padStart(2, '0')}-${name}`);
      console.log(`[recon] 📸 ${p}`);
    };

    // Set up baseline authenticator
    const auth = new BaselineAuthenticator(cdp);
    await auth.enable({
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    });

    console.log(`[recon] ✅ Virtual authenticator enabled`);

    // ─── PHASE 1a: REGISTRATION ───
    console.log(`[recon] 📝 Phase 1a: Registration`);

    // Intercept WebAuthn API calls to capture the options
    const registrationCapture = await interceptRegistration(page);

    // Navigate to registration page
    await gotoSettled(page, opts.urlRegister);
    await shot('registration-page');

    // Try to fill in username and trigger registration
    // This is site-specific — for webauthn.io:
    await performRegistration(page, username);
    await shot('after-registration');

    // Wait for the intercepted data
    const regData = await registrationCapture;

    if (regData.options) {
      report.registration.publicKeyOptions = regData.options;

      // Extract analysis data
      report.analysis.rpId = regData.options.rp?.id ?? null;
      report.analysis.rpName = regData.options.rp?.name ?? null;
      report.analysis.supportedAlgorithms = regData.options.pubKeyCredParams?.map(p => p.alg) ?? [];
      report.analysis.attestationPreference = regData.options.attestation ?? null;
      report.analysis.userVerificationRequirement =
        regData.options.authenticatorSelection?.userVerification ?? null;
      report.analysis.residentKeyRequirement =
        regData.options.authenticatorSelection?.residentKey ?? null;
      report.analysis.timeoutMs = regData.options.timeout ?? null;

      // Estimate challenge entropy
      if (regData.options.challenge) {
        const challengeBytes = Buffer.from(regData.options.challenge, 'base64url');
        report.analysis.challengeEntropyBits = challengeBytes.length * 8;
      }
    }

    if (regData.response) {
      report.registration.response = regData.response;
    }

    // Get credential details from the authenticator
    const creds = await auth.getCredentials();
    if (creds.length > 0) {
      const cred = creds[0]!;
      report.registration.credential.credentialId = cred.credentialId;
    }

    console.log(`[recon] ✅ Registration captured`);

    // ─── PHASE 1b: AUTHENTICATION ───
    console.log(`[recon] 🔑 Phase 1b: Authentication`);

    const authCapture = await interceptAuthentication(page);

    // Navigate to login page
    await gotoSettled(page, opts.urlLogin);
    await shot('login-page');

    // Try to perform authentication
    await performAuthentication(page, username);
    await shot('after-authentication');

    const authData = await authCapture;

    if (authData.options) {
      report.authentication.publicKeyOptions = authData.options;
    }

    if (authData.response) {
      report.authentication.response = authData.response;
    }

    console.log(`[recon] ✅ Authentication captured`);

    // ─── ANALYSIS ───
    console.log(`[recon] 🧪 Analyzing baseline...`);
    report.analysis.observations = analyzeBaseline(report);

    // Cleanup
    await auth.disable();

    if (!opts.keepOpen) {
      await closeCDPSession(conn);
      conn = null;
    }
  } catch (err) {
    console.error(`[recon] ❌ Error during recon:`, err);
    report.analysis.observations.push(`Error during recon: ${err}`);
    if (conn && !opts.keepOpen) {
      await closeCDPSession(conn);
    }
    // Re-throw so CLI can handle it
    throw err;
  }

  // Write report
  writeFileSync(outFile, JSON.stringify(report, null, 2), 'utf-8');
  console.log(`[recon] 📄 Baseline report saved to: ${outFile}`);

  return report;
}

/**
 * Inject script to intercept navigator.credentials.create() options.
 * We DON'T override the call — we just observe the options before CDP handles it.
 */
async function interceptRegistration(page: Page): Promise<{
  options: PublicKeyCredentialCreationOptionsJSON | null;
  response: { statusCode: number | null; body: string | null; classification: 'ACCEPTED' | 'REJECTED' | 'ERROR' | null };
}> {
  let resolvePromise: (val: any) => void;
  const promise = new Promise<any>((resolve) => {
    resolvePromise = resolve;
  });

  // We'll capture data via network interception + page evaluation
  let capturedOptions: PublicKeyCredentialCreationOptionsJSON | null = null;
  let capturedResponse = { statusCode: null as number | null, body: null as string | null, classification: null as 'ACCEPTED' | 'REJECTED' | 'ERROR' | null };

  // Inject monitoring script BEFORE page navigation
  await page.addInitScript(`
    (function() {
      const origCreate = navigator.credentials.create.bind(navigator.credentials);
      navigator.credentials.create = async function(options) {
        // Store the publicKey options for capture
        if (options && options.publicKey) {
          const pk = options.publicKey;
          const serialized = {
            rp: pk.rp,
            user: pk.user ? {
              id: pk.user.id ? btoa(String.fromCharCode(...new Uint8Array(pk.user.id))) : null,
              name: pk.user.name,
              displayName: pk.user.displayName,
            } : undefined,
            challenge: pk.challenge ? btoa(String.fromCharCode(...new Uint8Array(pk.challenge))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '') : null,
            pubKeyCredParams: pk.pubKeyCredParams,
            timeout: pk.timeout,
            excludeCredentials: pk.excludeCredentials?.map(c => ({
              type: c.type,
              id: c.id ? btoa(String.fromCharCode(...new Uint8Array(c.id))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '') : null,
              transports: c.transports,
            })),
            authenticatorSelection: pk.authenticatorSelection,
            attestation: pk.attestation,
            extensions: pk.extensions,
          };
          window.__ppwn_regOptions = serialized;
        }
        // Let the original (CDP virtual authenticator) handle it
        return origCreate(options);
      };
    })();
  `);

  // Monitor network for registration API response
  const responseHandler = async (response: any) => {
    const url = response.url();
    const req = response.request();
    const method = req.method();

    // Look for POST requests that might be the registration completion
    if (method === 'POST' && (
      url.includes('register') ||
      url.includes('registration') ||
      url.includes('attestation') ||
      url.includes('credential') ||
      url.includes('webauthn')
    )) {
      try {
        capturedResponse.statusCode = response.status();
        capturedResponse.body = await response.text().catch(() => null);

        if (capturedResponse.statusCode! >= 200 && capturedResponse.statusCode! < 300) {
          capturedResponse.classification = 'ACCEPTED';
        } else if (capturedResponse.statusCode! >= 400) {
          capturedResponse.classification = 'REJECTED';
        } else {
          capturedResponse.classification = 'ERROR';
        }
      } catch {
        // Response might not be readable
      }
    }
  };

  page.on('response', responseHandler);

  // Set a timeout-based resolution — give the page time to complete
  const checkInterval = setInterval(async () => {
    try {
      const opts = await page.evaluate(() => (globalThis as any).__ppwn_regOptions ?? null);
      if (opts) {
        capturedOptions = opts;
        clearInterval(checkInterval);
        page.off('response', responseHandler);

        // Small delay to let the API response come in
        await new Promise(r => setTimeout(r, 2000));
        resolvePromise!({ options: capturedOptions, response: capturedResponse });
      }
    } catch {
      // Page might not be ready yet
    }
  }, 500);

  // Safety timeout
  setTimeout(() => {
    clearInterval(checkInterval);
    page.off('response', responseHandler);
    resolvePromise!({ options: capturedOptions, response: capturedResponse });
  }, 30000);

  return promise;
}

/**
 * Inject script to intercept navigator.credentials.get() options.
 */
async function interceptAuthentication(page: Page): Promise<{
  options: PublicKeyCredentialRequestOptionsJSON | null;
  response: { statusCode: number | null; body: string | null; classification: 'ACCEPTED' | 'REJECTED' | 'ERROR' | null };
}> {
  let resolvePromise: (val: any) => void;
  const promise = new Promise<any>((resolve) => {
    resolvePromise = resolve;
  });

  let capturedOptions: PublicKeyCredentialRequestOptionsJSON | null = null;
  let capturedResponse = { statusCode: null as number | null, body: null as string | null, classification: null as 'ACCEPTED' | 'REJECTED' | 'ERROR' | null };

  await page.addInitScript(`
    (function() {
      const origGet = navigator.credentials.get.bind(navigator.credentials);
      navigator.credentials.get = async function(options) {
        if (options && options.publicKey) {
          const pk = options.publicKey;
          const serialized = {
            challenge: pk.challenge ? btoa(String.fromCharCode(...new Uint8Array(pk.challenge))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '') : null,
            timeout: pk.timeout,
            rpId: pk.rpId,
            allowCredentials: pk.allowCredentials?.map(c => ({
              type: c.type,
              id: c.id ? btoa(String.fromCharCode(...new Uint8Array(c.id))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '') : null,
              transports: c.transports,
            })),
            userVerification: pk.userVerification,
            extensions: pk.extensions,
          };
          window.__ppwn_authOptions = serialized;
        }
        return origGet(options);
      };
    })();
  `);

  const responseHandler = async (response: any) => {
    const url = response.url();
    const req = response.request();
    const method = req.method();

    if (method === 'POST' && (
      url.includes('login') ||
      url.includes('assertion') ||
      url.includes('authentication') ||
      url.includes('authenticate') ||
      url.includes('verification') ||
      url.includes('webauthn')
    )) {
      try {
        capturedResponse.statusCode = response.status();
        capturedResponse.body = await response.text().catch(() => null);

        if (capturedResponse.statusCode! >= 200 && capturedResponse.statusCode! < 300) {
          capturedResponse.classification = 'ACCEPTED';
        } else if (capturedResponse.statusCode! >= 400) {
          capturedResponse.classification = 'REJECTED';
        } else {
          capturedResponse.classification = 'ERROR';
        }
      } catch {
        // Response might not be readable
      }
    }
  };

  page.on('response', responseHandler);

  const checkInterval = setInterval(async () => {
    try {
      const opts = await page.evaluate(() => (globalThis as any).__ppwn_authOptions ?? null);
      if (opts) {
        capturedOptions = opts;
        clearInterval(checkInterval);
        page.off('response', responseHandler);
        await new Promise(r => setTimeout(r, 2000));
        resolvePromise!({ options: capturedOptions, response: capturedResponse });
      }
    } catch {
      // Page might not be ready yet
    }
  }, 500);

  setTimeout(() => {
    clearInterval(checkInterval);
    page.off('response', responseHandler);
    resolvePromise!({ options: capturedOptions, response: capturedResponse });
  }, 30000);

  return promise;
}

/**
 * Perform registration on the target site.
 * Supports webauthn.io selectors with fallback to generic selectors.
 */
async function performRegistration(page: Page, username: string): Promise<void> {
  try {
    await page.waitForLoadState('domcontentloaded').catch(() => {});

    // webauthn.io uses #username or input[name="username"]
    // Also try generic selectors for other sites
    const usernameSelectors = [
      '#username',
      'input[name="username"]',
      'input[x-model="username"]',       // Alpine.js binding on webauthn.io
      'input#input-email',
      'input[placeholder*="username" i]',
      'input[placeholder*="email" i]',
      'input[type="text"]:first-of-type',
    ];

    for (const sel of usernameSelectors) {
      const el = page.locator(sel);
      if (await el.count() > 0 && await el.first().isVisible()) {
        await el.first().fill(username);
        console.log(`[recon]    Filled username via selector: ${sel}`);
        break;
      }
    }

    // webauthn.io: button#register-button or button with text "Register"
    const registerSelectors = [
      '#register-button',
      'button:has-text("Register")',
      'button:has-text("Sign Up")',
      'button:has-text("Create Passkey")',
      'button:has-text("Create")',
      '[data-action="register"]',
    ];

    for (const sel of registerSelectors) {
      const el = page.locator(sel);
      if (await el.count() > 0 && await el.first().isVisible()) {
        await el.first().click();
        console.log(`[recon]    Clicked register via selector: ${sel}`);
        break;
      }
    }

    // Wait for the WebAuthn ceremony to complete (CDP handles it automatically)
    // Look for success indicators on webauthn.io
    await Promise.race([
      page.waitForSelector('.alert-success, .success, [data-success]', { timeout: 10000 }).catch(() => null),
      page.waitForResponse(resp =>
        resp.url().includes('register') && resp.url().includes('finish') && resp.status() === 200,
        { timeout: 10000 }
      ).catch(() => null),
      page.waitForTimeout(8000),
    ]);

    console.log(`[recon]    Registration ceremony completed`);
  } catch (err) {
    console.log(`[recon] ⚠️  Could not auto-interact with registration page: ${err}`);
    console.log(`[recon]    The page might need manual interaction or different selectors.`);
    console.log(`[recon]    Tip: Run with --no-headless to see the page and interact manually.`);
  }
}

/**
 * Perform authentication on the target site.
 * Supports webauthn.io selectors with fallback to generic selectors.
 */
async function performAuthentication(page: Page, username: string): Promise<void> {
  try {
    await page.waitForLoadState('domcontentloaded').catch(() => {});

    const usernameSelectors = [
      '#username',
      'input[name="username"]',
      'input[x-model="username"]',
      'input#input-email',
      'input[placeholder*="username" i]',
      'input[placeholder*="email" i]',
      'input[type="text"]:first-of-type',
    ];

    for (const sel of usernameSelectors) {
      const el = page.locator(sel);
      if (await el.count() > 0 && await el.first().isVisible()) {
        await el.first().fill(username);
        console.log(`[recon]    Filled username via selector: ${sel}`);
        break;
      }
    }

    // webauthn.io: button#authenticate-button or button with text "Authenticate"/"Login"
    const loginSelectors = [
      '#authenticate-button',
      'button:has-text("Authenticate")',
      'button:has-text("Login")',
      'button:has-text("Sign In")',
      'button:has-text("Verify")',
      '#login-button',
      '[data-action="login"]',
    ];

    for (const sel of loginSelectors) {
      const el = page.locator(sel);
      if (await el.count() > 0 && await el.first().isVisible()) {
        await el.first().click();
        console.log(`[recon]    Clicked authenticate via selector: ${sel}`);
        break;
      }
    }

    // Wait for the WebAuthn ceremony to complete
    await Promise.race([
      page.waitForSelector('.alert-success, .success, [data-success]', { timeout: 10000 }).catch(() => null),
      page.waitForResponse(resp =>
        resp.url().includes('login') && resp.url().includes('finish') && resp.status() === 200,
        { timeout: 10000 }
      ).catch(() => null),
      page.waitForTimeout(8000),
    ]);

    console.log(`[recon]    Authentication ceremony completed`);
  } catch (err) {
    console.log(`[recon] ⚠️  Could not auto-interact with login page: ${err}`);
    console.log(`[recon]    Tip: Run with --no-headless to see the page and interact manually.`);
  }
}

/**
 * Analyze the baseline report and generate observations.
 */
function analyzeBaseline(report: BaselineReport): string[] {
  const obs: string[] = [];

  // Check rp.id
  if (report.analysis.rpId) {
    obs.push(`RP ID: "${report.analysis.rpId}"`);
  } else {
    obs.push('⚠️  RP ID not specified — browser will default to current origin hostname');
  }

  // Check algorithms
  const algs = report.analysis.supportedAlgorithms;
  if (algs.length > 0) {
    const algNames = algs.map(a => {
      switch (a) {
        case -7: return 'ES256 (P-256)';
        case -257: return 'RS256 (RSA)';
        case -8: return 'EdDSA';
        case -35: return 'ES384 (P-384)';
        case -36: return 'ES512 (P-521)';
        default: return `Unknown (${a})`;
      }
    });
    obs.push(`Supported algorithms: ${algNames.join(', ')}`);
  }

  // Check attestation
  if (report.analysis.attestationPreference) {
    obs.push(`Attestation preference: ${report.analysis.attestationPreference}`);
    if (report.analysis.attestationPreference === 'none') {
      obs.push('📋 Server accepts "none" attestation — self-attestation & no-attestation tests likely to pass');
    } else if (report.analysis.attestationPreference === 'direct') {
      obs.push('📋 Server requests "direct" attestation — test if it actually validates the attestation statement');
    }
  }

  // Check user verification
  if (report.analysis.userVerificationRequirement) {
    obs.push(`User verification requirement: ${report.analysis.userVerificationRequirement}`);
    if (report.analysis.userVerificationRequirement === 'discouraged') {
      obs.push('⚠️  UV discouraged — UV flag flip tests expected to be accepted');
    } else if (report.analysis.userVerificationRequirement === 'required') {
      obs.push('📋 UV required — test if server actually checks the UV flag bit');
    }
  }

  // Check challenge entropy
  if (report.analysis.challengeEntropyBits !== null) {
    obs.push(`Challenge entropy: ${report.analysis.challengeEntropyBits} bits (${report.analysis.challengeEntropyBits / 8} bytes)`);
    if (report.analysis.challengeEntropyBits < 128) {
      obs.push('⚠️  Challenge has less than 128 bits of entropy — potential weakness');
    }
  }

  // Check resident key
  if (report.analysis.residentKeyRequirement) {
    obs.push(`Resident key requirement: ${report.analysis.residentKeyRequirement}`);
  }

  // Check registration response
  if (report.registration.response.classification === 'ACCEPTED') {
    obs.push('✅ Registration was accepted by the server');
  } else {
    obs.push(`⚠️  Registration result: ${report.registration.response.classification ?? 'UNKNOWN'}`);
  }

  // Check authentication response
  if (report.authentication.response.classification === 'ACCEPTED') {
    obs.push('✅ Authentication was accepted by the server');
  } else {
    obs.push(`⚠️  Authentication result: ${report.authentication.response.classification ?? 'UNKNOWN'}`);
  }

  return obs;
}
