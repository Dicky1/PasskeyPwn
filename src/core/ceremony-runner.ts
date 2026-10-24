/**
 * ceremony-runner.ts
 *
 * Reusable driver for a single WebAuthn ceremony against a target page.
 * It fills a username, clicks the register/authenticate button, and classifies
 * the relying party's verdict by watching the "finish/verify" network response.
 *
 * The fuzz engine uses this together with ShadowAuthenticator: the shadow
 * authenticator forges the WebAuthn response (optionally mutated), and this
 * runner observes whether the SERVER accepts or rejects that response.
 */

import { Page } from 'playwright';
import { gotoSettled } from './cdp-session.js';

export type Classification = 'ACCEPTED' | 'REJECTED' | 'ERROR' | 'UNKNOWN';

export interface CeremonyResult {
  classification: Classification;
  statusCode: number | null;
  body: string | null;
  matchedUrl: string | null;
}

const USERNAME_SELECTORS = [
  '#username',
  'input[name="username"]',
  'input[x-model="username"]',
  'input#input-email',
  'input[placeholder*="username" i]',
  'input[placeholder*="email" i]',
  'input[type="text"]:first-of-type',
];

const REGISTER_SELECTORS = [
  '#register-button',
  'button:has-text("Register")',
  'button:has-text("Sign Up")',
  'button:has-text("Create Passkey")',
  'button:has-text("Create")',
  '[data-action="register"]',
];

const LOGIN_SELECTORS = [
  '#authenticate-button',
  'button:has-text("Authenticate")',
  'button:has-text("Login")',
  'button:has-text("Sign In")',
  'button:has-text("Verify")',
  '#login-button',
  '[data-action="login"]',
];

export const REGISTER_URL_KEYWORDS = [
  'register', 'registration', 'attestation', 'attest', 'makecredential', 'credential', 'enroll', 'webauthn',
];
export const LOGIN_URL_KEYWORDS = [
  'login', 'signin', 'sign-in', 'authentication', 'authenticate', 'assertion', 'assert', 'verification', 'verify', 'webauthn',
];

/** Fill the first visible username/email field found on the page. */
export async function fillUsername(page: Page, username: string): Promise<void> {
  for (const sel of USERNAME_SELECTORS) {
    const el = page.locator(sel);
    if ((await el.count()) > 0 && (await el.first().isVisible().catch(() => false))) {
      await el.first().fill(username);
      return;
    }
  }
}

async function clickFirst(page: Page, selectors: string[]): Promise<boolean> {
  for (const sel of selectors) {
    const el = page.locator(sel);
    if ((await el.count()) > 0 && (await el.first().isVisible().catch(() => false))) {
      await el.first().click();
      return true;
    }
  }
  return false;
}

/** Click the first visible authentication button found on the page. */
export function clickAuthenticate(page: Page): Promise<boolean> {
  return clickFirst(page, LOGIN_SELECTORS);
}

function classify(status: number): Classification {
  if (status >= 200 && status < 300) return 'ACCEPTED';
  if (status >= 400) return 'REJECTED';
  return 'ERROR';
}

/**
 * Watch for the "finish" response of a ceremony. We keep the last POST response
 * whose URL matches the ceremony keywords — that is the server's final verdict.
 */
function makeResponseCollector(page: Page, urlKeywords: string[]): {
  snapshot: () => CeremonyResult;
  detach: () => void;
} {
  let result: CeremonyResult = {
    classification: 'UNKNOWN',
    statusCode: null,
    body: null,
    matchedUrl: null,
  };

  const handler = async (response: { url(): string; status(): number; request(): { method(): string }; text(): Promise<string> }) => {
    const url = response.url().toLowerCase();
    const method = response.request().method();
    if (method !== 'POST') return;
    if (!urlKeywords.some((kw) => url.includes(kw))) return;

    const status = response.status();
    const body = await response.text().catch(() => null);
    result = {
      classification: classify(status),
      statusCode: status,
      body,
      matchedUrl: response.url(),
    };
  };

  page.on('response', handler as never);
  return {
    snapshot: () => result,
    detach: () => page.off('response', handler as never),
  };
}

async function runCeremony(
  page: Page,
  url: string,
  username: string,
  buttonSelectors: string[],
  urlKeywords: string[],
): Promise<CeremonyResult> {
  const collector = makeResponseCollector(page, urlKeywords);
  try {
    await gotoSettled(page, url);

    await fillUsername(page, username);
    await clickFirst(page, buttonSelectors);

    // Give the ceremony + finish request time to complete.
    await Promise.race([
      page
        .waitForResponse(
          (resp: { url(): string; status(): number }) =>
            urlKeywords.some((kw) => resp.url().toLowerCase().includes(kw)) &&
            (resp.status() < 300 || resp.status() >= 400),
          { timeout: 12000 },
        )
        .catch(() => null),
      page.waitForTimeout(10000),
    ]);
    // Small settle delay so the collector sees the final response.
    await page.waitForTimeout(500);

    return collector.snapshot();
  } finally {
    collector.detach();
  }
}

/**
 * Drive a registration ceremony and return the server's verdict.
 */
export function runRegister(page: Page, url: string, username: string): Promise<CeremonyResult> {
  return runCeremony(page, url, username, REGISTER_SELECTORS, REGISTER_URL_KEYWORDS);
}

/**
 * Drive an authentication ceremony and return the server's verdict.
 */
export function runAuthenticate(page: Page, url: string, username: string): Promise<CeremonyResult> {
  return runCeremony(page, url, username, LOGIN_SELECTORS, LOGIN_URL_KEYWORDS);
}
