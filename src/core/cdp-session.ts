/**
 * cdp-session.ts
 * Wrapper for CDP connection via Playwright Chromium.
 * Manages browser lifecycle, context creation, and CDP session attachment.
 */

import { chromium, Browser, BrowserContext, Page, CDPSession } from 'playwright';
import { mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

export interface CDPSessionOptions {
  headless?: boolean;
  proxy?: string;
  slowMo?: number;
}

export interface CDPConnection {
  browser: Browser;
  context: BrowserContext;
  page: Page;
  cdp: CDPSession;
}

/**
 * Launch Chromium via Playwright and establish a CDP session on the default page.
 * This is the foundation for both BaselineAuthenticator and ShadowAuthenticator.
 */
export async function createCDPSession(opts: CDPSessionOptions = {}): Promise<CDPConnection> {
  const launchOptions: Parameters<typeof chromium.launch>[0] = {
    headless: opts.headless ?? true,
    args: [
      '--disable-blink-features=AutomationControlled',
      // Allow WebAuthn API in automated contexts
      '--enable-features=WebAuthenticationCableSecondFactor',
    ],
  };

  if (opts.proxy) {
    launchOptions.proxy = { server: opts.proxy };
  }

  if (opts.slowMo) {
    launchOptions.slowMo = opts.slowMo;
  }

  const browser = await chromium.launch(launchOptions);
  const context = await browser.newContext({
    // Realistic viewport and user agent
    viewport: { width: 1280, height: 720 },
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  });

  const page = await context.newPage();
  const cdp = await page.context().newCDPSession(page);

  return { browser, context, page, cdp };
}

/**
 * Navigate robustly. We deliberately avoid waitUntil:'networkidle' because many
 * real sites (webauthn.io included) keep long-lived connections open, so network
 * never goes idle and the navigation hangs until timeout. Instead we wait for the
 * DOM and give the SPA a brief, bounded settle window.
 */
export async function gotoSettled(page: Page, url: string, settleMs = 1500, timeoutMs = 20000): Promise<void> {
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: timeoutMs }).catch(() => {});
  await page.waitForTimeout(settleMs);
}

/**
 * Capture a full-page screenshot as evidence. Returns the written path.
 * Failures are swallowed so evidence capture never breaks a test run.
 */
export async function captureScreenshot(page: Page, dir: string, name: string): Promise<string> {
  const d = resolve(dir);
  mkdirSync(d, { recursive: true });
  const file = join(d, name.endsWith('.png') ? name : `${name}.png`);
  await page.screenshot({ path: file, fullPage: true }).catch(() => {});
  return file;
}

/**
 * Cleanup: close browser and all resources.
 */
export async function closeCDPSession(conn: CDPConnection): Promise<void> {
  try {
    await conn.cdp.detach();
  } catch {
    // CDPSession may already be detached
  }
  await conn.context.close();
  await conn.browser.close();
}

