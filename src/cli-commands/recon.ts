/**
 * CLI command: recon
 * `passkeypwn recon --url-register <url> --url-login <url> [options]`
 * 
 * Performs Phase 1 reconnaissance against a WebAuthn-enabled target.
 */

import { Command } from 'commander';
import { runRecon } from '../modules/recon.js';

export function createReconCommand(): Command {
  const cmd = new Command('recon')
    .description('Perform WebAuthn reconnaissance — register + authenticate to capture baseline configuration')
    .requiredOption('--url-register <url>', 'URL of the registration page')
    .requiredOption('--url-login <url>', 'URL of the login/authentication page')
    .option('--username <name>', 'Username for registration (default: auto-generated)')
    .option('--out <path>', 'Output file path for baseline.json (default: ./baseline.json)')
    .option('--no-headless', 'Run browser in visible (headed) mode')
    .option('--screenshots <dir>', 'Capture full-page screenshots of each step into this directory')
    .option('--proxy <url>', 'Route all browser traffic through a proxy (e.g., http://127.0.0.1:8080 for Burp)')
    .option('--slow-mo <ms>', 'Slow down browser actions by N ms (useful for debugging)', parseInt)
    .option('--keep-open', 'Keep browser open after recon (for manual inspection)')
    .action(async (options) => {
      console.log('');
      console.log('  ╔═══════════════════════════════════════╗');
      console.log('  ║   PasskeyPwn — WebAuthn Recon         ║');
      console.log('  ╚═══════════════════════════════════════╝');
      console.log('');

      try {
        const report = await runRecon({
          urlRegister: options.urlRegister,
          urlLogin: options.urlLogin,
          username: options.username,
          outFile: options.out,
          keepOpen: options.keepOpen ?? false,
          screenshotDir: options.screenshots,
          sessionOptions: {
            headless: options.headless ?? true,
            proxy: options.proxy,
            slowMo: options.slowMo,
          },
        });

        // Print summary
        console.log('');
        console.log('  ── Summary ──');
        if (report.analysis.observations.length > 0) {
          for (const obs of report.analysis.observations) {
            console.log(`  ${obs}`);
          }
        }
        console.log('');
        console.log(`  Done. See ${options.out ?? './baseline.json'} for full report.`);
      } catch (err) {
        console.error(`[recon] Fatal error:`, err);
        process.exit(1);
      }
    });

  return cmd;
}

