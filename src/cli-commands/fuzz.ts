/**
 * CLI command: fuzz
 * `passkeypwn fuzz --module <modules> [options]`
 *
 * Runs mutation fuzz tests that check whether the target relying party rejects
 * malformed WebAuthn ceremonies. Requires a baseline.json from the recon phase.
 */

import { Command } from 'commander';
import { runFuzz } from '../modules/fuzz.js';

export function createFuzzCommand(): Command {
  const cmd = new Command('fuzz')
    .description('Run mutation fuzz tests against WebAuthn endpoints (requires a recon baseline)')
    .requiredOption(
      '--module <modules>',
      'Comma-separated fuzz modules: origin,challenge,counter,flags,attestation,credid',
    )
    .option('--baseline <path>', 'Path to baseline.json from recon phase (default: ./baseline.json)')
    .option('--url-register <url>', 'Override registration URL from baseline')
    .option('--url-login <url>', 'Override login URL from baseline')
    .option(
      '--mode <mode>',
      'Mutation delivery: "replay" (HTTP capture-replay, target-agnostic) or "browser" (DOM-driven)',
      'browser',
    )
    .option('--out <dir>', 'Results directory (default: ./results/)')
    .option('--screenshots <dir>', 'Capture screenshots of the replay capture phase into this directory')
    .option('--no-headless', 'Run browser in visible mode')
    .option('--proxy <url>', 'Route browser traffic through a proxy (e.g., http://127.0.0.1:8080)')
    .option('--slow-mo <ms>', 'Slow down browser actions by N ms', parseInt)
    .action(async (options) => {
      console.log('');
      console.log('  ╔═══════════════════════════════════════╗');
      console.log('  ║   PasskeyPwn — WebAuthn Fuzz          ║');
      console.log('  ╚═══════════════════════════════════════╝');
      console.log('');

      const modules = String(options.module)
        .split(',')
        .map((m: string) => m.trim())
        .filter(Boolean);

      const mode = options.mode === 'replay' ? 'replay' : 'browser';

      try {
        await runFuzz({
          modules,
          baselinePath: options.baseline,
          urlRegister: options.urlRegister,
          urlLogin: options.urlLogin,
          mode,
          outDir: options.out,
          screenshotDir: options.screenshots,
          sessionOptions: {
            headless: options.headless ?? true,
            proxy: options.proxy,
            slowMo: options.slowMo,
          },
        });
        console.log('');
        console.log('  Done. Run "passkeypwn report --format md --out report.md" to render results.');
      } catch (err) {
        console.error(`[fuzz] Fatal error: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
    });

  return cmd;
}
