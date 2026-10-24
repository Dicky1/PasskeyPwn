#!/usr/bin/env node

/**
 * PasskeyPwn — Black-box offensive tester for WebAuthn/Passkey implementations.
 * 
 * For authorized security testing only.
 * This tool is designed for security researchers conducting bug bounty
 * or authorized penetration testing of WebAuthn implementations.
 * 
 * Usage:
 *   passkeypwn recon    --url-register <url> --url-login <url>
 *   passkeypwn fuzz     --module origin,challenge,counter,flags,attestation,credid
 *   passkeypwn exploit  --module rogue-persist,downgrade,enum,recovery --authorized "..."
 *   passkeypwn report   --format sarif|md --out <path>
 */

import { Command } from 'commander';
import { createReconCommand } from './cli-commands/recon.js';
import { createFuzzCommand } from './cli-commands/fuzz.js';
import { createExploitCommand } from './cli-commands/exploit.js';
import { createReportCommand } from './cli-commands/report.js';

const program = new Command();

program
  .name('passkeypwn')
  .description(
    'PasskeyPwn — Black-box offensive tester for WebAuthn/Passkey implementations.\n' +
    'For authorized security testing only.',
  )
  .version('1.0.0')
  .option('--proxy <url>', 'Global proxy for all browser traffic (e.g., http://127.0.0.1:8080)')
  .option('--no-headless', 'Run browser in visible (headed) mode')
  .option('--verbose', 'Enable verbose debug output');

// Register subcommands
program.addCommand(createReconCommand());
program.addCommand(createFuzzCommand());
program.addCommand(createExploitCommand());
program.addCommand(createReportCommand());

// Banner
console.log('');
console.log('  ██████╗  █████╗ ███████╗███████╗██╗  ██╗███████╗██╗   ██╗██████╗ ██╗    ██╗███╗   ██╗');
console.log('  ██╔══██╗██╔══██╗██╔════╝██╔════╝██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔══██╗██║    ██║████╗  ██║');
console.log('  ██████╔╝███████║███████╗███████╗█████╔╝ █████╗   ╚████╔╝ ██████╔╝██║ █╗ ██║██╔██╗ ██║');
console.log('  ██╔═══╝ ██╔══██║╚════██║╚════██║██╔═██╗ ██╔══╝    ╚██╔╝  ██╔═══╝ ██║███╗██║██║╚██╗██║');
console.log('  ██║     ██║  ██║███████║███████║██║  ██╗███████╗   ██║   ██║     ╚███╔███╔╝██║ ╚████║');
console.log('  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝');
console.log('                                                              v1.0.0');
console.log('  WebAuthn/Passkey Security Tester — For authorized use only.');
console.log('');

program.parse(process.argv);

