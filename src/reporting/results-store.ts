/**
 * results-store.ts
 *
 * Shared on-disk format for test results. The fuzz/exploit phases write one
 * run file per execution into the results directory (default: ./results/);
 * the report phase reads them all back and renders SARIF / Markdown.
 */

import { writeFileSync, mkdirSync, readdirSync, readFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';

export type Classification = 'ACCEPTED' | 'REJECTED' | 'ERROR' | 'UNKNOWN' | 'SKIPPED';

export interface CaseResult {
  /** Unique rule id, e.g. "fuzz.origin.cross-origin". */
  id: string;
  /** The --module this case belongs to (origin, challenge, ...). */
  module: string;
  /** Human-readable name. */
  name: string;
  /** Which ceremony was mutated. */
  ceremony: 'register' | 'authenticate';
  /** SARIF category (drives severity mapping). */
  category: string;
  /** What the mutation does and why acceptance is a problem. */
  description: string;
  /** Whether this case is meaningful for the target's baseline policy. */
  applicable: boolean;
  /** The server's verdict on the mutated ceremony. */
  classification: Classification;
  /** True when the server accepted something a secure RP should reject. */
  isFinding: boolean;
  /** Severity to assign if this case is a finding. */
  severity: 'error' | 'warning' | 'note';
  statusCode: number | null;
  responseExcerpt: string | null;
  payload: string | null;
  endpoint: string;
  poc?: PocRequest;
}

export interface PocRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
}

export function buildCurl(poc: PocRequest): string {
  const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  const lines = [`curl -i -X ${poc.method} ${q(poc.url)}`];
  for (const [k, v] of Object.entries(poc.headers)) {
    if (k.toLowerCase() === 'content-length') continue;
    lines.push(`  -H ${q(`${k}: ${v}`)}`);
  }
  if (poc.body != null) lines.push(`  --data-raw ${q(poc.body)}`);
  return lines.join(' \\\n');
}

export interface RunResult {
  meta: {
    tool: string;
    version: string;
    timestamp: string;
    phase: string;
    target: string;
    modules: string[];
    authorization?: string;
  };
  cases: CaseResult[];
}

const RESULTS_FILE_PREFIX = 'ppwn-run-';

export function defaultResultsDir(): string {
  return resolve(process.cwd(), 'results');
}

/**
 * Persist a run's results to a timestamped JSON file in `outDir`.
 * Returns the absolute path written.
 */
export function saveRunResult(run: RunResult, outDir?: string): string {
  const dir = outDir ? resolve(outDir) : defaultResultsDir();
  mkdirSync(dir, { recursive: true });

  const stamp = run.meta.timestamp.replace(/[:.]/g, '-');
  const file = join(dir, `${RESULTS_FILE_PREFIX}${run.meta.phase}-${stamp}.json`);
  writeFileSync(file, JSON.stringify(run, null, 2), 'utf-8');
  return file;
}

/**
 * Load every run result JSON file from `dir`.
 */
export function loadRunResults(dir?: string): RunResult[] {
  const d = dir ? resolve(dir) : defaultResultsDir();
  if (!existsSync(d)) return [];

  const runs: RunResult[] = [];
  for (const name of readdirSync(d)) {
    if (!name.startsWith(RESULTS_FILE_PREFIX) || !name.endsWith('.json')) continue;
    try {
      const parsed = JSON.parse(readFileSync(join(d, name), 'utf-8')) as RunResult;
      if (parsed && Array.isArray(parsed.cases)) runs.push(parsed);
    } catch {
      // Skip unreadable/corrupt result files.
    }
  }
  return runs;
}
