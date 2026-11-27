/**
 * CLI command: report
 * `passkeypwn report --format sarif|md --out <path> [--results <dir>]`
 *
 * Aggregates run-result files written by the fuzz/exploit phases and renders
 * them as SARIF 2.1.0 or Markdown.
 */

import { Command } from 'commander';
import { resolve } from 'node:path';
import { loadRunResults, buildCurl, PocRequest } from '../reporting/results-store.js';
import { SarifFinding, SarifReport, writeSarifReport } from '../reporting/sarif-writer.js';
import { writeMarkdownReport, TestMatrixRow } from '../reporting/markdown-writer.js';
import { writeHtmlReport } from '../reporting/html-writer.js';

export function createReportCommand(): Command {
  const cmd = new Command('report')
    .description('Generate a SARIF or Markdown report from saved test results')
    .requiredOption('--format <format>', 'Output format: sarif, md, or html')    .option('--out <path>', 'Output file path (default: ./passkeypwn-report.<ext>)')
    .option('--results <dir>', 'Results directory to read (default: ./results/)')
    .action(async (options) => {
      const format = String(options.format).toLowerCase();
      if (format !== 'sarif' && format !== 'md' && format !== 'html') {
        console.error(`[report] Unknown format "${options.format}". Use "sarif", "md", or "html".`);
        process.exit(1);
      }

      const runs = loadRunResults(options.results);
      if (runs.length === 0) {
        console.error(
          `[report] No result files found in ${resolve(options.results ?? './results')}. ` +
            `Run "passkeypwn fuzz ..." first.`,
        );
        process.exit(1);
      }

      const findings: SarifFinding[] = [];
      const matrix: TestMatrixRow[] = [];
      let target = '';
      let startTime = new Date().toISOString();

      for (const run of runs) {
        if (run.meta.target) target = run.meta.target;
        if (run.meta.timestamp < startTime) startTime = run.meta.timestamp;

        for (const c of run.cases) {
          matrix.push({
            module: c.module,
            name: c.name,
            ceremony: c.ceremony,
            classification: c.classification,
            applicable: c.applicable,
            isFinding: c.isFinding,
            statusCode: c.statusCode,
            detail: c.responseExcerpt,
          });
          if (!c.isFinding) continue;
          findings.push({
            ruleId: c.id,
            ruleName: c.name,
            level: c.severity,
            message: c.description,
            endpoint: c.endpoint,
            httpMethod: 'POST',
            statusCode: c.statusCode ?? undefined,
            responseExcerpt: c.responseExcerpt ?? undefined,
            payload: c.payload ?? undefined,
            category: c.category,
            ...(c.poc ? { poc: c.poc } : {}),
          });
        }
      }

      const report: SarifReport = {
        findings,
        targetUrl: target,
        startTime,
        endTime: new Date().toISOString(),
      };

      const ext = format === 'sarif' ? 'sarif' : format === 'html' ? 'html' : 'md';
      const outPath = resolve(options.out ?? `./passkeypwn-report.${ext}`);

      if (format === 'sarif') {
        writeSarifReport(report, outPath);
      } else if (format === 'html') {
        writeHtmlReport(report, outPath, matrix);
      } else {
        writeMarkdownReport(report, outPath, matrix);
      }

      const totalCases = runs.reduce((n, r) => n + r.cases.length, 0);
      for (const c of runs.flatMap((r) => r.cases)) {
        if (c.isFinding && c.poc) console.log(`\\n# PoC (${c.id})\\n${buildCurl(c.poc)}`);
      }
      console.log(
        `[report] ${findings.length} finding(s) across ${totalCases} test case(s) from ${runs.length} run(s).`,
      );
    });

  return cmd;
}
