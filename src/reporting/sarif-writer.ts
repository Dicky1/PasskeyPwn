/**
 * sarif-writer.ts
 * 
 * Generates SARIF 2.1.0 compliant output for PasskeyPwn findings.
 * 
 * One `run` per execution, one `result` per test case finding.
 * Each result includes:
 *   - ruleId: unique test case name
 *   - level: error | warning | note (mapped from severity)
 *   - message.text: summary of payload + server response excerpt
 *   - locations: endpoint being tested
 */

import { writeFileSync } from 'node:fs';

export interface SarifFinding {
  ruleId: string;
  ruleName: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: string;
  endpoint: string;
  httpMethod?: string;
  statusCode?: number;
  responseExcerpt?: string;
  payload?: string;
  category: string;
  helpUri?: string;
}

export interface SarifReport {
  findings: SarifFinding[];
  targetUrl: string;
  startTime: string;
  endTime?: string;
}

/**
 * Build a SARIF 2.1.0 JSON document from findings.
 */
export function buildSarifDocument(report: SarifReport): object {
  const rules = new Map<string, {
    id: string;
    name: string;
    shortDescription: { text: string };
    helpUri?: string;
    properties?: { category: string };
  }>();

  const results: object[] = [];

  for (const finding of report.findings) {
    // Add rule if not already present
    if (!rules.has(finding.ruleId)) {
      rules.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.ruleName,
        shortDescription: { text: finding.ruleName },
        helpUri: finding.helpUri,
        properties: { category: finding.category },
      });
    }

    // Build message text
    let messageText = finding.message;
    if (finding.payload) {
      messageText += `\n\nPayload: ${finding.payload}`;
    }
    if (finding.responseExcerpt) {
      messageText += `\n\nServer response (excerpt): ${finding.responseExcerpt.substring(0, 500)}`;
    }
    if (finding.statusCode) {
      messageText += `\n\nHTTP Status: ${finding.statusCode}`;
    }

    results.push({
      ruleId: finding.ruleId,
      level: finding.level,
      message: { text: messageText },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: finding.endpoint,
            },
          },
          properties: {
            httpMethod: finding.httpMethod ?? 'POST',
          },
        },
      ],
    });
  }

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0' as const,
    runs: [
      {
        tool: {
          driver: {
            name: 'PasskeyPwn',
            version: '1.0.0',
            informationUri: 'https://github.com/passkeypwn/passkeypwn',
            rules: Array.from(rules.values()),
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: report.startTime,
            endTimeUtc: report.endTime ?? new Date().toISOString(),
            properties: {
              targetUrl: report.targetUrl,
            },
          },
        ],
      },
    ],
  };

  return sarif;
}

/**
 * Write SARIF report to a file.
 */
export function writeSarifReport(report: SarifReport, outputPath: string): void {
  const sarif = buildSarifDocument(report);
  writeFileSync(outputPath, JSON.stringify(sarif, null, 2), 'utf-8');
  console.log(`[sarif] Report written to: ${outputPath}`);
}

