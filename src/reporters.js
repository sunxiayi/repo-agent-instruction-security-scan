const { SIGNALS } = require('./scanner');

const TOOL_NAME = 'Repo Agent Instruction Security Scan';
const TOOL_VERSION = '1.1.3';

function sarifLevel(severity) {
  if (severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function toSarif(report) {
  return {
    $schema:
      'https://json.schemastore.org/sarif-2.1.0-rtm.5.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri:
              'https://repoagentkit.com/agent-instruction-security-scanner?utm_source=sarif-report',
            rules: SIGNALS.map((signal) => ({
              id: signal.id,
              name: signal.title.replaceAll(/[^A-Za-z0-9]+/g, ''),
              shortDescription: { text: signal.title },
              help: { text: signal.guidance },
              properties: {
                precision: 'medium',
                securitySeverity:
                  signal.severity === 'high'
                    ? '8.0'
                    : signal.severity === 'medium'
                      ? '5.0'
                      : '2.0',
                tags: ['security', 'ai-agent-instructions'],
              },
            })),
          },
        },
        artifacts: report.scannedFiles.map((file) => ({
          location: { uri: file },
        })),
        results: report.findings.map((finding) => ({
          ruleId: finding.id,
          level: sarifLevel(finding.severity),
          message: {
            text: `${finding.title}. ${finding.guidance}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.file },
                region: { startLine: finding.line },
              },
            },
          ],
          properties: {
            severity: finding.severity,
            evidence: finding.evidence,
          },
        })),
        properties: {
          scannedFiles: report.scannedFiles.length,
          truncated: report.truncated,
        },
      },
    ],
  };
}

module.exports = { TOOL_NAME, TOOL_VERSION, sarifLevel, toSarif };
