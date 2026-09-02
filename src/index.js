const fs = require('node:fs');
const path = require('node:path');

const { scanRepository } = require('./scanner');

const severityOrder = { none: 99, high: 3, medium: 2, low: 1 };

function input(name, fallback = '') {
  return process.env[`INPUT_${name.toUpperCase()}`] ?? fallback;
}

function escapeCommand(value) {
  return String(value)
    .replaceAll('%', '%25')
    .replaceAll('\r', '%0D')
    .replaceAll('\n', '%0A');
}

function escapeProperty(value) {
  return escapeCommand(value).replaceAll(':', '%3A').replaceAll(',', '%2C');
}

function command(name, properties, message) {
  const pairs = Object.entries(properties)
    .map(([key, value]) => `${key}=${escapeProperty(value)}`)
    .join(',');
  process.stdout.write(`::${name}${pairs ? ` ${pairs}` : ''}::${escapeCommand(message)}\n`);
}

function appendOutput(name, value) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (!outputPath) return;
  fs.appendFileSync(outputPath, `${name}=${String(value)}\n`);
}

function writeSummary(report, failOn) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;

  const rows = report.findings.length
    ? report.findings
        .slice(0, 100)
        .map(
          (finding) =>
            `| ${finding.severity.toUpperCase()} | \`${finding.file}:${finding.line}\` | ${finding.title} |`,
        )
        .join('\n')
    : '| — | — | No findings |';

  fs.appendFileSync(
    summaryPath,
    [
      '# Repo Agent Instruction Security Scan',
      '',
      `Scanned **${report.scannedFiles.length}** supported instruction file(s). Found **${report.findings.length}** review prompt(s): ${report.counts.high} high, ${report.counts.medium} medium, ${report.counts.low} low.`,
      '',
      '| Severity | Location | Finding |',
      '| --- | --- | --- |',
      rows,
      '',
      report.truncated
        ? '> File discovery hit the 200-file safety cap; the result is incomplete.'
        : '> Static findings are review prompts, not proof of malicious intent. A clean result is not a security guarantee.',
      '',
      `Failure threshold: \`${failOn}\`. [Review a public repository in the browser](https://repoagentkit.com/agent-instruction-security-scanner?utm_source=github-action-summary).`,
      '',
    ].join('\n'),
  );
}

function main() {
  const workspace = path.resolve(process.env.GITHUB_WORKSPACE || process.cwd());
  const requestedPaths = input('PATHS', '.')
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean);
  const failOn = input('FAIL-ON', 'high').trim().toLowerCase();
  const reportPathInput = input(
    'REPORT-PATH',
    'repo-agent-instruction-security.json',
  ).trim();

  if (!(failOn in severityOrder)) {
    throw new Error('fail-on must be one of: high, medium, low, none');
  }

  const report = scanRepository(workspace, requestedPaths.length ? requestedPaths : ['.']);

  for (const finding of report.findings) {
    command(
      finding.severity === 'high' ? 'error' : 'warning',
      { file: finding.file, line: finding.line, title: finding.title },
      `${finding.title}. ${finding.guidance}`,
    );
  }

  let reportPath = '';
  if (reportPathInput) {
    reportPath = path.resolve(workspace, reportPathInput);
    const relative = path.relative(workspace, reportPath);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new Error('report-path must stay inside GITHUB_WORKSPACE');
    }
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
    reportPath = path.relative(workspace, reportPath).split(path.sep).join('/');
  }

  appendOutput('findings', report.findings.length);
  appendOutput('high', report.counts.high);
  appendOutput('medium', report.counts.medium);
  appendOutput('low', report.counts.low);
  appendOutput('report', reportPath);
  writeSummary(report, failOn);

  process.stdout.write(
    `Scanned ${report.scannedFiles.length} instruction file(s); found ${report.findings.length} review prompt(s).\n`,
  );

  const threshold = severityOrder[failOn];
  const shouldFail = report.findings.some(
    (finding) => severityOrder[finding.severity] >= threshold,
  );
  if (shouldFail) {
    process.exitCode = 1;
    command(
      'error',
      {},
      `Instruction security findings met the configured ${failOn} failure threshold.`,
    );
  }
}

try {
  main();
} catch (error) {
  process.exitCode = 1;
  command('error', {}, error instanceof Error ? error.message : String(error));
}
