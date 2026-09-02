#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const { TOOL_VERSION, toSarif } = require('../src/reporters');
const { scanRepository } = require('../src/scanner');

const severityOrder = { none: 99, high: 3, medium: 2, low: 1 };

function usage() {
  return `Repo Agent Instruction Security Scan ${TOOL_VERSION}

Usage:
  repo-agent-scan [paths...] [options]

Options:
  --format <text|json|sarif>  Output format (default: text)
  --output <file>             Write the report inside the scan root
  --fail-on <level>           high, medium, low, or none (default: high)
  --help                      Show this help
  --version                   Show the version

Examples:
  repo-agent-scan .
  repo-agent-scan AGENTS.md .claude/rules --fail-on medium
  repo-agent-scan . --format sarif --output agent-instructions.sarif
`;
}

function parseArgs(argv) {
  const options = {
    paths: [],
    format: 'text',
    output: '',
    failOn: 'high',
    help: false,
    version: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--help' || value === '-h') options.help = true;
    else if (value === '--version' || value === '-v') options.version = true;
    else if (value === '--format') options.format = argv[++index] || '';
    else if (value.startsWith('--format=')) options.format = value.slice(9);
    else if (value === '--output') options.output = argv[++index] || '';
    else if (value.startsWith('--output=')) options.output = value.slice(9);
    else if (value === '--fail-on') options.failOn = argv[++index] || '';
    else if (value.startsWith('--fail-on=')) options.failOn = value.slice(10);
    else if (value.startsWith('-')) throw new Error(`Unknown option: ${value}`);
    else options.paths.push(value);
  }

  if (!['text', 'json', 'sarif'].includes(options.format)) {
    throw new Error('--format must be one of: text, json, sarif');
  }
  if (!(options.failOn in severityOrder)) {
    throw new Error('--fail-on must be one of: high, medium, low, none');
  }
  return options;
}

function textReport(report) {
  const rows = report.findings.map(
    (finding) =>
      `${finding.severity.toUpperCase()} ${finding.file}:${finding.line} ${finding.title}\n  ${finding.guidance}`,
  );
  return [
    ...rows,
    rows.length ? '' : 'No review prompts found.',
    `Scanned ${report.scannedFiles.length} instruction file(s); found ${report.findings.length} review prompt(s): ${report.counts.high} high, ${report.counts.medium} medium, ${report.counts.low} low.`,
    report.truncated
      ? 'File discovery hit the 200-file safety cap; the result is incomplete.'
      : 'Static findings are review prompts, not vulnerability verdicts.',
  ].join('\n');
}

function serialise(report, format) {
  if (format === 'json') return `${JSON.stringify(report, null, 2)}\n`;
  if (format === 'sarif') return `${JSON.stringify(toSarif(report), null, 2)}\n`;
  return `${textReport(report)}\n`;
}

function writeOutput(root, output, contents) {
  if (!output) {
    process.stdout.write(contents);
    return;
  }

  const outputPath = path.resolve(root, output);
  const relative = path.relative(root, outputPath);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('--output must stay inside the scan root');
  }
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, contents);
  process.stderr.write(`Wrote ${relative.split(path.sep).join('/')}\n`);
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(usage());
    return;
  }
  if (options.version) {
    process.stdout.write(`${TOOL_VERSION}\n`);
    return;
  }

  const root = process.cwd();
  const report = scanRepository(
    root,
    options.paths.length ? options.paths : ['.'],
  );
  writeOutput(root, options.output, serialise(report, options.format));

  const threshold = severityOrder[options.failOn];
  if (
    report.findings.some(
      (finding) => severityOrder[finding.severity] >= threshold,
    )
  ) {
    process.exitCode = 1;
  }
}

try {
  main();
} catch (error) {
  process.exitCode = 2;
  process.stderr.write(
    `repo-agent-scan: ${error instanceof Error ? error.message : String(error)}\n`,
  );
}

module.exports = { main, parseArgs, serialise, textReport, usage };
