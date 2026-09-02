# Repo Agent Instruction Security Scan

[![Test](https://github.com/sunxiayi/repo-agent-instruction-security-scan/actions/workflows/test.yml/badge.svg)](https://github.com/sunxiayi/repo-agent-instruction-security-scan/actions/workflows/test.yml)

A deterministic, zero-dependency GitHub Action that reviews coding-agent instruction files before they reach your default branch. It scans `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, Cursor rules, GitHub Copilot instructions, Claude rules, and Windsurf rules without executing repository code or sending file contents to a service.

## Use it in a workflow

```yaml
name: Agent instruction security

on:
  pull_request:
    paths:
      - '**/AGENTS.md'
      - '**/CLAUDE.md'
      - '**/GEMINI.md'
      - '**/.cursorrules'
      - '**/.cursor/rules/**'
      - '**/.github/copilot-instructions.md'
      - '**/.github/instructions/*.instructions.md'
      - '**/.claude/rules/**'
      - '**/.windsurf/rules/**'

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: sunxiayi/repo-agent-instruction-security-scan@v1
```

The action adds line-level annotations, writes a job summary, emits counts as outputs, and saves `repo-agent-instruction-security.json`. It fails on high-severity findings by default.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `paths` | `.` | Newline-separated files or directories inside the workspace. |
| `fail-on` | `high` | Minimum failing severity: `high`, `medium`, `low`, or `none`. |
| `report-path` | `repo-agent-instruction-security.json` | JSON report path. Use an empty value to disable the report. |

Outputs: `findings`, `high`, `medium`, `low`, and `report`.

## What it reviews

- Hidden or bidirectional Unicode
- Downloaded content piped to a shell or interpreter
- Instructions to expose or transfer secrets
- Approval, permission, or sandbox bypasses
- Mutable remote instructions treated as authority
- Broad destructive commands
- Broad access to sensitive files
- Encoded or dynamically constructed execution

Every result includes a file, line, severity, evidence excerpt, and repair prompt. Files larger than 150 KB are skipped, discovery stops at 200 supported files, dependency/build directories and symlinks are ignored, and requested paths cannot escape the checked-out workspace.

## Boundaries

This is a static early-warning screen. A finding is not proof of malicious intent or a vulnerability, and a clean result is not a security guarantee. The action does not execute instructions, inspect application code, make network requests, require a token, or collect telemetry.

For an instant browser review of any public GitHub repository, use the [Repo Agent Kit scanner](https://repoagentkit.com/agent-instruction-security-scanner?utm_source=github-action-readme). Its documented rule set and privacy boundary match this action.

## Development

```bash
npm test
INPUT_PATHS=AGENTS.md INPUT_FAIL-ON=high node src/index.js
```

See [GitHub's secure-use reference](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions) before changing workflow permissions or processing untrusted context.

## License

[MIT](LICENSE)
