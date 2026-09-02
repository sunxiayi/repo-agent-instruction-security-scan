const fs = require('node:fs');
const path = require('node:path');

const MAX_FILE_BYTES = 150_000;
const DEFAULT_MAX_FILES = 200;

const SIGNALS = [
  {
    id: 'hidden-unicode',
    title: 'Hidden or bidirectional Unicode',
    severity: 'high',
    pattern: /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/u,
    guidance:
      'Remove invisible or bidirectional control characters and review the surrounding text.',
  },
  {
    id: 'download-execute',
    title: 'Downloaded content piped to execution',
    severity: 'high',
    pattern:
      /(?:curl|wget)\b[^\n|;&]*(?:\||&&|;)\s*(?:sudo\s+)?(?:bash|sh|zsh|python(?:3)?|node|pwsh|powershell)\b/i,
    guidance:
      'Download, pin, inspect, and verify the artifact separately before any execution step.',
  },
  {
    id: 'secret-transfer',
    title: 'Instruction to expose or transfer secrets',
    severity: 'high',
    pattern:
      /(?:send|upload|post|transmit|exfiltrat\w*|paste|echo|print)\b[^\n]{0,100}\b(?:secret|token|api[_ -]?key|credential|password|\.env|ssh[_ -]?key)\b/i,
    guidance:
      'Remove secret-transfer instructions and use an approved secret store with least privilege.',
  },
  {
    id: 'permission-bypass',
    title: 'Approval, permission, or sandbox bypass',
    severity: 'high',
    pattern:
      /(?:--dangerously-skip-permissions|disable\s+(?:the\s+)?sandbox|bypass\s+(?:all\s+)?(?:approval|confirmation|permission)|never\s+ask\s+(?:the\s+user\s+)?(?:for\s+)?(?:approval|confirmation)|ignore\s+(?:all\s+)?security\s+(?:rules?|warnings?))/i,
    guidance:
      'Keep sandboxing and approval boundaries explicit; scope any exception to one reviewed operation.',
  },
  {
    id: 'remote-authority',
    title: 'Mutable remote instructions treated as authority',
    severity: 'medium',
    pattern:
      /(?:fetch|download|read|follow|obey|load)\b[^\n]{0,120}\bhttps?:\/\/[^\s)]+[^\n]{0,80}\b(?:instruction|command|prompt|rule|policy|authoritative|source of truth)\b/i,
    guidance:
      'Pin remote material by digest or commit and treat it as untrusted data until reviewed.',
  },
  {
    id: 'destructive-command',
    title: 'Broad destructive command',
    severity: 'high',
    pattern:
      /(?:rm\s+-[a-z]*r[a-z]*f|git\s+(?:reset\s+--hard|clean\s+-[a-z]*f)|drop\s+(?:database|schema|table)|format\s+[a-z]:|del\s+\/s\s+\/q)\b/i,
    guidance:
      'Replace broad deletion with an explicit target, a recovery path, and human confirmation.',
  },
  {
    id: 'sensitive-file-access',
    title: 'Broad access to sensitive files',
    severity: 'medium',
    pattern:
      /(?:read|scan|search|copy|collect|cat|find)\b[^\n]{0,120}(?:~\/\.ssh|~\/\.aws|~\/\.config|\/etc\/shadow|\.env(?:\.|\b)|id_rsa|credentials\.json|keychain)/i,
    guidance:
      'Limit file access to named project files and exclude credentials, home directories, and secret stores.',
  },
  {
    id: 'encoded-execution',
    title: 'Encoded or dynamically constructed execution',
    severity: 'high',
    pattern:
      /(?:base64\s+(?:--decode|-d)|frombase64string|atob\s*\()[^\n]{0,140}(?:\||&&|;|invoke-expression|iex\b|eval\s*\(|exec\s*\()/i,
    guidance:
      'Do not execute decoded or dynamically assembled content; inspect the plain-text command first.',
  },
];

const ignoredDirectories = new Set([
  '.git',
  '.next',
  '.turbo',
  'build',
  'coverage',
  'dist',
  'node_modules',
  'target',
  'vendor',
]);

function normalisePath(value) {
  return value.split(path.sep).join('/').replace(/^\.\//, '');
}

function isSupportedInstructionFile(filePath) {
  const normalised = normalisePath(filePath);
  const base = path.posix.basename(normalised).toLowerCase();

  if (
    ['agents.md', 'claude.md', 'gemini.md', 'skill.md', '.cursorrules'].includes(
      base,
    )
  ) {
    return true;
  }

  return (
    /^\.cursor\/rules\/.+\.(?:md|mdc)$/i.test(normalised) ||
    /(?:^|\/)\.cursor\/rules\/.+\.(?:md|mdc)$/i.test(normalised) ||
    /(?:^|\/)\.github\/copilot-instructions\.md$/i.test(normalised) ||
    /(?:^|\/)\.github\/instructions\/.+\.instructions\.md$/i.test(normalised) ||
    /(?:^|\/)\.claude\/rules\/.+\.md$/i.test(normalised) ||
    /(?:^|\/)\.windsurf\/rules\/.+\.md$/i.test(normalised)
  );
}

function discoverInstructionFiles(root, requestedPaths, maxFiles = DEFAULT_MAX_FILES) {
  const rootPath = path.resolve(root);
  const files = [];
  const seen = new Set();

  function visit(target) {
    if (files.length >= maxFiles) return;

    let stat;
    try {
      stat = fs.lstatSync(target);
    } catch {
      return;
    }

    if (stat.isSymbolicLink()) return;

    if (stat.isDirectory()) {
      const name = path.basename(target);
      if (target !== rootPath && ignoredDirectories.has(name)) return;

      for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
        if (ignoredDirectories.has(entry.name)) continue;
        visit(path.join(target, entry.name));
        if (files.length >= maxFiles) break;
      }
      return;
    }

    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) return;
    const relative = normalisePath(path.relative(rootPath, target));
    if (!relative.startsWith('../') && isSupportedInstructionFile(relative) && !seen.has(relative)) {
      seen.add(relative);
      files.push(relative);
    }
  }

  for (const requested of requestedPaths) {
    const target = path.resolve(rootPath, requested || '.');
    const relative = path.relative(rootPath, target);
    if (relative.startsWith('..') || path.isAbsolute(relative)) continue;
    visit(target);
  }

  return {
    files: files.sort(),
    truncated: files.length >= maxFiles,
  };
}

function scanText(text, file = 'AGENTS.md') {
  const findings = [];
  const lines = text.split(/\r?\n/);

  for (let index = 0; index < lines.length; index += 1) {
    for (const signal of SIGNALS) {
      if (signal.pattern.test(lines[index])) {
        findings.push({
          id: signal.id,
          title: signal.title,
          severity: signal.severity,
          guidance: signal.guidance,
          file,
          line: index + 1,
          evidence: lines[index].trim().slice(0, 240),
        });
      }
    }
  }

  return findings;
}

function scanRepository(root, requestedPaths, maxFiles = DEFAULT_MAX_FILES) {
  const discovered = discoverInstructionFiles(root, requestedPaths, maxFiles);
  const findings = discovered.files.flatMap((file) => {
    const text = fs.readFileSync(path.join(root, file), 'utf8');
    return scanText(text, file);
  });

  const counts = { high: 0, medium: 0, low: 0 };
  for (const finding of findings) counts[finding.severity] += 1;

  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    scannedFiles: discovered.files,
    truncated: discovered.truncated,
    counts,
    findings,
  };
}

module.exports = {
  DEFAULT_MAX_FILES,
  MAX_FILE_BYTES,
  SIGNALS,
  discoverInstructionFiles,
  isSupportedInstructionFile,
  scanRepository,
  scanText,
};
