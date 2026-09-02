# Repo Agent Instruction Security Scan

## Scope

- Keep the action dependency-free and deterministic.
- Treat instruction files as untrusted text; never execute their contents.
- Keep file discovery inside `GITHUB_WORKSPACE`, skip symlinks, and preserve the size and file-count caps.
- Add or update a Node test for every detector or discovery change.

## Validation

- Run `npm test` after changes.
- Run the action against this file with `INPUT_PATHS=AGENTS.md INPUT_FAIL-ON=high node src/index.js`.
- Never add secrets, repository tokens, telemetry, network requests, or code execution.

## Release boundary

- Keep exactly one root `action.yml`.
- Keep `v1` aligned with the latest reviewed `v1.x.x` release.
- Document detector limitations and breaking changes in the README and release notes.
