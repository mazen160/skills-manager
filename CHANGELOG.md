# Changelog

All notable changes to Skills Manager are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Keep CLI help focused on the canonical `claude`, `cursor`, `codex`, and `opencode` agent names; document supported compatibility spellings in the README and remove misleading `cloud` and `codecs` typo aliases.

## [1.0.0] - 2026-08-06

### Added

- Add `scan`, `install`, `list`, `update`, and `uninstall` workflows for Claude, Cursor, Codex, and OpenCode skills.
- Add GitHub repository, tree URL, SSH remote, branch, tag, subdirectory, and local-folder sources.
- Add recursive `SKILL.md` discovery for monorepos and atomic installation with source metadata for tracked updates.
- Add opt-in AI security review through Claude, Cursor, Codex, or OpenCode, plus `--force-run-ai-checks` for a second opinion on statically blocked sources.
- Add CI scan mode with a JSON verdict on stdout, findings on stderr, report artifacts, and non-zero unsafe exits.
- Add `skills analyze cost` with metadata, activated-skill, and full-directory context estimates plus skill-definition validation.
- Add verbose installed-skill inventory, update previews, guarded update application, and dry-run uninstall behavior.
- Add the `skill`, `skills`, `skill-manager`, and `skills-manager` command aliases.
- Add a versioned CLI banner, TTY-aware color, `NO_COLOR` and `FORCE_COLOR` support, normalized JSON reports, and elapsed-time output.
- Add PyPI packaging, source and wheel release checks, a complete brand kit, terminal demos, and standard-library tests.

### Security

- Block high and critical findings before installation or update application.
- Detect private keys, credential assignments, dangerous shell execution, executable environment access, persistence hooks, registry rewrites, native loading, embedded Git metadata, and scanner-evasion padding.
- Reject opaque or unsafe payloads, including bytecode, native libraries, archives, document containers, images, symlinks, escaping hard links, and deceptive filesystem entries.
- Inspect ZIP-compatible archives for path traversal, embedded executables, hidden configuration, compiled payloads, and excessive contents.
- Run AI reviewers in restricted agent-specific sandboxes and merge their findings without allowing an AI verdict to override a deterministic block.

[1.0.0]: https://github.com/mazen160/skills-manager/releases/tag/v1.0.0
