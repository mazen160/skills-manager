# Changelog

All notable changes to Skills Manager are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add a fail-closed analyzer registry and normalized finding schema v2 with stable fingerprints, categories, analyzer provenance, locations, policy metadata, and analyzer health.
- Add Unicode deception, multi-stage shell pipeline flow, dependency pinning, recursive reference containment, provider-secret, PII-harvesting, and Markdown exfiltration analyzers.
- Add magic-byte validation, focused Python AST and shell source-to-sink analysis, `SKILL.md`/`allowed-tools` security contracts, cross-skill collection correlation, and bounded recursive ZIP/TAR member scanning.
- Add SARIF 2.1.0 export with `--sarif`, built-in `strict`/`balanced`/`permissive` profiles, JSON policy files, and repeatable versioned external signature packs with `--rules-file`.

### Security

- Keep policy configuration fail-closed: blocking deterministic rules cannot be disabled or downgraded by a policy file, analyzer failures become blocking findings, and archive contents are inspected in memory under shared depth, member, ratio, and expanded-byte budgets.

## [1.0.2] - 2026-08-06

### Added

- Add repeatable `--exclude RULE` and `--exclude-path GLOB` controls to scan and install, with stable rule IDs in text and JSON findings.
- Preserve install exclusions in `.skills-install.json` and reapply them during update checks and installation.
- Add `make dev-install` for editable local development installs.

### Changed

- Scan additional source and text-like formats, including unknown UTF-8 files, while classifying known binary and document assets separately.
- Report hidden entries, persistence directories, executable modes, and symlinks at clearer package-relative boundaries.

### Fixed

- Reduce false positives from quoted dangerous-command examples, inert test fixtures, placeholder credentials, documentation-only registry and hook mentions, conventional metadata, and source directories named `hooks`.
- Distinguish internal symlinks from links that escape the selected source tree.
- Detect JSON-escaped and encrypted private keys, literal credentials, actionable destructive commands, and actual registry or persistent-hook configuration.

### Security

- Apply path exclusions before inventory and installation so excluded content is neither scanned nor copied.
- Include exclusion details and suppressed-finding counts in normalized security results for auditable policy exceptions.

## [1.0.1] - 2026-08-06

### Added

- Accept direct GitHub `/blob/<branch>/<path>/SKILL.md` URLs for scanning, installation, and analysis, including `?plain=1` and line-fragment variants.
- Add the `agentic-skill-manager` and `agentic-skills-manager` command aliases alongside the existing four entry points.
- Report size, file counts, validation findings, and metadata, activated-skill, and full-directory token estimates for each analyzed skill.
- Add analysis CI output, configurable skill and file token limits, and non-zero exits for invalid or oversized skills.
- Test Python 3.9 through 3.13 in CI and verify every packaged command alias from an installed wheel.

### Changed

- Keep CLI help focused on the canonical `claude`, `cursor`, `codex`, and `opencode` agent names; document supported compatibility spellings in the README and remove misleading `cloud` and `codecs` typo aliases.
- Add `install --minimum-accepted-severity` with a `medium` default so callers can tighten or relax the severity ceiling without changing scanner code.
- Standardize AI review, timeout, report output, and forced-review controls across scan, install, and update.
- Rewrite the README around the scanner, supported workflows, security boundaries, and direct PyPI installation.
- Expand the security policy with explicit static and AI trust boundaries, safer usage guidance, and private reporting instructions.

### Fixed

- Avoid reporting `/usr/bin/env` interpreter shebangs and documentation-only mentions as environment-variable access while retaining checks for real environment APIs and shell commands.
- Bound scanner resources, harden archive and filesystem traversal, and restore installed content when an update fails.

### Security

- Keep critical findings blocking at every accepted severity ceiling and require the explicit `--unsafe-install` override to copy a blocked source.
- Reject unsafe links, bytecode, native payloads, deceptive Git metadata, archive traversal, and scanner-evasion inputs before installation.

## [1.0.0] - 2026-08-06

### Added

- Add `scan`, `install`, `list`, `update`, and `uninstall` workflows for Claude, Cursor, Codex, and OpenCode skills.
- Add GitHub repository, tree URL, SSH remote, branch, tag, subdirectory, and local-folder sources.
- Add recursive `SKILL.md` discovery for monorepos and atomic installation with source metadata for tracked updates.
- Add opt-in AI security review through Claude, Cursor, Codex, or OpenCode, plus `--force-run-ai-checks` for a second opinion on statically blocked sources.
- Standardize AI review controls across scan, install, and update, including `--ai-agent-timeout-seconds`.
- Add CI scan mode with a JSON verdict on stdout, findings on stderr, report artifacts, and non-zero unsafe exits.
- Add `skills analyze [SOURCE...]` for installed skills, local folders, direct `SKILL.md` paths, and GitHub repository/tree/blob URLs, with context estimates, validation, token-limit policy, and CI verdict output.
- Add verbose installed-skill inventory, update previews, guarded update application, and dry-run uninstall behavior.
- Add the `skill`, `skills`, `skill-manager`, `skills-manager`, `agentic-skill-manager`, and `agentic-skills-manager` command aliases.
- Add a versioned CLI banner, TTY-aware color, `NO_COLOR` and `FORCE_COLOR` support, normalized JSON reports, and elapsed-time output.
- Add PyPI packaging, source and wheel release checks, a complete brand kit, terminal demos, and standard-library tests.

### Security

- Block high and critical findings before installation or update application.
- Detect private keys, credential assignments, dangerous shell execution, executable environment access, persistence hooks, registry rewrites, native loading, embedded Git metadata, and scanner-evasion padding.
- Reject opaque or unsafe payloads, including bytecode, native libraries, archives, document containers, images, symlinks, escaping hard links, and deceptive filesystem entries.
- Inspect ZIP-compatible archives for path traversal, embedded executables, hidden configuration, compiled payloads, and excessive contents.
- Run AI reviewers in restricted agent-specific sandboxes and merge their findings without allowing an AI verdict to override a deterministic block.

[Unreleased]: https://github.com/mazen160/skills-manager/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/mazen160/skills-manager/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/mazen160/skills-manager/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/mazen160/skills-manager/releases/tag/v1.0.0
