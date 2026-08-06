# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x (latest) | Yes |
| < 1.0 | No |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues by email to **security@mazen.tech** (or open a [GitHub Security Advisory](https://github.com/mazen160/skills-manager/security/advisories/new) if you prefer).

Include:
- A description of the vulnerability and its impact
- Steps to reproduce or a minimal proof-of-concept
- Any suggested remediation

You will receive an acknowledgement within **3 business days**. We aim to publish a fix and advisory within **14 days** of confirmation.

## Scope

Issues in scope include:

- Static scanner bypasses that allow a malicious skill to install without a blocking finding
- Sandbox escapes in the AI reviewer invocation (e.g., write access outside the workspace)
- Path traversal or arbitrary file write during install/update
- Archive bombs or resource exhaustion that crash or hang the scanner
- Prompt injection that subverts the AI reviewer's security verdict

Issues out of scope:

- Vulnerabilities in third-party AI CLIs (claude, cursor, codex, opencode) — report those upstream
- Skills themselves — report malicious published skills to the relevant registry

## Security model

Skills Manager is a security gate, not a full sandbox. The static scanner runs entirely in-process and produces deterministic findings. High- and critical-severity findings always block installation and cannot be overridden by AI results. The AI reviewer is additive and may be influenced by prompt injection; do not rely on it alone as a security boundary.
