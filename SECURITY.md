# Security Policy

Skills are not passive documents. They can change how an agent reasons, which tools it calls, and which scripts it runs. Skills Manager treats every source as untrusted until it passes a deterministic review.

This policy explains what the project protects, where those protections stop, and how to report a vulnerability without putting users at risk.

## Supported releases

Security fixes are made against the latest published release and the current `main` branch.

| Target | Support status |
| --- | --- |
| Latest PyPI release | Supported |
| Current `main` branch | Fixes land here first; it may contain unreleased changes |
| Older releases, forks, and modified builds | Not supported |

Before reporting a vulnerability, reproduce it against the latest release or `main`. If the issue only affects an older version, include that detail in the report.

## Report vulnerabilities privately

Do not open a public issue, discussion, or pull request for a suspected vulnerability.

Email [mazin[AT]mazinahmed[DOT]net) with the subject `[Skills Manager security]`. This is the project's private reporting channel; GitHub issues and discussions are public.

Include enough detail to reproduce and assess the issue:

- A concise description of the vulnerability and its impact.
- The affected Skills Manager version or commit.
- Your operating system, Python version, and exact command-line options.
- A minimal test repository or redacted fixture.
- Reproduction steps and observed output.
- Whether the issue requires `--unsafe-install`, `--show-ai-inputs`, or another explicit risk-acceptance option.
- A suggested fix, if you have one. It is useful, but not required.

Do not include live credentials, private customer data, or a payload that targets systems you do not own. Redact security reports before attaching them; paths, source content, and agent output may contain sensitive data.


## In scope

The strongest reports show a concrete break in a documented security boundary. Examples include:

- A deterministic scanner bypass that lets a known blocking construct pass without a finding.
- A severity-policy or CI exit-code bug that reports a blocked source as safe.
- Path traversal, arbitrary file write, symlink or hard-link abuse, or unsafe overwrite during install or update.
- Archive traversal, decompression abuse, nested payload handling, or a resource-limit bypass.
- Git argument injection, unsafe repository-path resolution, or malicious `.git` metadata affecting the host.
- A rollback failure that corrupts or removes an existing installed skill.
- An AI-review invocation escaping the restrictions Skills Manager applies to that specific agent.
- Prompt injection that causes the selected AI reviewer to access data or modify files beyond its documented boundary.
- Sensitive source, prompt, inventory, or report data being exposed without the user enabling the relevant output.

## Out of scope

The following are not Skills Manager vulnerabilities by themselves:

- General model mistakes, non-deterministic AI verdicts, or prompt injection that only changes the optional AI opinion without crossing a documented boundary.
- Vulnerabilities in Claude, Cursor, Codex, OpenCode, Git, Python, GitHub, or another upstream dependency. Report those to the upstream project.
- The documented behavior of `--unsafe-install`, which intentionally permits installation despite blocking findings.
- The documented behavior of `--show-ai-inputs`, which intentionally prints the complete AI-review prompt and deterministic inventory.
- Cursor's trusted mode or OpenCode's lack of an explicit sandbox in the invocation used here. Those are known limitations described below.
- Malicious behavior that happens after installation inside the host agent. Skills Manager scans and copies skills; it is not a runtime sandbox for Claude, Cursor, Codex, or OpenCode.
- Availability failures caused only by a network provider, GitHub, or an AI service.
- Token-estimation differences. Context estimates are heuristics, not exact tokenizer output.
- Reports that require testing against systems or repositories without authorization.

## Security model and trust boundaries

Skills Manager is a pre-installation security gate. It reduces risk; it does not prove that a skill is safe.

### Deterministic review is the primary gate

The static scanner inventories the complete selected source tree and checks files, recursive references, bounded archive contents, executable surfaces, hidden configuration, persistence hooks, dependency pinning, registry changes, native loading, environment access, Unicode deception, manifest capability contracts, source-to-sink behavior, and scanner-evasion patterns. It reads untrusted content but does not execute bundled skill code or extract archives to disk.

Install and update use `--minimum-accepted-severity medium` by default. Low and medium findings are accepted; high and critical findings block the operation. You can tighten or relax that ceiling explicitly. `--unsafe-install` bypasses the install gate and should be treated as accepting the full risk of the source.

Scan and install support explicit exclusions after manual review. `--exclude RULE` suppresses one stable scanner rule while retaining the matching content. `--exclude-path GLOB` removes matching source-relative content from both the scan and installed copy. Exclusions are included in result JSON; install exclusions are also stored in tracking metadata and reapplied during updates. Treat either option as a scoped policy exception and review it whenever the source changes.

Built-in `strict`, `balanced`, and `permissive` scanner profiles and versioned JSON policy files can raise or tune non-blocking findings. Policy files cannot disable a blocking deterministic rule or lower its severity. Versioned external signature packs are validated before scanning, reject duplicate IDs and unsafe nested-quantifier forms, and are reported with the active policy fingerprint. These controls do not make third-party regular expressions a substitute for source review.

`--sarif PATH` exports the normalized result as SARIF 2.1.0. Treat SARIF and JSON artifacts as sensitive: paths, snippets, domains, and finding metadata may describe confidential source. Provider credentials are redacted and fingerprinted rather than copied into finding metadata.

`--force-run-ai-checks` does not override a deterministic block. It only runs the optional AI review so you can collect a second opinion on an already-blocked source.

### AI review is optional and agent-dependent

When you enable `--ai-checks`, Skills Manager passes source material, a deterministic inventory, and a review prompt to the selected local agent CLI. That CLI may send the material to its model provider under its own configuration and data policy. The subprocess inherits the caller's environment, including credentials required by the agent CLI; use a minimal, low-privilege environment for untrusted reviews.

Isolation is not identical across supported agents:

| Agent | Invocation boundary |
| --- | --- |
| Claude | Safe mode with a read-only tool allowlist for the review directories |
| Codex | Ephemeral execution with a workspace-write sandbox and no approval escalation |
| Cursor | Trusted mode; broad local filesystem write access is possible |
| OpenCode | No explicit filesystem or network sandbox in the current invocation |

Prefer Claude or Codex when reviewer isolation matters. Treat Cursor and OpenCode AI review as higher-risk on a workstation containing sensitive files or credentials. The AI reviewer is additive and non-deterministic; never use it as the only security boundary.

### Installation is not runtime isolation

Approved skills are copied atomically into an agent-specific directory and receive source metadata for future update checks. Skills Manager does not control what the host agent does after loading that skill. Review the final source, pin trusted revisions where possible, and re-scan updates before applying them.

## Safer usage

Use CI mode when a machine-readable gate matters:

```bash
skills scan https://github.com/owner/repo --ci
skills analyze https://github.com/owner/repo --ci
```

Use a stricter install ceiling for environments where medium findings must also block:

```bash
skills install https://github.com/owner/repo \
  --minimum-accepted-severity low
```

Save reports only where their source paths and findings can be handled as sensitive artifacts. Run optional AI review from a low-privilege environment, especially when using an agent without a strong sandbox.
