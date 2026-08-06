# Skills Manager v1.0.0

Installing an agent skill means trusting its Markdown, scripts, and bundled files with the same access your coding agent has. Skills Manager puts a security decision before that copy step, then keeps the skill traceable through updates and removal. Version 1.0.0 is the first public release.

## Scan before a skill touches your config

Every scan starts with deterministic checks for secrets, executable payloads, persistence, registry rewrites, filesystem tricks, archives, and scanner evasion. High and critical findings block installation.

```sh
skills scan https://github.com/owner/repo
```

Add `--ai-checks` when you want Claude, Cursor, Codex, or OpenCode to review the same source in a restricted sandbox. The AI findings are merged into the report, but they cannot overrule a static block.

```sh
skills scan https://github.com/owner/repo --ai-checks --agent codex
```

## Manage the full skill lifecycle

Skills Manager installs from GitHub or local folders, discovers skills recursively in monorepos, and records where each installed skill came from. You can list skills across supported agents, compare them with their original sources, apply rescanned updates, and preview an uninstall before deleting anything.

```sh
skills install https://github.com/owner/repo --recursive
skills list --verbose
skills update --apply
skills uninstall my-skill
```

Installing the package gives you four equivalent commands: `skill`, `skills`, `skill-manager`, and `skills-manager`.

## Measure context cost

`skills analyze cost` estimates how much context each skill consumes at catalog load, activation, and full-directory load. The same pass catches malformed front matter, broken relative links, missing metadata, invalid UTF-8, and oversized files.

```sh
skills analyze cost ~/.claude/skills ~/.codex/skills --load-mode full
```

## Use it in CI

`skills scan --ci` prints a one-line JSON verdict to stdout, writes findings to stderr, and exits non-zero for an unsafe source. Add `--output` to keep the full report as a build artifact.

```sh
skills scan https://github.com/owner/repo --ci --output result.json
```

## Install

```sh
python3 -m pip install agentic-skills-manager==1.0.0
skills --version
```

Skills Manager is a single Python module with no runtime dependencies. It requires Python 3.9 or newer and Git for remote sources.

## Credits

Built by [Mazin Ahmed](https://github.com/mazen160).

---

Full source: <https://github.com/mazen160/skills-manager/tree/v1.0.0>
