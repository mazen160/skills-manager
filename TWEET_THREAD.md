# Launch-day thread for Skills Manager v1.0.0

## 1/6 - hook

Installing an AI agent skill means trusting its Markdown, scripts, and bundled files with your agent's access. Skills Manager scans that source before it touches your config.

[character count: 174]

---

## 2/6 - security scanning

Every scan checks for secrets, dangerous shell execution, persistence, registry rewrites, opaque payloads, archive tricks, and scanner evasion. High and critical findings block the install.

[character count: 189]

---

## 3/6 - AI review

Add --ai-checks and Claude, Cursor, Codex, or OpenCode reviews the source in a restricted sandbox. Its findings are merged with the static report, but an AI verdict can never override a deterministic block.

[character count: 206]

---

## 4/6 - lifecycle

Skills Manager handles the whole lifecycle: scan, install, list, update, uninstall. It works across Claude, Cursor, Codex, and OpenCode, and tracks every installed skill back to its source.

[character count: 189]

---

## 5/6 - context cost

Skills consume context too. skills analyze cost estimates catalog, activation, and full-directory usage, then flags malformed front matter, broken links, missing metadata, and oversized files.

[character count: 192]

---

## 6/6 - try it

Skills Manager v1.0.0 is one Python file with no runtime dependencies. Install it with: pip install agentic-skills-manager

https://github.com/mazen160/skills-manager

[character count: 165]
