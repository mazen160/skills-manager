# Contributing to Skills Manager

Thank you for taking the time to contribute.

## Prerequisites

- Python 3.9 or later
- No third-party dependencies required

## Setting up a development environment

```bash
git clone https://github.com/mazen160/skills-manager.git
cd skills-manager
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"     # or: pip install build twine
```

## Running the tests

```bash
python -m unittest discover -s tests -v
```

The test suite is dependency-free and runs against the standard library only.

## Code style

- Dependency-free Python 3.9+ compatible code only (no third-party imports)
- Follow the existing style: type annotations, `dataclass`, `pathlib.Path`
- No comments that describe *what* the code does — only *why* (non-obvious constraints, invariants, workarounds)

## Security-sensitive changes

All changes that touch the scanner, sandbox flags, archive handling, or install paths require extra care:

- Static-gate changes: high/critical findings must always block installation
- Sandbox changes: the AI reviewer must not gain write access to the source being reviewed
- Archive scanner: fail closed on unreadable or pathological archives

If you discover a security issue, please follow the [Security Policy](SECURITY.md) instead of opening a public issue.

## Submitting a pull request

1. Fork the repository and create a feature branch.
2. Write or update tests for your change.
3. Run `python -m unittest discover -s tests -v` and confirm all tests pass.
4. Run `python -m build --wheel --sdist && twine check dist/*` to verify packaging.
5. Open a pull request with a clear description of the change and the motivation.

## Reporting bugs

Open a GitHub Issue with:
- Skills Manager version (`skills --version`)
- Python version (`python --version`)
- Operating system
- Minimal reproduction steps
