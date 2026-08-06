# Releasing

Skills Manager ships to PyPI as [`skills-manager`](https://pypi.org/project/skills-manager/). The import module is `skills_manager`.

## One-time setup

```bash
python3 -m pip install --upgrade build twine
```

Create a PyPI API token at https://pypi.org/manage/account/token/ and put it in `~/.pypirc`:

```ini
[pypi]
  username = __token__
  password = pypi-<your-token>
```

## Cut a release

1. Bump the version in `pyproject.toml` (`[project] version`).
2. Build the sdist and wheel:

```bash
rm -rf dist build *.egg-info
python3 -m build
```

3. Check the artifacts:

```bash
python3 -m twine check dist/*
```

4. Smoke-test the wheel in a clean environment:

```bash
python3 -m venv /tmp/skills-test
/tmp/skills-test/bin/pip install dist/skills_manager-*.whl
/tmp/skills-test/bin/skills --help
/tmp/skills-test/bin/skill --banner
/tmp/skills-test/bin/skill-manager --banner
/tmp/skills-test/bin/skills-manager --banner
```

5. (Optional) Upload to TestPyPI first:

```bash
python3 -m twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ skills-manager
```

6. Upload to PyPI:

```bash
python3 -m twine upload dist/*
```

7. Tag the release:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

## After release

```bash
pip install skills-manager
skills --help
skill --help
skill-manager --help
skills-manager --help
```

Installing the package puts four equivalent commands on `PATH`: `skill`, `skills`, `skill-manager`, and `skills-manager`.
