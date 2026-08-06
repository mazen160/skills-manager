# Releasing Skills Manager

Skills Manager ships to PyPI as [`skills-manager`](https://pypi.org/project/skills-manager/). The import module is `skills_manager`. Version `1.0.0` is the first public release.

## One-time setup

Install the isolated build and upload tools:

```bash
make release-tools
```

Create a scoped PyPI API token at <https://pypi.org/manage/account/token/> and store it outside the repository. Twine reads `TWINE_USERNAME` and `TWINE_PASSWORD`, or the matching entry in `~/.pypirc`.

```ini
[pypi]
username = __token__
password = pypi-<your-token>
```

Never commit the token or `.pypirc`.

## Prepare v1.0.0

Run the complete local release gate:

```bash
make release
```

This command:

1. Confirms `pyproject.toml` and `skills_manager.__version__` agree.
2. Runs the test suite.
3. Builds a clean source archive and wheel.
4. Runs `twine check --strict` over both artifacts.
5. Installs the wheel in `.release-venv` and exercises `skill`, `skills`, `skill-manager`, and `skills-manager`.

The verified artifacts are written to `dist/`:

```text
dist/skills_manager-1.0.0-py3-none-any.whl
dist/skills_manager-1.0.0.tar.gz
```

## TestPyPI

Test the upload and installation path before the production release:

```bash
make publish-test
python3 -m venv /tmp/skills-manager-testpypi
/tmp/skills-manager-testpypi/bin/pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  skills-manager==1.0.0
/tmp/skills-manager-testpypi/bin/skills --version
```

## Tag and publish

Commit the release files before creating the tag:

```bash
git add pyproject.toml skills_manager.py tests/test_skills_manager.py \
  Makefile MANIFEST.in README.md RELEASING.md CHANGELOG.md \
  RELEASE_NOTES.md TWEET_THREAD.md .gitignore
git commit -m "release: v1.0.0"
git tag -a v1.0.0 -m "v1.0.0"
git push origin main v1.0.0
```

Upload the exact verified version. The confirmation value prevents an accidental production upload:

```bash
make publish CONFIRM_VERSION=1.0.0
```

Create the GitHub release from the reviewed notes:

```bash
gh release create v1.0.0 \
  --title "Skills Manager v1.0.0" \
  --notes-file RELEASE_NOTES.md \
  dist/skills_manager-1.0.0-py3-none-any.whl \
  dist/skills_manager-1.0.0.tar.gz
```

## Verify production

Install from PyPI into another clean environment:

```bash
python3 -m venv /tmp/skills-manager-pypi
/tmp/skills-manager-pypi/bin/pip install skills-manager==1.0.0
/tmp/skills-manager-pypi/bin/skill --version
/tmp/skills-manager-pypi/bin/skills --version
/tmp/skills-manager-pypi/bin/skill-manager --version
/tmp/skills-manager-pypi/bin/skills-manager --version
```

PyPI does not allow replacing files for an existing version. If an artifact is wrong after upload, increment the version and publish a new release.
