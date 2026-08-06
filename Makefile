SHELL := /bin/sh

PYTHON ?= python3
DIST_DIR := dist
SMOKE_VENV := .release-venv
VERSION := $(shell sed -n 's/^version = "\([^"]*\)"/\1/p' pyproject.toml)
MODULE_VERSION := $(shell $(PYTHON) -c 'import skills_manager; print(skills_manager.__version__)')
WHEEL := $(DIST_DIR)/agentic_skills_manager-$(VERSION)-py3-none-any.whl

.DEFAULT_GOAL := help

.PHONY: help version release-tools verify-version test clean build check smoke release publish-test publish

help:
	@printf '%s\n' \
		'Skills Manager release commands:' \
		'  make test          Run the standard-library test suite' \
		'  make build         Build a clean source archive and wheel' \
		'  make check         Build and validate both distributions' \
		'  make smoke         Install the wheel and exercise all four commands' \
		'  make release       Run the complete release check without uploading' \
		'  make publish-test  Upload verified artifacts to TestPyPI' \
		'  make publish CONFIRM_VERSION=$(VERSION)' \
		'                     Upload verified artifacts to production PyPI'

version:
	@printf '%s\n' '$(VERSION)'

release-tools:
	$(PYTHON) -m pip install --upgrade build twine

verify-version:
	@test -n '$(VERSION)' || (printf '%s\n' 'Could not read the package version from pyproject.toml.' >&2; exit 1)
	@test '$(VERSION)' = '$(MODULE_VERSION)' || (printf '%s\n' 'Version mismatch: pyproject.toml=$(VERSION), skills_manager.py=$(MODULE_VERSION)' >&2; exit 1)

test: verify-version
	$(PYTHON) -m unittest discover -s tests

clean:
	rm -rf build dist skills_manager.egg-info

build: clean test
	$(PYTHON) -m build

check: build
	@test -f '$(DIST_DIR)/agentic_skills_manager-$(VERSION).tar.gz'
	@test -f '$(WHEEL)'
	$(PYTHON) -m twine check --strict $(DIST_DIR)/*

smoke: check
	$(PYTHON) -m venv --clear '$(SMOKE_VENV)'
	$(SMOKE_VENV)/bin/python -m pip install --disable-pip-version-check '$(WHEEL)'
	$(SMOKE_VENV)/bin/python -c 'import skills_manager; assert skills_manager.__version__ == "$(VERSION)"'
	$(SMOKE_VENV)/bin/skill --version
	$(SMOKE_VENV)/bin/skills --version
	$(SMOKE_VENV)/bin/skill-manager --version
	$(SMOKE_VENV)/bin/skills-manager --version
	$(SMOKE_VENV)/bin/skills --banner >/dev/null

release: smoke
	@printf '%s\n' 'Release $(VERSION) is built and verified in $(DIST_DIR)/.'

publish-test: release
	$(PYTHON) -m twine upload --repository testpypi $(DIST_DIR)/*

publish: release
	@test '$(CONFIRM_VERSION)' = '$(VERSION)' || (printf '%s\n' 'Refusing production upload. Run: make publish CONFIRM_VERSION=$(VERSION)' >&2; exit 1)
	$(PYTHON) -m twine upload $(DIST_DIR)/*
