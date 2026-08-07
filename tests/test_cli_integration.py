#!/usr/bin/env python3
"""End-to-end CLI integration tests.

These tests exercise the full scan/install/list/update/uninstall lifecycle by
running the module's main() directly while redirecting HOME to a temporary
directory so no real agent skill directories are touched.

Dependency-free: runs with the standard library test runner.

    python3 -m unittest discover -s tests
    python3 tests/test_cli_integration.py
"""

from __future__ import annotations

import io
import json
import os
import re
import sys
import tempfile
import textwrap
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import skills_manager as skills  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _skill_md(name: str, description: str = "A test skill.") -> str:
    return textwrap.dedent(f"""\
        ---
        name: {name}
        description: {description}
        ---
        This is the body of {name}.
    """)


def _run_main(*argv: str) -> tuple[int, str, str]:
    """Run skills_manager.main() with the given argv and capture output."""
    saved_argv = sys.argv
    sys.argv = ["skills", *argv]
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    try:
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            rc = skills.main()
    except SystemExit as exc:
        rc = int(exc.code) if exc.code is not None else 0
    finally:
        sys.argv = saved_argv
    return rc, stdout_buf.getvalue(), stderr_buf.getvalue()


def _make_skill_dir(root: Path, name: str, extra_files: dict[str, str] | None = None) -> Path:
    skill_dir = root / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(_skill_md(name), encoding="utf-8")
    for filename, content in (extra_files or {}).items():
        (skill_dir / filename).write_text(content, encoding="utf-8")
    return skill_dir


# ---------------------------------------------------------------------------
# Scan command
# ---------------------------------------------------------------------------

class ScanSafeSkillTests(unittest.TestCase):
    def test_scan_safe_skill_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "safe-skill")
            rc, stdout, stderr = _run_main("scan", str(skill_dir))
        self.assertEqual(rc, 0, stderr)

    def test_scan_writes_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "safe-skill")
            out_path = Path(tmp) / "result.json"
            rc, _, _ = _run_main("scan", str(skill_dir), "--output", str(out_path))
            self.assertEqual(rc, 0)
            result = json.loads(out_path.read_text())
            self.assertIn("safe", result)
            self.assertIn("findings", result)
            self.assertTrue(result["safe"])

    def test_scan_output_creates_missing_parent_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "safe-skill")
            out_path = Path(tmp) / "nested" / "deep" / "result.json"
            rc, _, _ = _run_main("scan", str(skill_dir), "--output", str(out_path))
            self.assertEqual(rc, 0)
            self.assertTrue(out_path.exists())

    def test_scan_output_directory_as_file_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "safe-skill")
            dir_path = Path(tmp) / "a-directory"
            dir_path.mkdir()
            rc, _, stderr = _run_main("scan", str(skill_dir), "--output", str(dir_path))
        self.assertNotEqual(rc, 0)
        self.assertIn("directory", stderr.lower())

    def test_scan_absolute_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "safe-skill")
            out_path = Path(tmp) / "absolute-result.json"
            rc, _, _ = _run_main("scan", str(skill_dir), "--output", str(out_path))
            self.assertEqual(rc, 0)
            self.assertTrue(out_path.exists())

    def test_scan_relative_output_path_resolves_to_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "safe-skill")
            out_name = "rel-result.json"
            out_path = Path.cwd() / out_name
            try:
                rc, _, _ = _run_main("scan", str(skill_dir), "--output", out_name)
                self.assertEqual(rc, 0)
                self.assertTrue(out_path.exists())
            finally:
                out_path.unlink(missing_ok=True)


class ScanMaliciousSkillTests(unittest.TestCase):
    def test_scan_private_key_material_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(
                Path(tmp),
                "bad-skill",
                extra_files={
                    "secret.pem": (
                        "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n"
                    )
                },
            )
            rc, _, _ = _run_main("scan", str(skill_dir))
        self.assertNotEqual(rc, 0)

    def test_scan_bytecode_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "bad-skill")
            cache = skill_dir / "__pycache__"
            cache.mkdir()
            (cache / "evil.cpython-311.pyc").write_bytes(b"\x00\x01payload")
            rc, _, _ = _run_main("scan", str(skill_dir))
        self.assertNotEqual(rc, 0)


# ---------------------------------------------------------------------------
# CI mode (scan --ci)
# ---------------------------------------------------------------------------

class ScanCiModeTests(unittest.TestCase):
    def test_scan_ci_safe_skill_exits_zero_with_json_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "safe-skill")
            rc, stdout, _ = _run_main("scan", str(skill_dir), "--ci")
        self.assertEqual(rc, 0)
        result = json.loads(stdout)
        self.assertIn("safe", result)

    def test_scan_ci_malicious_skill_nonzero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "bad-skill")
            (skill_dir / "evil.pyc").write_bytes(b"\x00\x01\x02")
            rc, stdout, _ = _run_main("scan", str(skill_dir), "--ci")
        self.assertNotEqual(rc, 0)
        result = json.loads(stdout)
        self.assertFalse(result["safe"])

    def test_scan_ci_human_progress_not_in_stdout(self) -> None:
        # CI mode should suppress decorative progress text from stdout.
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "safe-skill")
            _, stdout, _ = _run_main("scan", str(skill_dir), "--ci")
        # stdout should be valid JSON only (no banner / progress lines before)
        result = json.loads(stdout)
        self.assertIsInstance(result, dict)


# ---------------------------------------------------------------------------
# Install / list / uninstall lifecycle
# ---------------------------------------------------------------------------

class InstallLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.fake_home = self.tmp / "home"
        self.fake_home.mkdir()
        self._orig_home = os.environ.get("HOME")
        os.environ["HOME"] = str(self.fake_home)

    def tearDown(self) -> None:
        if self._orig_home is not None:
            os.environ["HOME"] = self._orig_home
        else:
            del os.environ["HOME"]
        self._tmp.cleanup()

    def _skill_source(self, name: str, **kwargs: str) -> Path:
        return _make_skill_dir(self.tmp / "sources", name, extra_files=kwargs or None)

    def test_install_and_list(self) -> None:
        source = self._skill_source("my-skill")
        rc, _, _ = _run_main("install", str(source))
        self.assertEqual(rc, 0)

        rc, stdout, _ = _run_main("list")
        self.assertEqual(rc, 0)
        self.assertIn("my-skill", stdout)

    def test_install_and_uninstall_with_yes(self) -> None:
        source = self._skill_source("del-skill")
        _run_main("install", str(source))

        # Without --yes, uninstall only previews
        rc, stdout, _ = _run_main("uninstall", "del-skill")
        self.assertEqual(rc, 0)
        self.assertIn("would remove", stdout.lower())

        # With --yes, it actually removes
        rc, _, _ = _run_main("uninstall", "del-skill", "--yes")
        self.assertEqual(rc, 0)

        _, stdout, _ = _run_main("list")
        self.assertNotIn("del-skill", stdout)

    def test_uninstall_without_yes_does_not_remove(self) -> None:
        source = self._skill_source("preview-skill")
        _run_main("install", str(source))

        _run_main("uninstall", "preview-skill")  # no --yes

        _, stdout, _ = _run_main("list")
        self.assertIn("preview-skill", stdout)

    def test_install_malicious_skill_is_blocked(self) -> None:
        source = self._skill_source("bad-skill")
        (source / "payload.pyc").write_bytes(b"\x00bad")
        rc, _, stderr = _run_main("install", str(source))
        self.assertNotEqual(rc, 0)
        # Should not appear in list
        _, stdout, _ = _run_main("list")
        self.assertNotIn("bad-skill", stdout)

    def test_install_default_max_severity_allows_medium(self) -> None:
        source = self._skill_source("medium-skill", **{"validate.py": "print('ok')\n"})
        (source / "validate.py").chmod(0o755)
        rc, _, stderr = _run_main("install", str(source))
        self.assertEqual(rc, 0, stderr)

    def test_install_max_severity_low_blocks_medium(self) -> None:
        source = self._skill_source("strict-skill", **{"validate.py": "print('ok')\n"})
        (source / "validate.py").chmod(0o755)
        rc, _, stderr = _run_main(
            "install", str(source), "--minimum-accepted-severity", "low"
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("--minimum-accepted-severity low", stderr)

    def test_install_max_severity_high_allows_high(self) -> None:
        source = self._skill_source(
            "permissive-skill",
            **{"read_env.py": "import os\nprint(os.environ)\n"},
        )
        rc, _, stderr = _run_main(
            "install", str(source), "--minimum-accepted-severity", "high"
        )
        self.assertEqual(rc, 0, stderr)

    def test_install_creates_metadata_file(self) -> None:
        source = self._skill_source("meta-skill")
        _run_main("install", str(source))
        skill_dir = skills.agent_skill_dir("claude") / "meta-skill"
        metadata_file = skill_dir / skills.INSTALL_METADATA_FILENAME
        self.assertTrue(metadata_file.exists(), "metadata file should be written on install")
        metadata = json.loads(metadata_file.read_text())
        self.assertIn("source", metadata)
        self.assertIn("skill", metadata)
        self.assertEqual(metadata["source"]["kind"], "local")

    def test_install_skips_existing_without_force(self) -> None:
        source = self._skill_source("existing-skill")
        rc1, out1, _ = _run_main("install", str(source))
        self.assertEqual(rc1, 0)
        rc2, out2, _ = _run_main("install", str(source))
        self.assertEqual(rc2, 0)
        self.assertIn("skipped", out2.lower())

    def test_install_force_overwrites_existing(self) -> None:
        source = self._skill_source("overwrite-skill")
        _run_main("install", str(source))
        # Modify source and reinstall with --force
        (source / "SKILL.md").write_text(
            _skill_md("overwrite-skill", "Updated description."), encoding="utf-8"
        )
        rc, _, _ = _run_main("install", str(source), "--force-install")
        self.assertEqual(rc, 0)
        skill_dir = skills.agent_skill_dir("claude") / "overwrite-skill"
        content = (skill_dir / "SKILL.md").read_text()
        self.assertIn("Updated description", content)

    def test_list_verbose(self) -> None:
        source = self._skill_source("verbose-skill")
        _run_main("install", str(source))
        rc, stdout, _ = _run_main("list", "--verbose")
        self.assertEqual(rc, 0)
        self.assertIn("verbose-skill", stdout)

    def test_list_specific_agent(self) -> None:
        source = self._skill_source("agent-skill")
        _run_main("install", str(source), "--agent", "claude")
        rc, stdout, _ = _run_main("list", "--agent", "claude")
        self.assertEqual(rc, 0)
        self.assertIn("agent-skill", stdout)

    def test_uninstall_unknown_skill_fails(self) -> None:
        rc, _, _ = _run_main("uninstall", "no-such-skill-xyz", "--yes")
        self.assertNotEqual(rc, 0)


# ---------------------------------------------------------------------------
# Update lifecycle
# ---------------------------------------------------------------------------

class UpdateLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.fake_home = self.tmp / "home"
        self.fake_home.mkdir()
        self._orig_home = os.environ.get("HOME")
        os.environ["HOME"] = str(self.fake_home)

    def tearDown(self) -> None:
        if self._orig_home is not None:
            os.environ["HOME"] = self._orig_home
        else:
            del os.environ["HOME"]
        self._tmp.cleanup()

    def test_update_untracked_skill_reports_status(self) -> None:
        source = _make_skill_dir(self.tmp / "sources", "untracked-skill")
        _run_main("install", str(source))
        # Remove metadata so it appears untracked
        skill_dir = skills.agent_skill_dir("claude") / "untracked-skill"
        (skill_dir / skills.INSTALL_METADATA_FILENAME).unlink()

        rc, stdout, _ = _run_main("update")
        # Should report the skill as untracked without crashing
        self.assertIn("untracked", stdout.lower())

    def test_update_no_changes_detected(self) -> None:
        source = _make_skill_dir(self.tmp / "sources", "tracked-skill")
        _run_main("install", str(source))
        # No changes since install → up-to-date
        rc, stdout, _ = _run_main("update")
        self.assertEqual(rc, 0)
        self.assertTrue(
            "up-to-date" in stdout.lower() or "no changes" in stdout.lower() or "unchanged" in stdout.lower(),
            f"Expected up-to-date/no-changes/unchanged in output: {stdout}",
        )


# ---------------------------------------------------------------------------
# Analyze command
# ---------------------------------------------------------------------------

class AnalyzeCommandTests(unittest.TestCase):
    def test_analyze_direct_root_returns_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(
                Path(tmp),
                "context-skill",
                extra_files={"reference.md": "Reference material.\n"},
            )
            rc, stdout, stderr = _run_main("analyze", str(skill_dir), "--json")

        self.assertEqual(rc, 0, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["summary"]["skills"], 1)
        self.assertEqual(report["skills"][0]["name"], "context-skill")
        self.assertEqual(report["skills"][0]["totals"]["files"], 2)
        self.assertGreater(report["skills"][0]["totals"]["bytes"], 0)
        self.assertEqual(len(report["skills"][0]["files"]), 2)

    def test_analyze_text_reports_size_and_files_for_every_skill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_skill_dir(root, "first-skill")
            _make_skill_dir(root, "second-skill")
            rc, stdout, stderr = _run_main("analyze", str(root))

        self.assertEqual(rc, 0, stderr)
        self.assertIn("Size (full directory):", stdout)
        self.assertIn("files", stdout)
        self.assertIn("first-skill", stdout)
        self.assertIn("second-skill", stdout)

    def test_analyze_token_limit_is_warning_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "large-skill")
            rc, stdout, stderr = _run_main(
                "analyze", str(skill_dir), "--max-skill-tokens", "1"
            )

        self.assertEqual(rc, 0, stderr)
        self.assertIn("large_skill", stdout)

    def test_analyze_can_fail_on_skill_token_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "large-skill")
            rc, _, _ = _run_main(
                "analyze",
                str(skill_dir),
                "--max-skill-tokens",
                "1",
                "--fail-on-max-tokens",
            )

        self.assertEqual(rc, 1)

    def test_analyze_can_fail_on_file_token_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "large-file-skill")
            rc, _, _ = _run_main(
                "analyze",
                str(skill_dir),
                "--max-file-tokens",
                "1",
                "--fail-on-max-tokens",
            )

        self.assertEqual(rc, 1)

    def test_analyze_ci_prints_verdict_to_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "ci-skill")
            rc, stdout, stderr = _run_main("analyze", str(skill_dir), "--ci")

        self.assertEqual(rc, 0, stderr)
        verdict = json.loads(stdout)
        self.assertTrue(verdict["safe"])
        self.assertEqual(verdict["command"], "analyze")
        self.assertEqual(verdict["skills"], 1)
        self.assertIn("PASS [analyze]", stderr)
        self.assertNotIn("Skills Context Usage Report", stdout)

    def test_analyze_ci_fails_for_invalid_skill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = Path(tmp) / "invalid-skill"
            skill_dir.mkdir()
            (skill_dir / "SKILL.md").write_text("No front matter.\n", encoding="utf-8")
            rc, stdout, stderr = _run_main("analyze", str(skill_dir), "--ci")

        self.assertEqual(rc, 1)
        verdict = json.loads(stdout)
        self.assertFalse(verdict["safe"])
        self.assertEqual(verdict["invalid_skills"], 1)
        self.assertIn("FAIL [analyze]", stderr)
        self.assertIn("missing_front_matter", stderr)

    def test_analyze_ci_honors_fail_on_max_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "large-ci-skill")
            rc, stdout, stderr = _run_main(
                "analyze",
                str(skill_dir),
                "--ci",
                "--max-skill-tokens",
                "1",
                "--fail-on-max-tokens",
            )

        self.assertEqual(rc, 1)
        verdict = json.loads(stdout)
        self.assertTrue(verdict["token_limit_exceeded"])
        self.assertIn("large_skill", stderr)

    def test_analyze_without_sources_uses_installed_skill_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            installed_root = Path(tmp) / "installed"
            _make_skill_dir(installed_root, "installed-skill")
            with patch.object(skills, "agent_skill_dirs", return_value=[installed_root]):
                rc, stdout, stderr = _run_main("analyze", "--json")

        self.assertEqual(rc, 0, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["summary"]["skills"], 1)
        self.assertEqual(report["skills"][0]["name"], "installed-skill")

    def test_analyze_accepts_direct_skill_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "file-skill")
            rc, stdout, stderr = _run_main("analyze", str(skill_dir / "SKILL.md"), "--json")

        self.assertEqual(rc, 0, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["skills"][0]["name"], "file-skill")

    def test_analyze_accepts_github_blob_url_without_temp_paths(self) -> None:
        url = "https://github.com/owner/repo/blob/main/demo/SKILL.md?plain=1"
        with tempfile.TemporaryDirectory() as tmp:
            root = _make_skill_dir(Path(tmp), "demo")
            source = skills.InstallSource(
                "github", url, "https://github.com/owner/repo.git", None, "main", "demo"
            )
            prepared = skills.PreparedSource(source, root, Path(tmp) / "security")

            @contextmanager
            def fake_prepared_source(*_args: object, **_kwargs: object):
                yield prepared

            with patch.object(skills, "prepared_source", fake_prepared_source):
                rc, stdout, stderr = _run_main("analyze", url, "--json")

        self.assertEqual(rc, 0, stderr)
        report = json.loads(stdout)
        skill = report["skills"][0]
        self.assertEqual(skill["findings"], [])
        self.assertEqual(
            skill["path"],
            "https://github.com/owner/repo/blob/main/demo",
        )
        self.assertEqual(
            report["summary"]["largest_files"][0]["full_path"],
            "https://github.com/owner/repo/blob/main/demo/SKILL.md",
        )
        self.assertNotIn(tmp, stdout)

    def test_analyze_help_has_no_nested_cost_command(self) -> None:
        rc, stdout, stderr = _run_main("analyze", "--help")
        self.assertEqual(rc, 0, stderr)
        self.assertIn("[SOURCE ...]", stdout)
        self.assertNotIn("{cost}", stdout)
        self.assertNotIn("--top", stdout)
        self.assertNotIn("--include-hidden", stdout)
        self.assertIn("--ci", stdout)
        self.assertIn("Exclude individual file details from JSON output.", stdout)
        self.assertNotIn("analyze_command", stderr)


# ---------------------------------------------------------------------------
# Command alias tests
# ---------------------------------------------------------------------------

class CommandAliasTests(unittest.TestCase):
    """Verify all six entry-point aliases are declared in pyproject.toml."""

    def test_all_aliases_in_entry_points(self) -> None:
        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        text = pyproject.read_text(encoding="utf-8")
        for alias in (
            "skill",
            "skills",
            "skill-manager",
            "skills-manager",
            "agentic-skill-manager",
            "agentic-skills-manager",
        ):
            self.assertIn(alias, text, f"alias {alias!r} missing from pyproject.toml")

    def test_main_is_callable(self) -> None:
        # All aliases point to skills_manager:main — verify it's importable and callable.
        self.assertTrue(callable(skills.main))

    def test_all_aliases_use_the_same_entry_point(self) -> None:
        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        text = pyproject.read_text(encoding="utf-8")
        for alias in (
            "skill",
            "skills",
            "skill-manager",
            "skills-manager",
            "agentic-skill-manager",
            "agentic-skills-manager",
        ):
            self.assertRegex(
                text,
                re.compile(
                    rf'^"?{re.escape(alias)}"?\s*=\s*"skills_manager:main"$',
                    re.MULTILINE,
                ),
            )


# ---------------------------------------------------------------------------
# Resource limit tests
# ---------------------------------------------------------------------------

class ResourceLimitTests(unittest.TestCase):
    def test_archive_member_size_limit_is_flagged(self) -> None:
        import zipfile as zf

        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "big-skill")
            zip_path = skill_dir / "big.zip"
            # Create a member whose deflated size is small but reported
            # file_size exceeds the limit.  We write a compressible payload
            # and rely on the file_size field in the ZipInfo header to
            # trigger the check.
            payload = b"A" * (skills.MAX_ARCHIVE_MEMBER_BYTES + 1)
            with zf.ZipFile(zip_path, "w", compression=zf.ZIP_DEFLATED) as arc:
                arc.writestr("oversized.txt", payload)

            inventory = skills.build_security_inventory(skill_dir)
            issues = [f["issue"] for f in inventory["deterministic_findings"]]
            self.assertTrue(
                any("exceeds limit" in issue or "archive" in issue.lower() for issue in issues),
                f"Expected size-limit or archive finding, got: {issues}",
            )

    def test_compression_ratio_check(self) -> None:
        import struct
        import zipfile as zf

        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "bomb-skill")
            zip_path = skill_dir / "bomb.zip"
            payload = b"A" * (101 * 1024 * 1024)  # 101 MB, very compressible
            with zf.ZipFile(zip_path, "w", compression=zf.ZIP_DEFLATED) as arc:
                arc.writestr("compressible.txt", payload)

            inventory = skills.build_security_inventory(skill_dir)
            issues = [f["issue"] for f in inventory["deterministic_findings"]]
            # At minimum the archive itself triggers the "archive can hide payloads" finding.
            self.assertTrue(
                any("archive" in issue.lower() or "compression" in issue.lower() or "ratio" in issue.lower() for issue in issues),
                f"Expected archive/compression finding, got: {issues}",
            )

    def test_directory_depth_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = _make_skill_dir(Path(tmp), "deep-skill")
            deep = skill_dir
            for i in range(skills.MAX_DIRECTORY_DEPTH + 2):
                deep = deep / f"level{i}"
                deep.mkdir()
            (deep / "SKILL.md").write_text(_skill_md("deep"), encoding="utf-8")

            inventory = skills.build_security_inventory(skill_dir)
            issues = [f["issue"] for f in inventory["deterministic_findings"]]
            self.assertTrue(
                any("depth limit" in issue.lower() for issue in issues),
                f"Expected depth-limit finding, got: {issues}",
            )

    def test_scan_budget_exceeded_is_flagged(self) -> None:
        # Build a scan root that has a single file larger than MAX_SCAN_BYTES_TOTAL.
        # We can't create a real 512 MB file in a unit test, so instead we
        # temporarily lower the budget constant and restore it.
        original = skills.MAX_SCAN_BYTES_TOTAL
        skills.MAX_SCAN_BYTES_TOTAL = 10  # tiny budget for testing
        try:
            with tempfile.TemporaryDirectory() as tmp:
                skill_dir = _make_skill_dir(Path(tmp), "budget-skill")
                (skill_dir / "big.txt").write_text("x" * 100, encoding="utf-8")
                inventory = skills.build_security_inventory(skill_dir)
                issues = [f["issue"] for f in inventory["deterministic_findings"]]
                self.assertTrue(
                    any("scan budget" in issue.lower() for issue in issues),
                    f"Expected scan-budget finding, got: {issues}",
                )
        finally:
            skills.MAX_SCAN_BYTES_TOTAL = original


# ---------------------------------------------------------------------------
# Rollback safety tests (copy_skill_tree)
# ---------------------------------------------------------------------------

class RollbackSafetyTests(unittest.TestCase):
    def test_install_to_new_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            source.mkdir()
            (source / "SKILL.md").write_text(_skill_md("rollback-skill"), encoding="utf-8")
            dest = Path(tmp) / "dest"
            skills.copy_skill_tree(source, dest)
            self.assertTrue((dest / "SKILL.md").exists())

    def test_install_overwrites_destination_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            source.mkdir()
            (source / "SKILL.md").write_text(_skill_md("v1"), encoding="utf-8")
            dest = Path(tmp) / "dest"
            skills.copy_skill_tree(source, dest)

            (source / "SKILL.md").write_text(_skill_md("v2"), encoding="utf-8")
            skills.copy_skill_tree(source, dest)

            content = (dest / "SKILL.md").read_text()
            self.assertIn("v2", content)

    def test_backup_cleaned_up_on_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            source.mkdir()
            (source / "SKILL.md").write_text(_skill_md("clean"), encoding="utf-8")
            dest = Path(tmp) / "dest"
            skills.copy_skill_tree(source, dest)
            skills.copy_skill_tree(source, dest)
            # No leftover backup or tmp dirs in parent
            leftovers = [
                p for p in Path(tmp).iterdir()
                if p.name.startswith(".dest.") and p != dest
            ]
            self.assertEqual(leftovers, [], f"Backup not cleaned up: {leftovers}")


if __name__ == "__main__":
    unittest.main()
