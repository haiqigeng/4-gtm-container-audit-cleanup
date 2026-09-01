from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
FAKE_FIRST = "/".join(("scripts", "first.py"))
FAKE_SECOND = "/".join(("scripts", "second.py"))
FAKE_NESTED_SECOND = "/".join(("scripts", "nested", "second.py"))
FAKE_UNEXPECTED = "/".join(("scripts", "unexpected.py"))

import build_skill_package  # noqa: E402
import gtm_self_test  # noqa: E402
import gtm_skill_identity as skill_identity  # noqa: E402
import gtm_vendor_registry as vendor_registry  # noqa: E402
from check_release import (  # noqa: E402
    coverage_profile_minimums,
    python_trust_boundary_coverage_report,
)


def coverage_payload(
    paths: list[str],
    *,
    branch_coverage: bool = True,
    percentage: float = 100.0,
) -> dict[str, object]:
    return {
        "meta": {"branch_coverage": branch_coverage},
        "files": {
            path: {
                "summary": {
                    "percent_covered": percentage,
                    "num_branches": 2,
                    "covered_branches": 2,
                }
            }
            for path in paths
        },
        "totals": {
            "percent_covered": percentage,
            "num_branches": 4,
            "covered_branches": 4,
        },
    }


def write_identity_fixture(root: Path, marker: str = "same") -> None:
    (root / "agents").mkdir(parents=True)
    (root / "references").mkdir()
    (root / "scripts").mkdir()
    (root / "SKILL.md").write_text(f"# Skill {marker}\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "2.0.0"\n', encoding="utf-8"
    )
    (root / "agents" / "openai.yaml").write_text("name: fixture\n", encoding="utf-8")
    (root / "references" / "rule.md").write_text("# Rule\n", encoding="utf-8")
    (root / "scripts" / "runtime.py").write_text("VALUE = 1\n", encoding="utf-8")


class RuntimeIdentityGateTests(unittest.TestCase):
    def test_identity_verification_reports_exact_runtime_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = root / "expected"
            actual = root / "actual"
            write_identity_fixture(expected)
            write_identity_fixture(actual)
            declared = skill_identity.write_manifest(actual)
            declared["source_git_dirty"] = False
            (actual / skill_identity.MANIFEST_NAME).write_text(
                json.dumps(declared, indent=2) + "\n", encoding="utf-8"
            )
            report, errors = skill_identity.verify_identity(expected, actual)
            self.assertEqual([], errors)
            self.assertEqual("pass", report["status"])

            (actual / "SKILL.md").write_text("# changed\n", encoding="utf-8")
            (actual / "scripts" / "unexpected.py").write_text(
                "VALUE = 2\n", encoding="utf-8"
            )
            (actual / "references" / "rule.md").unlink()
            report, errors = skill_identity.verify_identity(expected, actual)
            self.assertEqual(["references/rule.md"], report["missing_files"])
            self.assertEqual(["scripts/unexpected.py"], report["unexpected_files"])
            self.assertEqual(["SKILL.md"], report["changed_files"])
            self.assertTrue(any("manifest" in error.lower() for error in errors))

    def test_declared_identity_and_clean_git_fallback_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_identity_fixture(root)
            report, errors = skill_identity.declared_identity_errors(root)
            self.assertEqual("fail", report["status"])
            self.assertTrue(any("missing" in error for error in errors))

            report, errors = skill_identity.declared_identity_errors(
                root, require_manifest=False
            )
            self.assertEqual([], errors)
            self.assertEqual("pass", report["status"])

            manifest_path = root / skill_identity.MANIFEST_NAME
            manifest_path.write_text("not-json", encoding="utf-8")
            _, errors = skill_identity.declared_identity_errors(root)
            self.assertTrue(any("valid JSON" in error for error in errors))

            declared = skill_identity.build_identity(root)
            declared.update(
                {
                    "kind": "wrong",
                    "schema_version": 99,
                    "source_git_dirty": True,
                    "runtime_file_count": -1,
                }
            )
            manifest_path.write_text(
                json.dumps(declared, indent=2) + "\n", encoding="utf-8"
            )
            _, errors = skill_identity.declared_identity_errors(root)
            self.assertTrue(any("kind is invalid" in error for error in errors))
            self.assertTrue(any("schema_version" in error for error in errors))
            self.assertTrue(any("runtime_file_count" in error for error in errors))
            self.assertTrue(any("dirty" in error for error in errors))

    def test_clean_git_identity_errors_cover_every_provenance_boundary(self) -> None:
        actual = {"files": {"SKILL.md": "hash", "scripts/new.py": "hash"}}
        root = Path("fixture")
        with mock.patch.object(skill_identity, "git_commit", return_value=""):
            self.assertIn(
                "no readable Git commit",
                skill_identity.clean_git_identity_errors(root, actual)[0],
            )
        with (
            mock.patch.object(skill_identity, "git_commit", return_value="commit"),
            mock.patch.object(skill_identity, "git_dirty", return_value=True),
        ):
            self.assertIn(
                "dirty", skill_identity.clean_git_identity_errors(root, actual)[0]
            )
        with (
            mock.patch.object(skill_identity, "git_commit", return_value="commit"),
            mock.patch.object(skill_identity, "git_dirty", return_value=False),
            mock.patch.object(skill_identity, "git_tracked_files", return_value=None),
        ):
            self.assertIn(
                "cannot be read",
                skill_identity.clean_git_identity_errors(root, actual)[0],
            )
        with (
            mock.patch.object(skill_identity, "git_commit", return_value="commit"),
            mock.patch.object(skill_identity, "git_dirty", return_value=False),
            mock.patch.object(
                skill_identity, "git_tracked_files", return_value={"SKILL.md"}
            ),
        ):
            self.assertIn(
                "runtime files are not tracked",
                skill_identity.clean_git_identity_errors(root, actual)[0],
            )


class CompleteCoverageGateTests(unittest.TestCase):
    def test_profiles_cover_the_exact_python_trust_boundary(self) -> None:
        expected = {
            path.relative_to(ROOT).as_posix()
            for path in SCRIPTS.rglob("*.py")
            if path.is_file() and "__pycache__" not in path.parts
        }
        for profile in ("code-only", "release-complete"):
            with self.subTest(profile=profile):
                _, minimums = coverage_profile_minimums(profile)
                self.assertEqual(expected, set(minimums))

    def test_exact_branch_aware_evidence_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "scripts"
            nested = scripts / "nested"
            nested.mkdir(parents=True)
            first = scripts / "first.py"
            second = nested / "second.py"
            first.write_text("pass\n", encoding="utf-8")
            second.write_text("pass\n", encoding="utf-8")
            payload = coverage_payload(
                [str(first.resolve()), FAKE_NESTED_SECOND],
                percentage=80.0,
            )

            report, errors = python_trust_boundary_coverage_report(
                root,
                payload,
                profile="code-only",
                total_minimum=75.0,
                module_minimums={
                    FAKE_FIRST: 75,
                    FAKE_NESTED_SECOND: 75,
                },
            )

            self.assertEqual([], errors)
            self.assertEqual("pass", report["status"])
            self.assertEqual(2, report["trust_boundary_python_files"])

    def test_incomplete_or_non_branch_evidence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "first.py").write_text("pass\n", encoding="utf-8")
            (scripts / "second.py").write_text("pass\n", encoding="utf-8")
            payload = coverage_payload(
                [FAKE_FIRST, FAKE_UNEXPECTED],
                branch_coverage=False,
                percentage=49.0,
            )

            report, errors = python_trust_boundary_coverage_report(
                root,
                payload,
                profile="code-only",
                total_minimum=50.0,
                module_minimums={
                    FAKE_FIRST: 50,
                    FAKE_SECOND: 50,
                },
            )

            self.assertEqual("fail", report["status"])
            rendered = "\n".join(errors)
            self.assertIn("not branch-aware", rendered)
            self.assertIn(FAKE_SECOND, rendered)
            self.assertIn(FAKE_UNEXPECTED, rendered)
            self.assertIn("below the code-only minimum", rendered)


class ReleaseToolTrustBoundaryTests(unittest.TestCase):
    def test_ci_keeps_coverage_artifacts_external_and_runs_strict_release_gate(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        temporary_data = (
            '--data-file="${{ runner.temp }}/gtm-python-coverage.data"'
        )
        self.assertEqual(2, workflow.count(temporary_data))
        self.assertIn("--coverage-profile code-only", workflow)
        self.assertIn("github.event_name == 'workflow_dispatch'", workflow)
        self.assertIn("gtm_vendor_registry.py --online --max-age-days 120", workflow)

    def test_package_builder_copies_only_declared_runtime_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            output = Path(temporary) / "bundle"
            root.mkdir()
            for filename in build_skill_package.ROOT_FILES:
                (root / filename).write_text(f"{filename}\n", encoding="utf-8")
            for dirname in build_skill_package.ROOT_DIRECTORIES:
                directory = root / dirname
                directory.mkdir()
                (directory / "kept.txt").write_text("kept\n", encoding="utf-8")
            (root / "scripts" / "gtm_self_test.py").write_text(
                "excluded\n", encoding="utf-8"
            )
            (root / "scripts" / "cache.pyc").write_bytes(b"excluded")

            with mock.patch.object(build_skill_package, "write_manifest") as manifest:
                build_skill_package.build(root, output)

            self.assertTrue((output / "scripts" / "kept.txt").is_file())
            self.assertFalse((output / "scripts" / "gtm_self_test.py").exists())
            self.assertFalse((output / "scripts" / "cache.pyc").exists())
            manifest.assert_called_once_with(output, source_root=root)
            with self.assertRaises(FileExistsError):
                build_skill_package.build(root, output)

    def test_self_test_run_preserves_outcome_and_bounds_captured_output(self) -> None:
        completed = SimpleNamespace(
            returncode=3,
            stdout="x" * 5000,
            stderr="y" * 5000,
        )
        with mock.patch.object(gtm_self_test.subprocess, "run", return_value=completed):
            report = gtm_self_test.run(ROOT, "fixture", ["fixture"])

        self.assertEqual("fail", report["status"])
        self.assertEqual(3, report["return_code"])
        self.assertEqual(4000, len(report["stdout"]))
        self.assertEqual(4000, len(report["stderr"]))

    def test_code_only_self_test_runs_repository_checks_without_runtime_claim(self) -> None:
        stdout = StringIO()

        def passing_check(_root: Path, name: str, _command: list[str], **_kwargs: object):
            return {
                "name": name,
                "status": "pass",
                "return_code": 0,
                "stdout": "",
                "stderr": "",
            }

        with (
            mock.patch.object(sys, "argv", ["gtm_self_test.py", "--code-only"]),
            mock.patch.object(gtm_self_test, "run", side_effect=passing_check),
            mock.patch.object(gtm_self_test.importlib.util, "find_spec", return_value=None),
            redirect_stdout(stdout),
        ):
            status = gtm_self_test.main()

        report = json.loads(stdout.getvalue())
        self.assertEqual(0, status)
        self.assertEqual("code_only", report["mode"])
        self.assertEqual(
            ["unittest", "release_layout", "vendor_registry"],
            [item["name"] for item in report["checks"]],
        )

    def test_release_complete_self_test_fails_when_artifact_runtime_is_absent(self) -> None:
        stdout = StringIO()

        def passing_check(_root: Path, name: str, _command: list[str], **_kwargs: object):
            return {
                "name": name,
                "status": "pass",
                "return_code": 0,
                "stdout": "",
                "stderr": "",
            }

        with (
            mock.patch.object(sys, "argv", ["gtm_self_test.py"]),
            mock.patch.dict(
                gtm_self_test.os.environ,
                {"CODEX_NODE": "", "CODEX_ARTIFACT_NODE_MODULES": ""},
            ),
            mock.patch.object(gtm_self_test, "run", side_effect=passing_check),
            mock.patch.object(gtm_self_test.importlib.util, "find_spec", return_value=None),
            redirect_stdout(stdout),
        ):
            status = gtm_self_test.main()

        report = json.loads(stdout.getvalue())
        self.assertEqual(1, status)
        self.assertEqual("fail", report["status"])
        self.assertEqual("artifact_runtime", report["checks"][0]["name"])
        self.assertEqual(2, report["checks"][0]["return_code"])


class StrictOnlineVendorGateTests(unittest.TestCase):
    def write_registry(self, root: Path, docs: tuple[str, ...]) -> Path:
        rendered_docs = ", ".join(json.dumps(url) for url in docs)
        path = root / "registry.toml"
        path.write_text(
            "\n".join(
                (
                    "schema_version = 1",
                    f'reviewed_on = "{date.today().isoformat()}"',
                    "",
                    "[[vendors]]",
                    'name = "Fixture Vendor"',
                    'category = "fixture"',
                    'patterns = ["fixture"]',
                    f"official_docs = [{rendered_docs}]",
                    "unsupported_standard_events = []",
                    "event_replacements = []",
                    "",
                )
            ),
            encoding="utf-8",
        )
        return path

    def test_required_source_failure_is_an_error_with_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            registry = self.write_registry(
                Path(temporary),
                ("https://example.test/one", "https://example.test/two"),
            )
            with mock.patch.object(
                vendor_registry,
                "official_url_error",
                side_effect=(None, "network unavailable"),
            ):
                errors, warnings, counts = vendor_registry.validate_registry_report(
                    registry,
                    online=True,
                    max_age_days=1,
                )

            self.assertEqual([], warnings)
            self.assertEqual({"attempted": 2, "succeeded": 1, "failed": 1}, counts)
            self.assertTrue(any("required official URL check failed" in row for row in errors))

    def test_online_validation_converts_checker_exception_to_failed_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            registry = self.write_registry(
                Path(temporary),
                ("https://example.test/required",),
            )
            with mock.patch.object(
                vendor_registry,
                "official_url_error",
                side_effect=RuntimeError("checker crashed"),
            ):
                errors, warnings, counts = vendor_registry.validate_registry_report(
                    registry,
                    online=True,
                    max_age_days=1,
                )

            self.assertEqual([], warnings)
            self.assertEqual({"attempted": 1, "succeeded": 0, "failed": 1}, counts)
            self.assertTrue(any("RuntimeError: checker crashed" in row for row in errors))

    def test_online_cli_returns_nonzero_and_reports_failed_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            registry = self.write_registry(
                Path(temporary),
                ("https://example.test/required",),
            )
            stdout = StringIO()
            stderr = StringIO()
            argv = [
                "gtm_vendor_registry.py",
                "--registry",
                str(registry),
                "--online",
                "--max-age-days",
                "1",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    vendor_registry,
                    "official_url_error",
                    return_value="timeout",
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                status = vendor_registry.main()

            report = json.loads(stdout.getvalue().splitlines()[-1])
            self.assertEqual(1, status)
            self.assertEqual("fail", report["status"])
            self.assertTrue(report["online"])
            self.assertEqual(
                {"attempted": 1, "succeeded": 0, "failed": 1},
                report["official_sources"],
            )
            self.assertIn("ERROR:", stderr.getvalue())

    def test_online_cli_passes_only_when_every_source_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            registry = self.write_registry(
                Path(temporary),
                ("https://example.test/required",),
            )
            stdout = StringIO()
            argv = [
                "gtm_vendor_registry.py",
                "--registry",
                str(registry),
                "--online",
                "--max-age-days",
                "1",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    vendor_registry,
                    "official_url_error",
                    return_value=None,
                ),
                redirect_stdout(stdout),
            ):
                status = vendor_registry.main()

            report = json.loads(stdout.getvalue().splitlines()[-1])
            self.assertEqual(0, status)
            self.assertEqual("pass", report["status"])
            self.assertEqual(
                {"attempted": 1, "succeeded": 1, "failed": 0},
                report["official_sources"],
            )


if __name__ == "__main__":
    unittest.main()
