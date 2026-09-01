from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from check_release import (  # noqa: E402
    check_clean_tagged_checkout,
    referenced_resources,
    release_blocklist,
)
from gtm_skill_identity import declared_identity_errors, write_manifest  # noqa: E402


class ReleaseHealthTests(unittest.TestCase):
    def test_user_facing_start_and_completion_wording_is_frozen_once(self) -> None:
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        start = (
            "Please provide or identify the exact GTM web-container export file "
            "you want me to audit. I will not search for or infer a source file."
        )
        completion = (
            "Audit complete: [x] recommended operations, [y] owner decisions and "
            "[z] evidence limits. No GTM changes were made."
        )
        self.assertEqual(1, skill.count(start))
        self.assertEqual(1, skill.count(completion))

    def test_declared_runtime_rejects_dirty_build_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = write_manifest(root)
            manifest["source_git_dirty"] = True
            (root / ".skill-build-manifest.json").write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )
            _, errors = declared_identity_errors(root)
            self.assertTrue(any("dirty" in error for error in errors))

    def test_tagged_release_rejects_a_dirty_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            import subprocess

            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            tracked = root / "tracked.txt"
            tracked.write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Release Test",
                    "-c",
                    "user.email=release-test.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture",
                ],
                cwd=root,
                check=True,
            )
            self.assertEqual([], check_clean_tagged_checkout(root, "v2.0.0"))
            tracked.write_text("dirty\n", encoding="utf-8")
            self.assertTrue(check_clean_tagged_checkout(root, "v2.0.0"))

    def test_release_blocklist_is_required_and_must_not_be_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(FileNotFoundError, "required release blocklist"):
                release_blocklist(root)

            scripts = root / "scripts"
            scripts.mkdir()
            blocklist = scripts / "release_blocklist.txt"
            blocklist.write_text("# comments only\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "blocklist is empty"):
                release_blocklist(root)

            blocklist.write_text("obsolete phrase\n", encoding="utf-8")
            self.assertEqual(["obsolete phrase"], release_blocklist(root))

    def test_reference_wildcards_must_match_and_route_every_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wildcard = "/".join(("references", "03-rules", "*.md"))
            (root / "README.md").write_text(
                f"Read {wildcard} before work.\n",
                encoding="utf-8",
            )
            refs, missing = referenced_resources(root)
            self.assertEqual(set(), refs)
            self.assertTrue(any("unmatched wildcard" in row for row in missing))

            rules = root / "references" / "03-rules"
            rules.mkdir(parents=True)
            (rules / "first.md").write_text("# First\n", encoding="utf-8")
            (rules / "second.md").write_text("# Second\n", encoding="utf-8")
            refs, missing = referenced_resources(root)
            self.assertEqual([], missing)
            self.assertEqual(
                {
                    "/".join(("references", "03-rules", "first.md")),
                    "/".join(("references", "03-rules", "second.md")),
                },
                refs,
            )


if __name__ == "__main__":
    unittest.main()
