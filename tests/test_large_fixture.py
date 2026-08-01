from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from tests.large_fixture import multi_hundred_object_container  # noqa: E402

from gtm_audit_package_build import build_package  # noqa: E402


class LargeFixtureTests(unittest.TestCase):
    def test_multi_hundred_object_package_preserves_full_scope_and_auto_shards(
        self,
    ) -> None:
        source = multi_hundred_object_container()
        expected_objects = sum(
            len(source["containerVersion"].get(layer, []))
            for layer in (
                "tag",
                "trigger",
                "variable",
                "folder",
                "builtInVariable",
            )
        )
        self.assertGreaterEqual(expected_objects, 300)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export = root / "large-container.json"
            export.write_text(json.dumps(source), encoding="utf-8")
            package_dir = root / "audit-package"
            manifest = build_package(export, package_dir)
            self.assertEqual("pass", manifest["status"])
            shared = json.loads(
                (package_dir / "shared_facts.json").read_text(encoding="utf-8")
            )
            self.assertEqual(expected_objects, shared["counts"]["objects"])
            strategies = {
                run: details["strategy"]
                for run, details in manifest["review_work_units"]["runs"].items()
            }
            self.assertEqual(
                {
                    "operational_sanitation",
                    "configuration_correctness",
                    "business_architecture",
                },
                set(strategies),
            )
            self.assertIn("sharded", set(strategies.values()))
            configuration = manifest["review_work_units"]["runs"][
                "configuration_correctness"
            ]
            self.assertEqual(0, configuration["obligation_shards"])
            self.assertGreater(
                configuration["configuration_evidence_obligations"],
                configuration["authored_behavior_work_units"],
            )
            self.assertTrue(
                (package_dir / configuration["shard_manifest"]).is_file()
            )
            self.assertFalse((package_dir / "configuration-shards").exists())
            scalability = manifest["scalability"]
            self.assertLessEqual(
                scalability["artifact_files_excluding_manifest"],
                90,
            )
            self.assertLessEqual(
                scalability["artifact_to_source_bytes_ratio"],
                700,
            )


if __name__ == "__main__":
    unittest.main()
