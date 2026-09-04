from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from test_v2_operation_safety import operation, operation_fixture  # noqa: E402

from gtm_lib import custom_template_ids, custom_template_type_index, stable_hash  # noqa: E402
from gtm_operation_model import (  # noqa: E402
    apply_operations,
    operation_write_conflicts,
    set_json_path,
    validate_operations,
)


class OperationReferenceAndPathSafetyTests(unittest.TestCase):
    def test_template_remap_changes_only_type_for_local_and_gallery_consumers(self):
        for gallery in (False, True):
            with self.subTest(gallery=gallery):
                data = operation_fixture()
                cv = data["containerVersion"]
                cv["customTemplate"] = [
                    {"templateId": "10", "accountId": "1", "name": "Old"},
                    {"templateId": "20", "accountId": "1", "name": "New"},
                ]
                if gallery:
                    for template, token in zip(cv["customTemplate"], ("OLD", "NEW"), strict=True):
                        template["galleryReference"] = {"galleryTemplateId": token}
                tag = cv["tag"][0]
                tag.update(type="cvt_OLD" if gallery else "cvt_1_10", name="Campaign 10")
                tag["notes"] = "Keep 10 and https://example.com/10"
                tag["parameter"] = [{"key": "value", "value": "sale-10"}]
                original = copy.deepcopy(data)
                change = operation("OP-TEMPLATE", remaps=[{
                    "from_object_key": "customTemplate:10",
                    "to_object_key": "customTemplate:20",
                    "consumer_object_keys": ["tag:1"],
                }], deletions=[{"object_key": "customTemplate:10"}])
                self.assertEqual([], validate_operations(data, [change], source_sha256=stable_hash(data, 64)))
                target = apply_operations(data, [change], source_sha256=stable_hash(data, 64))["containerVersion"]
                expected = copy.deepcopy(tag)
                expected["type"] = "cvt_NEW" if gallery else "cvt_1_20"
                self.assertEqual(expected, target["tag"][0])
                self.assertEqual(["20"], custom_template_ids(
                    target["tag"][0], custom_template_type_index(target["customTemplate"])
                ))
                self.assertEqual(original, data)

    def test_template_remap_rejects_ambiguous_or_unrelated_references(self):
        data = operation_fixture()
        cv = data["containerVersion"]
        cv["customTemplate"] = [
            {"templateId": "10", "galleryReference": {"galleryTemplateId": "SAME"}},
            {"templateId": "20", "galleryReference": {"galleryTemplateId": "SAME"}},
        ]
        change = operation("OP-TEMPLATE", remaps=[{
            "from_object_key": "customTemplate:10", "to_object_key": "customTemplate:20",
            "consumer_object_keys": ["tag:1"],
        }])
        for token in ("googtag", "cvt_SAME"):
            cv["tag"][0]["type"] = token
            self.assertTrue(validate_operations(data, [change], source_sha256=stable_hash(data, 64)))
            with self.assertRaises(ValueError):
                apply_operations(data, [change], source_sha256=stable_hash(data, 64))

    def test_template_remap_can_target_a_declared_creation(self):
        for gallery in (False, True):
            data = operation_fixture()
            cv = data["containerVersion"]
            cv["customTemplate"] = [{"templateId": "10", "accountId": "1"}]
            cv["tag"][0]["type"] = "cvt_1_10"
            new_template = {"templateId": "20", "accountId": "1"}
            if gallery:
                new_template["galleryReference"] = {"galleryTemplateId": "NEW"}
            change = operation("OP-CREATE-OWNER", creations=[{
                "layer": "customTemplate", "object": new_template,
            }], remaps=[{
                "from_object_key": "customTemplate:10", "to_object_key": "customTemplate:20",
                "consumer_object_keys": ["tag:1"],
            }], deletions=[{"object_key": "customTemplate:10"}])
            self.assertEqual([], validate_operations(data, [change], source_sha256=stable_hash(data, 64)))
            target = apply_operations(data, [change], source_sha256=stable_hash(data, 64))["containerVersion"]
            self.assertEqual("cvt_NEW" if gallery else "cvt_1_20", target["tag"][0]["type"])

    def test_unsupported_remap_layer_is_not_string_substitution(self):
        data = operation_fixture()
        data["containerVersion"]["gtagConfig"] = [
            {"gtagConfigId": "10"}, {"gtagConfigId": "20"},
        ]
        change = operation("OP-UNSUPPORTED", remaps=[{
            "from_object_key": "gtagConfig:10", "to_object_key": "gtagConfig:20",
            "consumer_object_keys": ["tag:1"],
        }])
        self.assertTrue(validate_operations(data, [change], source_sha256=stable_hash(data, 64)))
        with self.assertRaisesRegex(ValueError, "unsupported remap layer"):
            apply_operations(data, [change], source_sha256=stable_hash(data, 64))

    def test_same_gallery_retirement_preserves_token_and_resolves_survivor(self):
        data = operation_fixture()
        cv = data["containerVersion"]
        cv["customTemplate"] = [
            {"templateId": value, "galleryReference": {"galleryTemplateId": "SAME"}}
            for value in ("10", "20")
        ]
        cv["tag"][0]["type"] = "cvt_SAME"
        cv["tag"][0]["notes"] = "Keep template 10 history unchanged"
        change = operation("OP-RETIRE-DUPLICATE", remaps=[{
            "from_object_key": "customTemplate:10", "to_object_key": "customTemplate:20",
            "consumer_object_keys": ["tag:1"],
        }], deletions=[{"object_key": "customTemplate:10"}])
        self.assertEqual([], validate_operations(data, [change], source_sha256=stable_hash(data, 64)))
        target = apply_operations(data, [change], source_sha256=stable_hash(data, 64))["containerVersion"]
        self.assertEqual(cv["tag"], target["tag"])
        self.assertEqual(["20"], custom_template_ids(
            target["tag"][0], custom_template_type_index(target["customTemplate"])
        ))
        cv["customTemplate"].append({
            "templateId": "30", "galleryReference": {"galleryTemplateId": "SAME"},
        })
        self.assertTrue(validate_operations(data, [change], source_sha256=stable_hash(data, 64)))

    def test_parent_child_writes_conflict_with_or_without_dependency(self):
        data = operation_fixture()
        first = operation("OP-PARENT", changes=[{
            "object_key": "tag:1", "json_path": "$.parameter", "before_source_sha256": stable_hash(data, 64),
            "after": [{"key": "new", "newValue": "FIRST"}],
        }])
        second = operation("OP-CHILD", additions=[{
            "object_key": "tag:1", "json_path": "$.parameter[0].newValue", "value": "SECOND",
        }])
        for dependencies in ([], ["OP-PARENT"]):
            second["depends_on"] = dependencies
            self.assertTrue(operation_write_conflicts([first, second]))
            self.assertTrue(validate_operations(data, [first, second], source_sha256=stable_hash(data, 64)))
        with self.assertRaisesRegex(ValueError, "addition target already exists"):
            apply_operations(data, [first, second], source_sha256=stable_hash(data, 64))
        merged = copy.deepcopy(first)
        merged["additions"] = second["additions"]
        self.assertTrue(operation_write_conflicts([merged]))
        self.assertTrue(validate_operations(data, [merged], source_sha256=stable_hash(data, 64)))

    def test_disjoint_siblings_and_token_boundaries_are_not_conflicts(self):
        data = operation_fixture()
        tag = data["containerVersion"]["tag"][0]
        edits = [operation(f"OP-{index}", changes=[{
            "object_key": "tag:1", "json_path": f"$.parameter[{index}].value",
            "before_source_sha256": stable_hash(data, 64), "after": f"NEW-{index}",
        }]) for index, row in enumerate(tag["parameter"])]
        self.assertEqual([], operation_write_conflicts(edits))
        self.assertEqual([], validate_operations(data, edits, source_sha256=stable_hash(data, 64)))
        paths = ["$.field", "$.fieldName", "$.rows[1].value", "$.rows[10].value"]
        unrelated = [operation(f"OP-{index}", additions=[{
            "object_key": "tag:1", "json_path": path, "value": "new",
        }]) for index, path in enumerate(paths)]
        self.assertEqual([], operation_write_conflicts(unrelated))
        same_slot = [operation(f"OP-{index}", additions=[{
            "object_key": "tag:1", "json_path": path, "value": "new",
        }]) for index, path in enumerate(("$.rows[1].value", "$.rows[01].value"))]
        self.assertTrue(operation_write_conflicts(same_slot))

    def test_additions_cannot_overwrite_properties_or_list_slots(self):
        for target, path in (({"value": None}, "$.value"), ({"rows": [1]}, "$.rows[0]")):
            before = copy.deepcopy(target)
            with self.assertRaises(ValueError):
                set_json_path(target, path, "new", allow_create=True)
            self.assertEqual(before, target)
        target = {"rows": [{}]}
        set_json_path(target, "$.rows[0].value", "new", allow_create=True)
        self.assertEqual({"rows": [{"value": "new"}]}, target)


if __name__ == "__main__":
    unittest.main()
