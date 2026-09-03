"""Affected-stage scan repair preserves evidence, judgments and the cycle limit."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_v2_workflow import (
    actionable_priority_export, build_package, complete_checkpoint, complete_audit,
    complete_base_reconciliation, write_fixture_projection_plan,
)
from gtm_audit_plan import apply_projection_plan
from gtm_fixed_point import (
    repair_projection_scan, start_fixed_point, advance_fixed_point, fixed_point_seal_errors,
)
from gtm_lib import write_json, file_sha256
from gtm_projection_review import (
    seal_projection_review, validate_projection_review, scaffold_projection_reconciliation,
    finalize_projection_reconciliation, retained_projection_review,
)
from gtm_target_synthesis import compile_operation_packet


class ProjectionScanRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root / "package"
        source = self.root / "source.json"
        write_json(source, actionable_priority_export())
        # Reproduce an omitted scan domain without changing source ingestion.
        with mock.patch("gtm_baseline_audit.add_naming_architecture_findings"):
            build_package(source, self.package)
            for owner in ("audit-a", "audit-b"):
                complete_checkpoint(self.package, owner, owner + "-source-context")
                complete_audit(self.package, owner, actionable_priority=True)
            complete_base_reconciliation(self.package)
            compile_operation_packet(self.package)
            self.number = start_fixed_point(self.package)["cycle"]
            self.finish_reviews("before")
        self.cycle = self.package / "fixed-point" / f"cycle-{self.number:02d}"
        scaffold_projection_reconciliation(self.cycle)
        self.fill_reconciliation()

    def read(self, path):
        return json.loads(path.read_text(encoding="utf-8"))

    def hashes(self, path):
        return {str(p.relative_to(path)): file_sha256(p) for p in path.rglob("*") if p.is_file()}

    def finish_reviews(self, suffix):
        for owner in ("review-a", "review-b"):
            plan = write_fixture_projection_plan(self.package, self.number, owner)
            apply_projection_plan(self.package, self.number, owner, plan,
                                  agent_id=owner + "-" + suffix,
                                  context_id=owner + "-context-" + suffix)
            seal_projection_review(self.package, self.number, owner)

    def fill_reconciliation(self, suffix="before"):
        rec_path = self.cycle / "projection-reconciliation.json"
        neutral_path = self.cycle / "projection-neutral-verification.json"
        rec, neutral = self.read(rec_path), self.read(neutral_path)
        rec.update(independent_agent_id="repair-reconciler-" + suffix,
                   independent_context_id="repair-context-" + suffix, status="complete")
        by_verification = {}
        for row in rec["comparisons"]:
            row.update(status="complete", canonical_decision=copy.deepcopy(row["review_decisions"]["review-a"]),
                       reconciliation_rationale="Both independent fixture reviews support this exact projected configuration conclusion.")
            by_verification[row["neutral_verification_id"]] = row["canonical_decision"]
        for row in neutral["verifications"]:
            row.update(status="complete", canonical_decision=by_verification[row["verification_id"]],
                       evidence_citations=row["allowed_evidence_citations"],
                       verification_rationale="The locked projected fixture evidence supports this unchanged semantic conclusion.")
        neutral["status"] = "complete" if neutral["verifications"] else "not_required"
        write_json(rec_path, rec)
        write_json(neutral_path, neutral)

    def test_repair_preserves_prior_results_and_only_authors_changed_rows(self):
        old = self.hashes(self.cycle)
        packet = (self.package / "operation-packet.json").read_bytes()
        source = (self.package / "locked-source.json").read_bytes()
        result = repair_projection_scan(self.package, "Restore omitted naming candidates")
        self.assertEqual(result["cycle"], self.number)
        self.assertGreater(result["retained_decisions"]["review-a"], 0)
        self.assertGreater(result["pending_decisions_per_review"], 0)
        self.assertEqual(packet, (self.package / "operation-packet.json").read_bytes())
        self.assertEqual(source, (self.package / "locked-source.json").read_bytes())
        snapshot = self.hashes(self.cycle / "prior-cycle")
        self.assertEqual(old, {k: snapshot[k] for k in old})
        self.finish_reviews("after")
        for owner in ("review-a", "review-b"):
            self.assertEqual([], validate_projection_review(self.cycle, owner))
        reconciliation = scaffold_projection_reconciliation(self.cycle)
        self.assertGreater(reconciliation["retained_comparisons"], 0)
        prior_rec = self.read(self.cycle / "prior-cycle/projection-reconciliation.json")
        old_rows = {row["comparison_id"]: row for row in prior_rec["comparisons"]}
        current = self.read(self.cycle / "projection-reconciliation.json")
        for row in current["comparisons"]:
            if row["status"] == "complete":
                self.assertEqual(row, old_rows[row["comparison_id"]])
        self.fill_reconciliation("after")
        finalize_projection_reconciliation(self.cycle)
        self.assertEqual("pass", advance_fixed_point(self.package)["status"])
        self.assertEqual([], fixed_point_seal_errors(self.package))

    def test_unverified_reconciliation_prose_is_not_carried_forward(self):
        path = self.cycle / "projection-reconciliation.json"
        rec = self.read(path)
        for row in rec["comparisons"]:
            row["canonical_decision"]["criteria_assessment"] = "An unproposed assessment cannot masquerade as accepted evidence during repair."
        write_json(path, rec)
        repair_projection_scan(self.package, "Restore omitted naming candidates")
        self.finish_reviews("after")
        result = scaffold_projection_reconciliation(self.cycle)
        self.assertEqual(0, result["retained_comparisons"])

    def test_no_scan_change_preserves_every_file(self):
        before = self.hashes(self.package)
        with mock.patch("gtm_baseline_audit.add_naming_architecture_findings"):
            with self.assertRaisesRegex(ValueError, "no corrected scan evidence"):
                repair_projection_scan(self.package, "No effective correction")
        self.assertEqual(before, self.hashes(self.package))

    def test_changed_retained_decision_fails_validation(self):
        repair_projection_scan(self.package, "Restore omitted naming candidates")
        self.finish_reviews("after")
        path = self.cycle / "reviews/review-a/review.json"
        review = self.read(path)
        retained = retained_projection_review(self.cycle, "review-a")["decisions"][0]
        row = next(r for r in review["decisions"] if r["obligation_id"] == retained["obligation_id"])
        row["criteria_assessment"] = "An unauthorized different semantic conclusion replaces the inherited assessment."
        write_json(path, review)
        self.assertIn("unchanged retained projection decision was edited", validate_projection_review(self.cycle, "review-a"))

    def test_changed_predecessor_is_not_reused(self):
        repair_projection_scan(self.package, "Restore omitted naming candidates")
        path = self.cycle / "prior-cycle/review-seals/review-a.review.json"
        review = self.read(path)
        review["decisions"][0]["criteria_assessment"] = "Changed predecessor"
        write_json(path, review)
        with self.assertRaisesRegex(ValueError, "predecessor changed"):
            retained_projection_review(self.cycle, "review-a")

    def test_failed_commit_restores_cycle_state_and_plans(self):
        before = self.hashes(self.package)
        with mock.patch("gtm_fixed_point._atomic_write_json", side_effect=OSError("injected state write failure")):
            with self.assertRaisesRegex(OSError, "injected state write failure"):
                repair_projection_scan(self.package, "Restore omitted naming candidates")
        self.assertEqual(before, self.hashes(self.package))

    def test_prior_review_binding_cannot_be_replaced(self):
        repair_projection_scan(self.package, "Restore omitted naming candidates")
        path = self.cycle / "prior-cycle/review-seals/review-a.json"
        seal = self.read(path)
        seal["review_seal_sha256"] = "0" * 64
        write_json(path, seal)
        with self.assertRaisesRegex(ValueError, "predecessor review binding"):
            retained_projection_review(self.cycle, "review-a")

    def test_repair_rejects_the_prior_agent_before_writing(self):
        repair_projection_scan(self.package, "Restore omitted naming candidates")
        plan = write_fixture_projection_plan(self.package, self.number, "review-a")
        before = self.hashes(self.package)
        with self.assertRaisesRegex(ValueError, "fresh agent and context"):
            apply_projection_plan(self.package, self.number, "review-a", plan,
                                  agent_id="review-a-before", context_id="new-context")
        self.assertEqual(before, self.hashes(self.package))

    def test_repair_peers_cannot_swap_their_previous_roles(self):
        repair_projection_scan(self.package, "Restore omitted naming candidates")
        for owner, prior_peer in (("review-a", "review-b"), ("review-b", "review-a")):
            plan = write_fixture_projection_plan(self.package, self.number, owner)
            before = self.hashes(self.package)
            with self.assertRaisesRegex(ValueError, "fresh agent and context"):
                apply_projection_plan(self.package, self.number, owner, plan,
                                      agent_id=prior_peer + "-before",
                                      context_id=prior_peer + "-context-before")
            self.assertEqual(before, self.hashes(self.package))

    def test_reconciliation_requires_a_new_context_after_repair(self):
        repair_projection_scan(self.package, "Restore omitted naming candidates")
        self.finish_reviews("after")
        scaffold_projection_reconciliation(self.cycle)
        self.fill_reconciliation()
        with self.assertRaisesRegex(ValueError, "reconciliation requires a fresh"):
            finalize_projection_reconciliation(self.cycle)
        self.assertFalse((self.cycle / "projection-closure-seal.json").exists())

    def test_failed_plan_validation_leaves_scaffolding_retryable(self):
        repair_projection_scan(self.package, "Restore omitted naming candidates")
        before = self.hashes(self.package)
        with mock.patch("gtm_audit_plan.retained_projection_review", side_effect=OSError("injected read failure")):
            with self.assertRaisesRegex(OSError, "injected read failure"):
                write_fixture_projection_plan(self.package, self.number, "review-a")
        self.assertEqual(before, self.hashes(self.package))
        self.assertFalse((self.package / "projection-scratch/cycle-01/review-a").exists())
        self.assertTrue(write_fixture_projection_plan(self.package, self.number, "review-a").is_file())

    def test_a_sealed_closure_cannot_be_replaced(self):
        write_json(self.cycle / "projection-closure-seal.json", {"fixture": "sealed"})
        before = self.hashes(self.package)
        with self.assertRaisesRegex(ValueError, "sealed closure"):
            repair_projection_scan(self.package, "Must preserve the sealed closure")
        self.assertEqual(before, self.hashes(self.package))

    def test_non_convergent_state_cannot_reset_its_cycle_budget(self):
        path = self.package / "fixed-point/state.json"
        state = self.read(path)
        state["status"] = "non_convergent_target_state"
        write_json(path, state)
        before = self.hashes(self.package)
        with self.assertRaisesRegex(ValueError, "unfinished current projection"):
            repair_projection_scan(self.package, "Cannot reset convergence")
        self.assertEqual(before, self.hashes(self.package))


if __name__ == "__main__":
    unittest.main()
