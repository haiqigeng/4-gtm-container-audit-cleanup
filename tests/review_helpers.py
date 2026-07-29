from __future__ import annotations

from typing import Any


def complete_review_attestation(
    review: dict[str, Any],
    *,
    decision_authoring_method: str,
    independent_review_context_id: str | None = None,
    optional_artifact_roles: list[str] | None = None,
    helper_modules: list[str] | None = None,
    semantic_completion_artifacts: list[str] | None = None,
) -> dict[str, Any]:
    """Build a completed provenance attestation for synthetic test reviews."""
    contract = review.get("input_contract") or {}
    required_roles = contract.get("required_artifact_roles")
    return {
        "status": "complete",
        "input_contract_sha256": contract.get("contract_sha256"),
        "used_artifact_roles": [
            *(required_roles if isinstance(required_roles, list) else []),
            *(optional_artifact_roles or []),
        ],
        "foreign_verdict_artifacts_used": [],
        "helper_modules": helper_modules or [],
        "decision_authoring_method": decision_authoring_method,
        "independent_review_context_id": (
            independent_review_context_id
            or f"{contract.get('review_run') or 'review'}:"
            f"{str(contract.get('contract_sha256') or '')[:20]}"
        ),
        "semantic_completion_artifacts": semantic_completion_artifacts or [],
    }
