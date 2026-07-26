#!/usr/bin/env python3
"""Shared human-facing cleanup-plan taxonomy."""

from __future__ import annotations

from typing import Any

AREAS = {
    "Stack & architecture",
    "GTM hygiene",
    "Tracking plan / dataLayer",
    "Event firing logic",
    "Ecommerce payload quality",
    "Media platform tracking",
    "Consent & compliance",
    "Server-side tracking",
    "Data quality / reporting",
    "Web performance",
    "Custom code & templates",
    "Governance / ownership",
}

PROBLEM_TYPES = {
    "Broken reference",
    "Unused object",
    "Exact duplicate",
    "Functional overlap",
    "Unnecessary complexity",
    "Naming inconsistency",
    "Folder organization",
    "Missing tracking",
    "Wrong trigger timing",
    "Over-firing",
    "Under-firing",
    "Duplicate firing",
    "Wrong product, market, or page scope",
    "Incomplete payload",
    "Wrong data format",
    "Wrong value or formula logic",
    "Obsolete or legacy setup",
    "Unclear business purpose",
    "Consent mismatch",
    "Server-side routing unclear",
    "Custom code risk",
    "Performance overhead",
    "Naming or ownership unclear",
    "Generic hygiene batch",
    "Container-only evidence boundary",
}

GENERAL_PROBLEM_CATEGORIES = {
    "Removal & lifecycle",
    "Configuration & routing",
    "Duplication & consolidation",
    "Custom code & integrations",
    "Consent & governance",
    "Naming & organization",
    "Measurement & payload",
}

GENERAL_CATEGORY_BY_PROBLEM_TYPE = {
    "Unused object": "Removal & lifecycle",
    "Obsolete or legacy setup": "Removal & lifecycle",
    "Broken reference": "Configuration & routing",
    "Wrong trigger timing": "Configuration & routing",
    "Over-firing": "Configuration & routing",
    "Under-firing": "Configuration & routing",
    "Duplicate firing": "Configuration & routing",
    "Wrong product, market, or page scope": "Configuration & routing",
    "Server-side routing unclear": "Configuration & routing",
    "Exact duplicate": "Duplication & consolidation",
    "Functional overlap": "Duplication & consolidation",
    "Unnecessary complexity": "Duplication & consolidation",
    "Generic hygiene batch": "Duplication & consolidation",
    "Custom code risk": "Custom code & integrations",
    "Performance overhead": "Custom code & integrations",
    "Consent mismatch": "Consent & governance",
    "Unclear business purpose": "Consent & governance",
    "Container-only evidence boundary": "Consent & governance",
    "Incomplete action plan": "Consent & governance",
    "Naming inconsistency": "Naming & organization",
    "Folder organization": "Naming & organization",
    "Naming or ownership unclear": "Naming & organization",
    "Missing tracking": "Measurement & payload",
    "Incomplete payload": "Measurement & payload",
    "Wrong data format": "Measurement & payload",
    "Wrong value or formula logic": "Measurement & payload",
}

CLEANUP_PLAN_COLUMNS = (
    "ID",
    "Status",
    "General problem category",
    "Area / problem type",
    "Affected object(s)",
    "Problem / evidence",
    "Action / priority / QA",
)


def general_problem_category(problem_type: Any) -> str:
    """Return the stable broad filter category for one exact problem type."""
    value = str(problem_type or "")
    try:
        return GENERAL_CATEGORY_BY_PROBLEM_TYPE[value]
    except KeyError as exc:
        raise ValueError(
            f"unsupported general-category problem type {value!r}"
        ) from exc


def taxonomy_errors(area: Any, problem_type: Any, label: str) -> list[str]:
    errors: list[str] = []
    if str(area or "") not in AREAS:
        errors.append(f"{label}: unsupported human area {area!r}")
    if str(problem_type or "") not in PROBLEM_TYPES:
        errors.append(f"{label}: unsupported human problem type {problem_type!r}")
    return errors
