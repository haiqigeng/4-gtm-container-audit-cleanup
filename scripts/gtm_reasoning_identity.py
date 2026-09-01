#!/usr/bin/env python3
"""Track reasoning-context and host-receipt identities across one GTM audit."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

IdentityRegistry = dict[str, dict[str, set[str]]]


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"reasoning identity artifact must be an object: {path}")
    return payload


def _empty_registry() -> IdentityRegistry:
    return {"contexts": {}, "receipts": {}}


def register_reasoning_identity(
    registry: IdentityRegistry,
    *,
    owner: str,
    context_id: Any = "",
    receipt_id: Any = "",
) -> None:
    """Register nonblank identities under their semantic review owner."""

    context = str(context_id or "").strip()
    receipt = str(receipt_id or "").strip()
    if context:
        registry["contexts"].setdefault(context, set()).add(owner)
    if receipt:
        registry["receipts"].setdefault(receipt, set()).add(owner)


def _register_record(
    registry: IdentityRegistry, owner: str, record: dict[str, Any]
) -> None:
    register_reasoning_identity(
        registry,
        owner=owner,
        context_id=record.get("independent_context_id"),
        receipt_id=(record.get("host_isolation_receipt") or {}).get("receipt_id"),
    )


def collect_reasoning_identity_registry(
    package_dir: Path,
    *,
    exclude_paths: Iterable[Path] = (),
) -> IdentityRegistry:
    """Collect every accepted or completed workflow reasoning identity.

    One owner may appear in more than one immutable artifact. For example, an
    audit's initial checkpoint and its initial audit seal intentionally retain
    the same host-scoped reasoning identity. Reuse is a conflict only when the
    same identity belongs to different semantic review owners.
    """

    package_dir = package_dir.resolve()
    excluded = {path.resolve() for path in exclude_paths}
    registry = _empty_registry()

    def add(path: Path, owner: str) -> None:
        if path.is_file() and path.resolve() not in excluded:
            _register_record(registry, owner, _load(path))

    for path in sorted(
        (package_dir / "audit-bundles").glob("*/source-checkpoint-seal.json")
    ):
        data = _load(path)
        audit_id = str(data.get("audit_id") or path.parent.name)
        if path.resolve() not in excluded:
            _register_record(registry, f"source-audit:{audit_id}:0", data)

    for path in sorted((package_dir / "audit-seals").glob("*.json")):
        data = _load(path)
        if data.get("kind") != "gtm_cleanroom_audit_seal":
            continue
        audit_id = str(data.get("audit_id") or path.stem)
        sequence = int(data.get("amendment_sequence") or 0)
        if path.resolve() not in excluded:
            _register_record(
                registry, f"source-audit:{audit_id}:{sequence}", data
            )

    for path in sorted((package_dir / "audit-seals" / "history").glob("*.seal.json")):
        data = _load(path)
        audit_id = str(data.get("audit_id") or path.name.split(".", 1)[0])
        sequence = int(data.get("amendment_sequence") or 0)
        if path.resolve() not in excluded:
            _register_record(
                registry, f"source-audit:{audit_id}:{sequence}", data
            )

    base_neutral = package_dir / "neutral-verification.json"
    if base_neutral.is_file() and base_neutral.resolve() not in excluded:
        for row in _load(base_neutral).get("verifications", []):
            if isinstance(row, dict):
                verification_id = str(row.get("verification_id") or "unknown")
                _register_record(registry, f"base-neutral:{verification_id}", row)

    fixed_point = package_dir / "fixed-point"
    for cycle_dir in sorted(fixed_point.glob("cycle-*")):
        cycle = cycle_dir.name
        for review_id in ("review-a", "review-b"):
            path = cycle_dir / "review-seals" / f"{review_id}.json"
            add(path, f"projection-review:{cycle}:{review_id}")
        path = cycle_dir / "projection-neutral-verification.json"
        if path.is_file() and path.resolve() not in excluded:
            for row in _load(path).get("verifications", []):
                if isinstance(row, dict):
                    verification_id = str(row.get("verification_id") or "unknown")
                    _register_record(
                        registry,
                        f"projection-neutral:{cycle}:{verification_id}",
                        row,
                    )

    delivery = package_dir / "delivery"
    for path in sorted((delivery / "editorial-versions").glob("editorial-*.json")):
        sequence = path.stem.removeprefix("editorial-")
        add(path, f"editorial:{sequence}")
    editorial_seal = delivery / "editorial-seal.json"
    if editorial_seal.is_file() and editorial_seal.resolve() not in excluded:
        data = _load(editorial_seal)
        sequence = int(data.get("amendment_sequence") or 0)
        _register_record(registry, f"editorial:{sequence:03d}", data)

    for review_kind, filename in (
        ("fidelity", "fidelity-review.json"),
        ("reader", "reader-review.json"),
    ):
        for path in sorted(delivery.glob(f"**/reviews/{review_kind}/{filename}")):
            if path.resolve() in excluded:
                continue
            build = path.parents[2].relative_to(delivery).as_posix()
            add(path, f"delivery-review:{build}:{review_kind}")

    return registry


def reasoning_identity_reuse_errors(
    registry: IdentityRegistry,
    *,
    owner: str,
    label: str,
    context_id: Any = "",
    receipt_id: Any = "",
) -> list[str]:
    """Reject an identity already owned by another workflow review unit."""

    errors: list[str] = []
    for identity_kind, identity in (
        ("reasoning context", str(context_id or "").strip()),
        ("host isolation receipt", str(receipt_id or "").strip()),
    ):
        if not identity:
            continue
        owners = registry[
            "contexts" if identity_kind == "reasoning context" else "receipts"
        ].get(identity, set())
        foreign_owners = sorted(owners - {owner})
        if foreign_owners:
            errors.append(
                f"{label}: {identity_kind} identity is already used by "
                + ", ".join(foreign_owners)
            )
    return errors


def workflow_reasoning_identity_errors(package_dir: Path) -> list[str]:
    """Report identities assigned to more than one semantic review owner."""

    registry = collect_reasoning_identity_registry(package_dir)
    errors: list[str] = []
    for kind in ("contexts", "receipts"):
        label = "reasoning context" if kind == "contexts" else "host isolation receipt"
        for identity, owners in sorted(registry[kind].items()):
            if len(owners) > 1:
                errors.append(
                    f"workflow-wide {label} identity {identity!r} is reused by "
                    + ", ".join(sorted(owners))
                )
    return errors


def used_reasoning_identities(
    package_dir: Path, *, exclude_paths: Iterable[Path] = ()
) -> tuple[set[str], set[str]]:
    """Return workflow-global identity sets for row-wise neutral validation."""

    registry = collect_reasoning_identity_registry(
        package_dir, exclude_paths=exclude_paths
    )
    return set(registry["contexts"]), set(registry["receipts"])
