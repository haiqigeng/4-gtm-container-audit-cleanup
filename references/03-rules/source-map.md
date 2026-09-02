# Rule Source Map

| Topic | Authoritative local source |
| --- | --- |
| North Star and all audit areas | `audit-coverage.md` |
| Product purpose and phase boundary | `../01-skill/purpose.md` and `../01-skill/non-goals.md` |
| Inputs and outputs | `../01-skill/inputs-outputs.md` |
| Definition of done | `../01-skill/acceptance-criteria.md` |
| Dual-audit workflow and fixed point | `workflow-and-assurance.md` |
| Human workbook | `workbook-delivery.md` |
| Runtime/release identity | `scripts/gtm_skill_identity.py` and `.skill-build-manifest.json` |
| Canonical scan and assurance | `scripts/gtm_canonical_scan.py` and `scripts/gtm_scan_assurance.py` |
| Obligation ownership | `scripts/gtm_obligation_ledger.py` |
| Audit bundles, provenance, validation, and seals | `scripts/gtm_cleanroom_audit.py` |
| Independent semantic plan authoring and application | `scripts/gtm_audit_plan.py` |
| Reconciliation and neutral checks | `scripts/gtm_reconciliation.py` |
| Operation model and projection | `scripts/gtm_operation_model.py`, `scripts/gtm_target_synthesis.py`, and `scripts/gtm_fixed_point.py` |
| Canonical record | `scripts/gtm_canonical_record.py` |
| Delivery mapping/build/reviews | `scripts/gtm_delivery_mapper.py`, `scripts/gtm_workbook_build.mjs`, `scripts/gtm_workbook_verify.mjs`, and `scripts/gtm_delivery_reviews.py` |
| GTM JSON structure | `container-json-guide.md` |
| Product/vendor contracts | `domain-contracts.md` and `vendor-registry.toml` |
| Naming | `naming-standardization.md` |
| Commands | `../02-commands/validation-commands.md` |
| Forward-test release proof | `../02-commands/forward-test-prompts.md` |

For version-sensitive judgments, use the locked registry first. If its applicable
official source is absent or stale, record a blocked evidence limit and one
research owner; do not modify the registry during the audit. Registry maintenance
is a separate skill-evolution action followed by a new audit package. A URL
supplied after evidence lock cannot silently alter a sealed audit.
