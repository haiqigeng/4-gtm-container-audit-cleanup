# Rule Source Map

| Topic | Authoritative local source |
| --- | --- |
| Product objective | `references/01-skill/purpose.md` |
| Inputs, outputs, lifecycle | `references/01-skill/inputs-outputs.md` |
| Completion/failure | `references/01-skill/acceptance-criteria.md` |
| Full pipeline | `execution-contract.md` |
| Release/runtime identity | `scripts/gtm_skill_identity.py` and `.skill-build-manifest.json` |
| Independent run bundles and seals | `scripts/gtm_review_isolation.py` |
| Persistent context | `scripts/gtm_context_model.py` |
| Source identity and modeled layers | `scripts/gtm_source_model.py` and `scripts/gtm_lib.py` |
| Canonical deterministic facts | `scripts/gtm_shared_facts.py` |
| Effective consent routes | `scripts/gtm_consent_model.py` |
| Vendor detection and official sources | `scripts/gtm_vendor_registry.py` and `vendor-registry.toml` |
| Custom-code parser coverage boundary | `scripts/gtm_configuration_review.py` |
| Basic cleanup | `operational-sanitation.md` |
| Object and custom-code correctness | `configuration-correctness.md` |
| Families and overlap | `business-architecture.md` |
| GA4/media/consent/server contracts | `domain-contracts.md` |
| JSON structure | `container-json-guide.md` |
| Naming | `naming-standardization.md` |
| Operations | `operation-schema.md` |
| Direct/API/JSON execution | `mutation-playbook.md` |
| Canonical cleanup workbook | `workbook-architecture.md` |
| Derived analyst workbook | `workbook-output-contract.md` |
| Change log | `change-log-template.md` |
| Severity | `severity-calibration.md` |
| Commands | `../02-commands/validation-commands.md` |

For vendor judgments, use the registry first. When the required event/feature
documentation is absent or stale, browse the current official vendor source and
bind that source/domain to the vendor in the versioned registry, validate it,
and rebuild before recording the URL in a certified configuration contract.
