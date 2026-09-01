# Inputs And Outputs

## Required Input

One complete, unambiguous GTM web ContainerVersion JSON export or equivalent
read-only GTM evidence with resolvable account, container, version/workspace, and
WEB container-type identity. A standard GTM export envelope proves omitted
supported web layers empty; equivalent read-only evidence must enumerate them.
Server-container exports are not accepted in this version.

## Optional Locked Input

- analyst-confirmed context such as CMP, route intent, exact server route hosts
  approved to own downstream consent gating, naming rules, exclusions, and exact
  `do_not_touch` object keys. Advanced Consent Mode approval is never a global
  boolean: each `advanced_consent_mode_approvals` row must contain exactly
  `destination_id`, `transport_scope` (`direct_browser` or `client_to_server`),
  `route_host` (empty only for direct browser), `approval_status: approved`, and
  concrete `evidence`;
- an analyst-approved tracking plan or requirement artifact. It is withheld from
  each audit until that audit seals its source-only checkpoint.
- for a post-canonical semantic repair only: the sealed predecessor
  `canonical-record.json` and one approved `gtm_semantic_repair_brief` bound to
  that record. The new package must use the same locked source; repair evidence
  is withheld until each fresh audit seals its source checkpoint.

Inference may route review; it cannot silently become an approved fact. Ambiguity
that changes a verdict becomes an owner decision or evidence limit.

## Outputs

The audit package contains immutable source and contract locks, the canonical
scan, independent scan assurance, obligation ledger, two isolated audit bundles
and seals, reconciliation and neutral verification, exact operation packet,
fixed-point proof and deterministic replay, sealed canonical record and manifest,
delivery map/editorial seals, workbook build and verification artifacts, and
independent fidelity/reader review seals.

A semantic successor additionally contains copied predecessor record/manifest/
seal evidence, the approved repair brief, explicit post-checkpoint repair
evidence on each exact owning obligation, and an immutable lineage binding. It is a complete new audit package,
not an in-place patch or reduced workflow.

The user-facing output is exactly one `.xlsx` workbook with four required visible
sheets and an optional Custom Code sheet, as specified in
`references/03-rules/workbook-delivery.md`. The canonical JSON remains a separate
technical artifact, not a second workbook.

## Completion State

`pass` means canonical audit closure, fixed-point replay, exact workbook coverage,
technical verification, fidelity, workbook-only reader, rendered-layout, privacy,
and formula checks all passed. A blocked workflow reports its exact unmet gate;
it never substitutes a partial workbook.
