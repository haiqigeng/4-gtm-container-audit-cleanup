# Inputs And Outputs

## Required Input

One complete, unambiguous GTM web ContainerVersion JSON export or equivalent
read-only GTM evidence explicitly supplied or selected by the user, with
resolvable account, container, version/workspace, and WEB container-type identity.
Never discover, infer, or choose the source from workspace files. A standard GTM
export envelope proves omitted supported web layers empty; equivalent read-only
evidence must enumerate them. Server-container exports and server-container
objects are not accepted.

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

Inference may route review; it cannot silently become an approved fact. Ambiguity
that changes a verdict becomes an owner decision or evidence limit.

For a focused repair, identify the validated prior audit package, a new working
successor path, the user-authorized exact decision IDs, and a concrete reason.
Repair scope identifies affected decisions; it does not inject new evidence into
the locked source audits. The helper resolves exact canonical, obligation, or source
decision IDs to their owning records; it does not infer a repair scope.

## Outputs

The audit package contains immutable source and contract locks, the canonical
scan, independent scan assurance, obligation ledger, two isolated audit bundles
and seals, reconciliation and neutral verification, exact operation packet,
deterministic target-validation evidence, sealed canonical record and manifest,
delivery map/editorial seals, workbook build and exhaustive technical verification
artifacts, and one fresh workbook delivery review seal.

The target-validation result consists of five files beneath `target-validation/`:
`projected-container.json`, `canonical-scan.json`, `scan-assurance.json`,
`validation-proof.json`, and `validation-seal.json`. The canonical record binds
that result under `target_validation`. These artifacts validate the combined
packet; they do not carry simulated-target semantic reviews or new decisions.

A working repair successor retains the validated source locks, scan, assurance,
ledger, checkpoints, both complete audits, seals, and histories. Its repair
receipt records the exact requested IDs, owning records, reason, predecessor
inventory, and excluded downstream paths. Generated reconciliation, operation,
target-validation, canonical, and delivery outputs are omitted from the new
working copy. The predecessor remains unchanged. Repair the exact owning stage.
Amend a source record through the existing protocol only when its own judgment
is defective; a reconciliation-only repair preserves both source audits and seals.
Then reconstruct and validate dependent reconciliation, target, canonical, and
workbook artifacts.
The helper creates no new scan or judgment and does not rerun the source audits.

The user-facing output is exactly one `.xlsx` workbook with four required visible
sheets and an optional Custom Code sheet, as specified in
`references/03-rules/workbook-delivery.md`. The canonical JSON remains a separate
technical artifact, not a second workbook.

## Completion State

`pass` means complete source-audit coverage, deterministic target validation,
canonical sealing, exact workbook coverage,
exhaustive row/field and recovery verification, workbook delivery reviewer,
rendered-layout, privacy, and formula checks all passed. A blocked workflow reports its exact unmet gate;
it never substitutes a partial workbook.

Passing proves the implemented static checks and delivery gates, not runtime
behaviour or that every possible optimisation has been exhausted.
