# Mutation Playbook

Never mutate or publish from an audit request alone.

## Contents

- Approval sequence
- Source-integrity and layer-complete readback
- Direct GTM/API/MCP
- Import JSON
- Custom code
- Consent and server routing
- Validation and stop conditions

## Approval Sequence

1. Deliver audit and cleanup plan.
2. Ask for route: direct GTM/API/MCP or import JSON.
3. Confirm whether all operations or an explicit list of operation IDs is approved.
4. Confirm rollback export and blockers.
5. Regenerate the selected future state and run the execution preflight.
6. Execute only the approved operations that pass the preflight.

Audit and recommendation depth are independent of this choice. Do not use
aggressiveness modes; approval is operation-specific. Treat a subset as staged
work, not as completion of the full cleanup plan.

The preflight fails closed when an approved operation intersects an exact
`do_not_touch` layer/ID, the future-state gate failed, or source hashes differ.
Server-coupled and configured-activation-risk operations require explicit
confirmation. A quarantined deletion also requires separate post-observation
confirmation. These are risk-specific fences, not extra audit modes.

```powershell
python -B scripts/gtm_execution_guard.py reconciled_operations.json context.json future_state_gate.json --approve OP-0001 --confirm-server-coupled OP-0001 --pretty
```

Add `--confirm-activation-risk` or `--confirm-observation` only for the exact
operation IDs whose corresponding evidence has been reviewed.

## Direct GTM/API/MCP

Preferred when human-readable GTM View Changes matters.

- Create a new dedicated workspace before mutation.
- Free GTM accounts may permit only three total workspaces, including the
  default. Warn and stop before cleanup when quota prevents creation.
- Modify existing objects in place when possible; preserve IDs and history.
- Create a new object only when the target architecture genuinely needs one;
  this includes first-class Zone and Google tag configuration entities when an
  approved target design requires them.
- Batch changes by dependency-safe operation, then read back and validate.
- Human approval may be grouped for readability, but execution remains atomic
  by operation ID so one failed mutation can stop without obscuring attribution.
- Delete only after every consumer is remapped and read back.
- Never work in or publish the default/live workspace without explicit request.

Recommended dependency order:

1. confirm canonical objects and business-specific names;
2. create approved terminal variables, tags, triggers, or templates;
3. add missing fields/list members and apply exact logic changes;
4. update tags and triggers that consume them;
5. flatten groups and sequencing safely;
6. apply final naming and folders;
7. delete obsolete objects;
8. full readback and future-state validation.

After final readback, regenerate sanitation, deterministic configuration
obligations, and business-architecture candidates. Reconcile any unexpected
result before requesting publication approval. Compare the complete readback
with the approved simulated future state; execution is not certified if any
expected field is missing, any unexpected field changed, or any difference
lacks one exact approved operation link.

## Import JSON

Create a real GTM container import JSON, never Markdown JSON or a partial object
list presented as importable.

Generate it from the simulated complete future export, then validate the full
effective container before delivery.

Import behavior may delete/recreate templates, tags, triggers, or variables and
can pollute View Changes. Same-container identity matching is not a reliable
substitute for direct in-place mutation. Choose overwrite/merge behavior
explicitly and explain the route.

Preserve:

- export wrapper and required metadata;
- enabled built-in variables;
- all referenced custom templates;
- clients, transformations, Zones, and Google tag configurations;
- folders and parent IDs;
- setup/teardown references;
- system trigger references;
- complete effective object graph.

For user-requested same-container review artifacts, validate the merged effective
container and warn that GTM may still recreate objects. Do not promise clean View
Changes from JSON.

## Custom Code

- Preserve exact GTM variable references unless the approved operation remaps them.
- Never replace a custom-JavaScript reference with an unrelated hardcoded value.
- Recheck escaping, output type, consent, DOM/storage/network behavior, and
  consumers after any edit.
- Prefer a native GTM feature or maintained template only when behavior and
  permissions remain equivalent.

## Consent And Server Routing

Consent, conversion value, transaction IDs, user data, media payloads, and
browser/server routing are high-impact. Require official-contract evidence,
challenge review, and exact readback. Do not change a web Google tag solely
because its measurement ID is absent when the export proves server-managed routing.
Do not add client blocking solely because transporter tags fire on every event
when the approved design forwards complete consent state for server-side
enforcement. Preserve and read back the forwarding parameter/variable chain;
change it only when the approved operation identifies a concrete gap.

## Validation And Stop Conditions

After each batch:

- verify that the readback is still a complete ContainerVersion with no
  malformed or unmodeled entity layer and no missing or duplicate object ID;
- fetch/read back changed objects;
- compare exact fields with approved structured actions;
- check references, names, templates, groups, built-ins, Zones, Google tag
  configurations, and consumers;
- update the field-level change record;
- preserve rollback instructions.

Stop immediately on workspace drift, unexpected object recreation, missing
reference, template mismatch, unapproved consent/value change, unknown business
token, API partial failure, or future-state gate failure.

Never publish or create a version unless separately and explicitly requested.
