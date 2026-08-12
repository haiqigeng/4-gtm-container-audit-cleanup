# Post-Execution Change Log

Produce this separately after direct cleanup or import-artifact generation.
Before execution, call it a planned preview or simulated change log.

## Required Granularity

Use one row per changed object field or dependency so a user can understand the
work without GTM View Changes.

Required information:

- change ID and approved operation ID;
- object layer, ID, and before/after name;
- change category and exact field path;
- before and after value or dependency;
- human reason and functional impact;
- QA method and status;
- rollback;
- blocker and execution status.

For additions/deletions, include the whole object as one creation/deletion row
plus material dependency rows when needed. Do not create no-op rows for untouched
templates, built-ins, tags, triggers, or variables.

## Workbook Shape

Keep the change log readable and separate from audit proof. A practical workbook
uses:

- visible Summary;
- visible Detailed Changes;
- optional hidden operation/source proof.

Use six or fewer columns by consolidating closely related fields. Do not repeat
the same sentence in reason, impact, and QA columns. This limit applies to
hidden proof tabs as well as visible tabs.

## Status Integrity

- `Applied and verified` only when linked to an approved operation and observed
  in a final complete readback whose certification passes;
- `Proposed` for planned previews;
- `Blocked` when execution failed or lacks operation linkage;
- `Requires verification` when readback has not been completed.

The final complete before/readback diff is the sole authoritative executed
result. API responses and intermediate batch records are provisional. Never
invent a change log from the plan, and never build an executed workbook from a
failed or absent certification.

Before diffing, validate both before and after sources as complete
ContainerVersion artifacts. Block the change log on malformed or unmodeled
entity layers, missing IDs, or duplicate IDs; positional matching or
first/last-wins identity would create false attribution. Diff every modeled
layer, including built-ins, folders, templates, clients, transformations,
Zones, and Google tag configurations, even when only some layers changed.

Approval linkage is field-specific, not object-specific. Replay approved
operations in order and link only an exact layer, object ID, action, field path,
before value, and after value. An unexpected field on an object that also has an
approved change remains `Blocked: missing approved operation link`.

Escape spreadsheet-formula prefixes and privacy-scan visible and hidden tabs.
