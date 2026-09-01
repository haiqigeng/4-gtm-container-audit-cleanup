# GTM Container JSON Guide

Use structured JSON parsing. Never audit a GTM export by regular-expression
search alone.

## Contents

- Root shapes and typed parameters
- References, edges, and source-bound facts
- Tags, triggers, variables, code, and templates
- Web-container scope and completeness

## Root Shapes

A standard export normally stores objects under `containerVersion`. Some API or
test artifacts expose the version object directly. Normalize both shapes before
analysis and preserve the original wrapper for generated artifacts.

Common layers:

| Layer | ID field |
| --- | --- |
| tag | `tagId` |
| trigger | `triggerId` |
| variable | `variableId` |
| folder | `folderId` |
| Zone | `zoneId` |
| custom template | `templateId` |
| built-in variable | `name` |
| Google tag configuration | `gtagConfigId` |

Before building semantic facts, fail closed when the source is not a
ContainerVersion, a known entity layer is not an array, an entry is not an
object, a required ID is blank/duplicated, or an unknown top-level list could
represent an unmodelled entity layer. Do not silently treat a Container
resource as a ContainerVersion or skip an empty future layer.

Read account/container IDs, public ID, usage context, export/version metadata,
and custom-template references from the export instead of asking the user when
already available.

## Parameters

GTM parameters are typed trees, not a flat dictionary. Values may appear in:

- `value` for scalar/template values;
- `list` for ordered items;
- `map` for key-value entries;
- nested parameters inside list/map values.

Preserve type, key, order, and nested shape. A list of item objects is not
equivalent to a scalar string containing JSON.

## References And Edges

Extract `{{Variable Name}}` from every string field, including code and nested
maps. Build edges for:

- tag/trigger/variable/template references;
- firing and blocking triggers;
- trigger-group members;
- setup and teardown tag names;
- Zone boundary evaluation trigger IDs;
- parent folders;
- custom-template type IDs.

Recognize GTM internal references such as `{{_event}}` and high-range system
trigger IDs. Built-in variables terminate a recursive trace and are not missing
custom variables.

## Source-Bound Facts

For every configurable object retain:

- `layer:id` object key;
- name, type, active/paused status;
- stable configuration hash after removing export metadata;
- exact source JSON path;
- leaf paths, value hashes, safe previews, and referenced variables;
- consumers and relation paths;
- code line number/hash/preview where applicable.

These fields are immutable in completed reviews. A changed value or source hash
invalidates reuse.

## Tag Routes

Do not label a tag triggerless until checking:

- `firingTriggerId` and system routes;
- whether another tag invokes it through `setupTag` or `teardownTag`;
- paused/scheduled state.

Blocking triggers, setup/teardown sequence, priority, consent settings, and
event parameters all contribute to execution logic.

## Trigger Conditions

Read all filter families and nested parameter nodes. Normalize operator, left
input, right value, case/modifier flags, and regex literals. Convert only
provably equivalent anchored/contains regex patterns for comparison; keep the
raw source as evidence.

Trigger groups require member expansion and cycle checks. A group is not a
simple OR: preserve GTM group semantics when designing an optimisation.

## Variables

Inspect variable type and all fields. For data-layer variables record path and
dataLayer version. For lookup/regex tables retain every row, default, matching
mode, and input variable. For URL/cookie/DOM/auto-event variables record the
exact source and output expectation. For custom JavaScript inspect all code.

Recursion ends at a concrete configured terminal or explicit missing/cycle/
ambiguous state, never at another variable's name. When duplicate custom names
or custom/built-in collisions exist, retain every possible object edge rather
than selecting one by dictionary order.

For every recursive node retain its configuration hash, source branches,
downstream hop, literal configured function, output type/shape, fallback and
event availability, and compatibility with the consuming object.

## Custom Code And Templates

Custom HTML code usually lives in parameter `html`; Custom JavaScript in
`javascript`; custom-template source in `templateData`. Preserve all nonblank
lines and hashes. Extract URLs, scripts, GTM references, dataLayer use, browser
storage, cookies, DOM operations, listeners, network calls, globals, return
shape, and parser facts without treating static signals as final judgments.
An absent or failed parser is itself an explicit coverage fact; it never turns
empty AST output into evidence that no parser-level issue exists.

## Web-Container Scope

Require WEB in `usageContext`. Identify client-side transport URLs, destinations,
consent-forwarding parameters, direct-browser branches, and mixed routes, but do
not infer or inspect downstream server-container processing. Reject a SERVER
ContainerVersion instead of switching audit modes.

## Complete Sources

The audit operates on one full source graph, never an import patch or changed-only
fragment. A standard GTM export envelope may omit empty web layers; equivalent
read-only evidence must enumerate them. Apply the same identity and shape gates
to every fixed-point projection.
