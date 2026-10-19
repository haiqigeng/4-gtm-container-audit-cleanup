# Records

Save work with `add OUT --worker <W> --file <file or ->`. A file holds one JSON object, a
JSON list, or one object per line. Invalid input saves nothing and the error says why.
Adding a record with an id you already own replaces it. Object keys are exact: `tag:12`,
`trigger:5`, `variable:7`, `template:3`, `folder:4`, or `container`.

## Finding

```json
{"type": "finding", "id": "D4-F01", "area": "A08", "title": "Add-to-cart tag sends only the first add-to-cart per page",
 "class": "defect", "basis": "source", "severity": "High", "objects": ["tag:191", "trigger:177"],
 "situation": "tag:191 fires once per page (Tag firing options), but its trigger trigger:177 fires on every add-to-cart.",
 "impact": "...", "recommendation": "...", "question": "...",
 "readiness": "conditional", "operations": ["D4-OP01"], "candidates": ["C-018"]}
```

| Field | Rule |
| --- | --- |
| `id` | Starts with your worker name: `D4-F01`, `INT-F02` |
| Texts | `title`, `situation`, `impact`, `recommendation`, `question`: follow Writing in policy.md and cite objects by key. Ids, area codes and paths belong in their own fields |
| `area` | One of A02–A26 (listed in your domain file and below) |
| `class` | defect, optimisation, keep, decision or evidence_limit |
| `basis` | Defects only: `source` or `policy` |
| `readiness` | ready, conditional or blocked for defects and optimisations; omit (n/a) otherwise |
| `operations` | Required when readiness is ready or conditional |
| `question` | Required for decision, evidence_limit, conditional and blocked |
| `candidates` | Candidate ids this finding confirms |

Areas: A02 inventory, A03 references, A04 lifecycle and usage, A05 duplicates, A06 tag and
template configuration, A07 trigger conditions, A08 firing options and sequencing, A09 CMP
and consent infrastructure, A10 direct consent architecture, A11 Advanced Consent Mode, A12
client-to-server transport, A13 server handoff boundary, A14 variables, A15 Google settings
ownership, A16 destinations, loaders and page views, A17 GA4 events and parameters, A18
ecommerce, A19 ads and vendors, A20 value semantics, A21 identity, personal data and
secrets, A22 custom templates and code, A23 zones and environments, A24 naming, folders and
notes, A25 efficiency and complexity, A26 target architecture.

## Operation

```json
{"type": "operation", "id": "D4-OP01", "title": "Fire the tag on every add-to-cart", "findings": ["D4-F01"],
 "actions": [{"do": "set", "object": "tag:191", "path": "tagFiringOption", "value": "ONCE_PER_EVENT"}],
 "depends_on": [], "preconditions": "Vendor confirms repeated calls are expected.",
 "verification": "Preview: two add-to-carts on one page fire the tag twice.",
 "rollback": "Set Tag firing options back to Once per page."}
```

`title`, `preconditions`, `verification` and `rollback` follow Writing in policy.md.

Actions:
- `set` / `add` / `remove`: `{"object", "path", "value"}`. `add` appends to a list;
  `remove` takes no value.
- `create`: `{"layer": "tag|trigger|variable|folder", "ref": "new:trigger:cart", "object": {complete GTM object with name}}`.
  Later actions and lists can use the ref, for example `"firingTriggerId": ["new:trigger:cart"]`.
- `delete`, `pause`, `unpause`: `{"object"}`.
- `rename`: `{"object", "name"}`. Variable references and setup/teardown tag names are
  rewritten automatically.
- `remap`: `{"from", "to"}`. Every consumer of `from` (a trigger, variable or tag) is
  pointed to `to`.

Path segments:
- A plain key: `tagFiringOption`, `consentSettings.consentStatus`.
- `parameter:<key>` selects a parameter by key; `map:<key>` selects a map entry.
- `[i]` selects a list position.
- `row:<field>=<value>` selects a table row; the value may contain dots
  (`row:parameter=user_data.email_address`).

Path examples:
- `parameter:eventName.value`
- `parameter:eventSettingsTable.list.row:parameter=currency.map:parameterValue.value`
- `blockingTriggerId`

`preconditions` lists only work or facts outside this operation that must hold before it is
applied (credential rotation, server change, owner confirmation; Readiness in policy.md).
Notes about what the change preserves belong in `verification` or the finding.

Operations stay separate when a client could apply them independently; combine actions
only when correctness needs them together. Use `depends_on` for real ordering. Actions run in
the order written, after the operation's prerequisites; the workbook lists each finding's
changes in that order and describes every step in the state it applies to. `check`
simulates your operations against the source and reports broken references (variables,
triggers, tags, folders, templates), name collisions, conflicting writes (two operations
writing the same field or row, when neither depends on the other), changes to protected
objects (`do_not_touch`), tags losing every consent control unless their destination or
server host is approved in context, and ready work that relies on a prerequisite or a
value still waiting for an answer.

## Other records

- `{"type": "dismiss", "candidates": ["C-021", "C-022"], "reason": "..."}`: candidates
  reviewed with no material issue. Give the real reason.
- `{"type": "discovery", "note": "...", "objects": [...]}`: D5 blind-pass observations.
- `{"type": "handoff", "to": "D1|D2|D3|D4|D5|integrator", "note": "...", "objects": [...]}`:
  an issue outside your areas.
- Integrator only: `decision` and `summary`. Verifier only: `verdict`. See their briefs.
