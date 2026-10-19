# D4 Structure And Maintainability

Areas: A02 inventory, A03 references, A04 lifecycle and usage, A07 trigger conditions, A08
firing options and sequencing, A14 variables, A23 zones and environments, A24 naming,
folders and notes. Pack: `packs/D4*.md`. Follow objects and their chains end to end.

## Check

**References**
- Missing variables, triggers or setup tags.
- Names that differ only by Unicode or spacing.

**Lifecycle**
- Unused triggers and variables; paused tags; objects reachable only from paused tags; tags
  without triggers.
- Names that say test, old, copy or temp; live tags that depend on test objects.
- Remove only after `show` confirms no consumer, and judge paused chains with their owner.

**Triggers**
- Regex validity (JavaScript-only syntax is not invalid).
- Regex characters used with a literal operator.
- Catch-all conditions on firing triggers; very short URL contains-conditions.
- Click and form triggers without filters.
- Exceptions that never evaluate on the tag's firing event.
- Trigger groups fire once per page, so repeatable members lose occurrences.
- A Custom Event trigger's event is its `_event` condition.

**Firing options**
- A once-per-page cap on a repeatable event drops later occurrences. Judge each consumer
  with `siblings`: loaders and initialisation can be per page; business events usually
  cannot.
- Keep the cap in the diagnosis even when the intended recurrence is unknown, and ask
  instead of guessing; a cap that matches the vendor's documented contract for that event
  is correct (`keep`).

**Priority**
- Remove an explicit 0.
- Remove a nonzero priority only when no co-eligible tag starts on the same event. Keep it
  when there is a start-order need.
- Priority orders starts, not completion; use sequencing when completion matters.

**Sequencing**
- Setup tags that also send data on their own triggers send twice.
- Check `stopOnSetupFailure`; a sequenced tag inherits its parent's triggers.

**Variables**
- Data Layer Variable version 1 versus 2 paths; bracket notation is not resolved.
- Lookup and regex tables: row order, default value, matching mode.
- Custom JavaScript returns.
- Duplicate sources; a one-consumer indirection that adds nothing.

**Zones and environments**
- Hard-coded preproduction or environment IDs; child container boundaries.

**Naming**
- Follow `naming.md`.
- Source naming findings state the problem and the benefit; the integrator sets final
  names after deciding which objects survive.
- No style-only renames.

## Typical operations

- `delete` unused objects; `remove` the `priority` field.
- `set` a regex or condition value.
- `set` `tagFiringOption` to `ONCE_PER_EVENT` (usually `conditional` on the vendor's
  recurrence contract).
- `remap` a duplicate variable to its survivor, then `delete` it.
