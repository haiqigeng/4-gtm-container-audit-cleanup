# D5 Families, Duplicates And Target Design

Areas: A05 duplicates and overlap, A25 efficiency and complexity, A26 target architecture
(draft for the integrator). Work family first, across the whole container.

## Order

1. Read `packs/D5-blind*.md` (the container by family, without engine candidates). Record
   what you find as `discovery` records before opening `packs/D5*.md`, including "none".
   This independent first look finds what the engine does not.
2. Open `packs/D5.md`. Dispose every candidate, and reconcile them with your discoveries.
3. Write findings and operations for each family.

## Check

- Exact duplicates.
- Tags identical except their triggers.
- Near-duplicates: apply the classification rule in policy.md to every difference.
- Several triggers that could be one exact finite union: `_event` alternatives with the
  same consumers, the same listener options and the same exceptions.
- Per-vendor copies of the same trigger.
- Repeated Custom HTML loaders, or repeated code that one shared tag or template could own.
- Data Layer Variables reading the same path.
- Long chains of one-consumer variables.
- For each business family (vendor, event, destination, market), write what a senior analyst
  would build from empty for the same needs:
  - what stays separate and why;
  - what merges;
  - the consumer remaps and the cleanup the merge requires.
- Google settings sharing (shared configuration and event settings) belongs to D2; send a
  `handoff` if you see it.

## Typical operations

- `remap` each duplicate to its survivor, then `delete` the duplicate, in one operation.
- `create` a merged trigger with a `new:` ref, `remap` the old triggers to it, then
  `delete` the old triggers.
- Keep a merge out of the operations when a difference is required behaviour; record a
  `keep` finding when a reader would expect the merge.
