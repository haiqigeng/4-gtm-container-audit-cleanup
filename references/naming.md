# Naming

Names help an analyst find and maintain objects. Propose a rename only for a concrete
benefit: a misleading role, an ambiguous difference, a collision, an inconsistency that
causes mistakes, or a placeholder or test name on a live object. Keep clear names even when
another style is possible, unless the user supplied a convention that requires the change.

## Which convention

1. The user's supplied convention (`naming_convention` in context), even when freeform.
2. Otherwise the container's own usable convention: consistent order and separators,
   readable role and scope, adopted by most objects (see `tag_name_prefixes` in the summary).
3. Otherwise these defaults:

| Layer | Pattern | Example |
| --- | --- | --- |
| Tags | Vendor - Event - Scope | GA4 - purchase - All |
| Custom Event triggers | CE - event_name | CE - LeadSubmitted |
| Page view / URL triggers | PV - Condition | PV - Hostname FR |
| Click triggers | LC - Description | LC - Newsletter CTA |
| Form triggers | FORM - Description | FORM - Newsletter |
| Blocking triggers | Block - reason | Block - Analytics consent denied |
| Trigger groups | TG - event Vendor Scope | TG - purchase GA4 All |
| Variables | Type acronym - source or purpose | DLV - ecommerce.items |
| Folders | Area | Ecommerce |

- Vendor acronyms: GA4, GADS, PA and the like, when they are clear; otherwise the full name.
- Variable prefixes: DLV, CJS, LT, RT, URL, 1P, JS, Const, Util.

## Rules

- Copy configured event names exactly, including case, accents and vendor syntax. Renaming
  an event is a behaviour change, never a naming fix.
- Name the actual role. A blocking trigger names its condition and event scope. A CMP or
  vendor name alone is not a role.
- Never encode a temporary fault or a repair instruction in a name.
- Names are unique within their layer. Add only the smallest qualifier that explains why
  two objects stay distinct.
- Structural changes, such as removing a one-member trigger group, are separate operations,
  not renames.

## Who does what

- Workers record naming problems as findings with the benefit; they write no `rename`
  actions.
- After deciding which objects survive, the integrator writes rename operations grouped by
  rule (one operation per coherent rule), referencing the naming findings.
- An object being removed gets no rename.
- `rename` rewrites variable references and setup/teardown tag names automatically;
  `finalize` rejects name collisions.
