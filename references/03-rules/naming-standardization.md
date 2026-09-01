# Naming Standardization

Use this reference whenever the audit or exact target plan includes naming review
or rename operations. Naming follows semantic canonicalisation; this skill does
not execute the rename.

## Contents

- Decision Hierarchy
- Canonical Audit And Delivery
- Default Patterns
- Vendor Acronyms
- Semantic Family Rules
- Case Rules
- Uniqueness And Blockers
- Rename QA

## Decision Hierarchy

Apply naming after semantic fixes, consolidation design, and deletion decisions
are known, so remaining objects receive stable final names.

1. Follow user-provided naming models or examples.
2. If no user model exists, infer the dominant local convention: separator
   style, object order, vendor acronyms, event casing, trigger-role prefixes,
   variable type prefixes, folder grouping, and suffixes.
3. Score whether the local convention is usable: broad adoption, consistent
   ordering, readable event/scope tokens, clear trigger role prefixes, and no
   misleading legacy labels.
4. Preserve meaningful local acronyms when the configuration proves them, for
   example `PA` for Piano Analytics.
5. Standardize semantically equivalent objects within the same object layer and
   family. Do not keep mixed labels only because they already exist.
6. If the local convention is usable, recommend `local-normalized`: keep the
   local order and vocabulary, then fix inconsistent objects.
7. If the local convention is missing, weak, or harmful, recommend
   `default-standardized` and use the integrated default patterns below.

## Canonical Audit And Delivery

Every naming obligation receives one canonical semantic decision. Record the
selected policy (`user-provided`, `local-normalized`, or `default-standardized`),
the source evidence and confidence, representative compliant names, uniqueness
status, and every owner blocker in that decision.

When a rename is materially justified and exact, encode each object-level rename
in the decision's operation proposal. Delivery maps that operation to exactly one
visible Recommendations row, with before/after names, object identity, rationale,
static verification, rollback, and row-bound technical comments. When no rename
is justified, the canonical audit decision explains why the current naming is
retained. When meaning is ambiguous, use an owner-decision or container-evidence-
limit decision rather than inventing a target.

Do not create a separate optimisation-plan row, rename-map tab, deterministic proof
tab, or hidden decision surface. Naming detail remains traceable through the
canonical audit decision, its exact operation when actionable, and comments on
the owning visible workbook row.

Do not invent business tokens to fill a name. If a proposed name cannot be made
unique without a new scope token, mark the row as owner-decision-needed rather
than adding an arbitrary suffix as the preferred final name.

## Default Patterns

| Layer | Pattern | Examples |
| --- | --- | --- |
| Tags | `Vendor - Event - Scope` | `GA4 - purchase - All`, `GADS - purchase - IGGI`, `PA - page.display - All`, `Meta - PageView - All` |
| Custom Event triggers | `CE - event_name` | `CE - view_item`, `CE - add_to_cart`, `CE - purchase` |
| Pageview / URL triggers | `PV - Condition Scope` | `PV - Hostname FR`, `PV - Homepage DE`, `PV - Contact Form CH` |
| Click triggers | `LC - Description Scope` | `LC - Homeslide`, `LC - Distributor CTA FR` |
| Form triggers | `FORM - Description Scope` | `FORM - Newsletter`, `FORM - User Provided Data` |
| Blocking triggers | `Block - condition_or_reason` | `Block - Consent Refused`, `Block - Internal Traffic`, `Block - Missing Ecommerce Items` |
| Trigger groups | `TG - event Vendor Scope` | `TG - purchase GA4 All`, `TG - add_to_cart Meta EU`, `TG - page_view GADS All` |
| Variables | `Type acronym - Variable name/source` | `DLV - ecommerce.items`, `CJS - Cart Total Price`, `LT - Currency`, `Util - Page URL` |
| Folders | `Area` by default | `GA4`, `Media`, `Consent`, `Utilities`, `Ecommerce` |

Use area-only folders by default. Split folders into `Area - Scope` only when a
folder becomes too large to navigate or the user provides a folder taxonomy.

## Vendor Acronyms

Use full vendor names or acronyms consistently. Prefer acronyms when the vendor
name is long or the local container already uses the acronym coherently.

Suggested defaults:

- `Google Analytics 4`: `GA4`
- `Google Ads`: `GADS`
- `Piano Analytics`: `PA`
- `Tradedoubler`: `TD`
- `The Trade Desk`: `TTD`
- `Display & Video 360`: `DV360`

Variable type acronyms:

- `DLV`: Data Layer Variable.
- `CJS`: Custom JavaScript variable.
- `LT`: Lookup Table.
- `RT`: Regex Table.
- `URL`: URL variable.
- `1P`: first-party cookie.
- `JS`: JavaScript variable.
- `Const`: constant.
- `Util`: utility/helper when the source is mixed or abstract.

## Semantic Family Rules

- Put the destination/platform first for tags, then event, then scope.
- Put the trigger utility or condition first for triggers.
- Put the implementation/source type first for variables.
- Avoid redundant layer prefixes such as `TR -`; GTM already shows the object is
  a trigger.
- Use `CE` for Custom Event triggers, `PV` for pageview or URL/hostname
  triggers, `LC` for link-click triggers, `FORM` for form-submit triggers,
  `Block` for blocking triggers, and `TG` for trigger groups.
- Flatten single-member trigger groups before final naming only when the sealed
  target architecture independently proves that deletion is safe.
- Treat vendor/CMP names as vocabulary, not role names. If `Didomi - ...`,
  `Consent - ...`, and `Block - ...` triggers all block a vendor because consent
  is denied, standardize them under the blocking-trigger pattern. Keep `Didomi`
  only when the trigger is truly a CMP event/state trigger.
- Put market, language, product range, campaign, pixel/account ID suffix,
  consent category, sequence role, or lifecycle status after the event/role in
  the scope/detail position.

## Case Rules

- When an object name contains a configured event literal, copy that literal
  exactly instead of humanising it. GA4 event literals therefore remain
  lowercase, such as `purchase` or `add_to_cart`; vendor literals retain their
  official casing, such as Meta `PageView`, `ViewContent`, or `Purchase`; and
  dotted events such as Piano `page.display` remain unchanged.
- Preserve every technical key exactly.
- Keep acronyms uppercase, such as `PA`, `GA4`, `GADS`, `CMP`, `DLV`, `URL`,
  and `JS`. Use `CJS` for Custom JavaScript variables when following the
  integrated default.
- Use sentence case for human-authored role, reason, and scope labels, such as
  `Analytics consent denied` or `Newsletter CTA`; this rule never changes an
  event literal.
- Do not mix `Page Display`, `page Display`, `PAGE DISPLAY`, and
  `page_display` for the same concept unless the destination's official event
  name requires it.

## Uniqueness And Blockers

Every proposed final name must be unique inside its GTM object layer. If a base
pattern collides, add the smallest meaningful suffix that explains why the
object remains separate: trigger event, page type, market, product range,
campaign, destination ID suffix, consent category, sequence role, or lifecycle
status such as `Legacy`, `Paused`, or `Decommission candidate`.

Use an object ID suffix only as a temporary audit placeholder when the real
business distinction is unknown. Mark the row as blocked for owner
clarification; do not treat the ID-suffixed name as a preferred final name.

Do not invent meanings for internal tokens. If a meaning cannot be inferred and
changes the safe rename, retain it as an owner decision and let the agent ask for
the smallest necessary clarification in context.

## Rename QA

Before proposing any exact rename:

- define the final convention for tags, triggers, variables, folders, and
  templates when relevant;
- decide event names from official vendor documentation when applicable;
- map all consumers and dependencies;
- dependency-sweep every renamed variable across tags, triggers, variables,
  lookup tables, templates, Custom HTML, and Custom JavaScript;
- dependency-sweep every renamed trigger/tag for setup/teardown `tagName`
  references, sequencing, trigger groups, and owner references where evidence is
  available;
- record before name, after name, object ID, reason, expected behavior impact,
  static verification, rollback, and any owner blocker in the canonical decision
  and operation proposal.
