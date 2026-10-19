# Audit Policy

Every role applies these rules.

## Goal

Judge the container as if a senior web analyst rebuilt it today from an empty container
for the same proven needs. Report what is wrong, what is materially simpler, and what
should stay; turn every justified change into exact operations.

## Classes

| Class | Use when |
| --- | --- |
| `defect` | The configuration is wrong (`basis: source`) or departs from the selected policy below (`basis: policy`) |
| `optimisation` | Behaviour is correct but a simpler or lower-drift design keeps every required behaviour |
| `keep` | A design that looks questionable has a positive, source-visible reason to stay |
| `decision` | A real business, policy, lifecycle or ownership choice belongs to the owner |
| `evidence_limit` | The conclusion needs evidence outside the container |

- A known defect stays a defect even when its fix needs an answer: use readiness
  `conditional` or `blocked` and put the missing answer in `question`.
- A missing approval does not prove the deployed configuration is wrong.
- Ordinary reviewed objects need no finding. Write `keep` only when a reader would
  otherwise expect a change.

## Readiness

- `ready`: the operations are written and the source establishes every behaviour the
  operations change.
- `conditional`: the operations are written but depend on a stated answer.
- `blocked`: the operations cannot be written until the answer arrives.

Work is never more ready than what it relies on. When one of these is not established,
it is `conditional` on that question (same text in every finding that waits on it):
- **Receivers of data leaving the container.** Data that leaves the container (event
  names, parameters, user properties, identity fields, routes) can have receivers you
  cannot see: a GA4 property's reports and custom definitions, a server container, a
  vendor. Removing or renaming such data is `ready` only when the source shows it is
  broken or unused, or context approves it. Otherwise it is `conditional`, and
  `question` names the receiving system to confirm.
- **Outside work.** Work that needs something done or confirmed outside the operation
  first (credential rotation, a server or vendor change, an owner's environment intent).
  The operation's `preconditions` name it, so a `ready` operation has no preconditions.
- **Prerequisites:** its `depends_on` operations.
- **Values with an open meaning:** every value it newly sends whose source or meaning
  another finding leaves open. Moving the same values into a shared settings variable,
  or remapping to an exact alias, sends nothing new.
- **Its own operations:** a finding is never more ready than the operations it links.
- **Consent for a new collection path.** An operation that gives a vendor tag a new
  collection path (activation, code that now executes, a broadened or added trigger)
  needs a consent predicate in its own `depends_on` closure.

`check` and `finalize` enforce these with exactly each operation's declared
prerequisites, except the source behaviour and the receivers, which the verifier judges.
They also show every setting a tag stops sending, including inherited or shared settings
on tags the operation does not edit.

- If you can write a supported operation, write it. Leaving it out is unfinished work,
  not an owner question.
- Objects in `do_not_touch` (summary context) get no operation; a defect on one is a
  `decision` for its owner.

## Priority

Priority combines impact, reach and certainty:

| Priority | Rule of thumb |
| --- | --- |
| Critical | Personal data or secrets exposed, or tags firing for refusing visitors on a main route |
| High | Wrong or lost conversion, revenue or consent data; a broken main tag; a policy departure on an ad route |
| Medium | Partial data loss, duplicated or inconsistent data, fragile code on a secondary route |
| Low | Maintenance cost, clutter or naming with no data effect |
| None | `keep` findings |

## When to propose a change

Propose an optimisation only when all of these hold:
- repetition or complexity is visible;
- a native GTM mechanism supports the target;
- every material distinction is preserved;
- the benefit is concrete;
- the change is expressible as exact operations;
- nothing about runtime is assumed.

Prefer native GTM, then a maintained gallery template, then custom code. Replace code only
when value, type, timing, consent, route and destination stay equivalent.

## Removal and consolidation

- Before removing or merging, find every consumer (`show`) and remap it in the same set
  of operations.
- Never delete because of age, pause status, a name, or equal current values alone.
- An object nothing uses is a removal candidate; a paused-only chain needs its owner's
  intent first.
- **Near-duplicates.** Classify each difference as irrelevant metadata, a required
  behavioural difference, or a finite difference one common design can express.
  - Different values today do not prove the objects must stay separate; equal values
    today do not prove they are interchangeable.
  - Check value type, missing/null behaviour, timing, listener settings, regex flags,
    event scope, consent, destination and consumers.
  - Keep purposeful variants such as distinct destinations or markets.
- A merged trigger must match exactly the same occurrences as the originals, including
  case and match boundaries, and keep every exception.
- Shared Google settings: configuration-wide values go on the configuration owner. Event
  parameters repeated across a compatible group go in one Event Settings variable for that
  group. Event-specific values and justified overrides stay local.

## Consent policy (selected policy for this audit)

| Route | Positive trigger | Consent owner |
| --- | --- | --- |
| Consent infrastructure (CMP, consent default/update) | Consent Initialization or the CMP's documented event | The consent writer; never vendor-gated |
| Advanced Consent Mode (destination in `consent_mode_destinations`) | Normal page or business event | Consent defaults/updates plus Google's built-in behaviour |
| Pure client-to-server transport (host in `consent_owned_hosts`) | Normal event | One shared consent value forwarded to the approved host |
| Any other vendor route | Consent-free trigger for the real event | One reusable denial blocker per vendor, purpose or category |

- A denial blocker must fail closed: it blocks when consent is absent, unknown or denied.
- Do not put consent in positive triggers or Additional Consent Checks on non-Advanced
  routes.
- Without an approved destination or host in context, Google tags follow the last row;
  `simulate` rejects removing every consent control from any other tag.
- A departure from this table is a `defect` with `basis: policy`, even when the exact fix
  needs a CMP mapping or owner answer.
- About server routes, conclude only that the client transport and consent forwarding are
  aligned or not aligned; downstream server enforcement is outside this audit.

## Evidence

- Use complete source evidence: `show` objects before concluding.
- Candidates are leads, not verdicts. Look beyond them.
- A detector's silence proves nothing.
- Do not infer behaviour from names alone. Keep the configured value's type: `false`
  (boolean) is not the text "false", and a missing field is not an empty one. Follow each
  payload value to its producer (`show`, or the pack's Value sources) and check its shape
  (array or object, which item), type, empty and zero handling, units (price versus
  discount) and quoting when it is inserted into code.
- Firing triggers are alternatives, conditions inside a trigger all apply, and an exception
  blocks only on an occurrence it can match. A sequenced tag inherits its parent's firing.
- When you find a pattern on one object, run `siblings` and decide the whole family in
  one finding with explicit exceptions.
- Unknown external contracts (vendor recurrence, CMP serialisation, server ownership) make
  the dependent change `conditional`, `blocked` or `evidence_limit`. They never justify
  inventing a runtime failure or clearing the issue.
- Research an unknown vendor contract once, at its official documentation, and cite it.

## Writing

Every text a reader sees is written for a web analyst who has not seen the container and
must decide what to do. These texts are the finding's `title`, `situation`, `impact`,
`recommendation` and `question`, the operation's `title`, `preconditions`, `verification`
and `rollback`, and the summary.

- Cite GTM objects by key (`tag:191`); the workbook shows each by type and name. Name a
  field by its GTM label (Tag firing options, Triggering, Exceptions, Event parameters) and
  a value as GTM shows it.
- `title`: the problem in a few words.
- `situation`: what is configured and what happens as a result, with the values that show
  it, so the reader can see it in GTM. Say so when a step is inferred. For a policy
  departure, name the consent rule it departs from and what it lets happen.
- `impact`: what is lost, doubled, wrong or sent without consent, for which events, pages
  or tools; for `keep`, why the design stays.
- `recommendation`: the end state in one sentence that starts with a verb. The steps come
  from the operations.
- `question`: asks for the value or decision itself, as one closed question with its
  options and what each changes.
- Operation `title`: the change in a few words. `verification`: what to do in Preview and
  what to see. `rollback`: how to undo it in GTM.
- At most three short sentences per text, one idea each, in the context language (French
  or English). Common GTM and GA4 terms are fine; explain anything else or leave it out.
  Event, parameter and object names stay exact.
- Each finding reads on its own. One finding covers a family and names its exceptions.
- Never invent scores, savings, runtime success, vendor receipt or legal approval.
- Never copy secrets or personal values; the engine masks them, so cite the object and field.

Example: `title` "Add-to-cart tag sends only the first add-to-cart per page". `situation`
"tag:191 fires once per page (Tag firing options), but its trigger trigger:177 fires on
every add-to-cart." `impact` "From the second add-to-cart on a page, Easyence receives
nothing, so carts filled from product lists are under-counted." `recommendation` "Let the
tag fire on every add-to-cart."
