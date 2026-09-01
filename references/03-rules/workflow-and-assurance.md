# Verified Dual-Audit Workflow

## Contents

- Authority and stage boundary
- Stages 1–7
- Isolation, repair, and fixed-point rules
- Speed and trust

## Authority And Boundary

The workflow authority is the sealed canonical JSON record. The analyst workbook
is a faithful decision surface, not an executable approval packet. This version
ends after one validated workbook. It does not mutate GTM, generate or apply an
import, create a GTM version, publish, certify readback, create a change log, or
compare completed audits.

The fixed workflow is:

```text
locked source/context/contract
  -> canonical deterministic scan
  -> independent raw-source assurance
  -> typed obligation ledger
  -> two host-isolated complete audits in parallel
  -> independent validation and seals
  -> reconciliation and targeted neutral verification
  -> exact target operations
  -> projected-container fixed-point proof and replay
  -> sealed canonical record
  -> evidence-locked editorial transformation
  -> one workbook plus technical/fidelity/reader/privacy gates
```

There is no three-run mode, reduced-depth mode, same-context fallback, or legacy
workbook path.

## Stage 1 — Evidence Gate

Accept one complete unambiguous ContainerVersion export or equivalent read-only
evidence. Lock source, context, skill identity, audit contract, vendor/template
registry, and optional approved requirement identities. Block partial identity,
invalid entity layers, duplicate IDs, or missing evidence that prevents a static
configuration judgment.

Start without a redundant confirmation only when the user named one resolvable
source, no competing source exists, complete identity can be read, and the
requested outcome is the full audit workbook.

## Stage 2 — Canonical Scan And Independent Assurance

Run every scan clause once and produce coordinate-bound facts for objects,
configured leaves and branches, references, consumers, terminal sources,
effective settings, firing/blocking topology, custom-code segments, consent,
routes, destinations, families, relationship candidates, and applicability.

The independent assurance path rereads raw JSON and recomputes, without calling
the scanner's corresponding derived logic:

- source hash, layers, IDs, and object identity;
- reference endpoints, consumers, and recursive variable sources;
- trigger/event/blocker identities;
- Google setting ownership and effective route/consent fields;
- destination and host identities;
- configured leaf, branch, recursive trace, and peer identities that own work;
- code objects, executable segments, line ranges, hashes, and parser status;
- matched/unmatched vendor identities and one canonical research owner;
- relationship candidate identity, members, type, coordinates, and owner; and
- exact 27-area coverage membership.

Any mismatch blocks semantic review. A mechanism may be inapplicable only with a
source-counted zero; it is never silently skipped. Assurance is intentionally a
critical-invariant recomputation, not a second full scanner.

Area ownership is explicit: area 1 is the evidence and assurance gate, areas
2–26 are complete semantic-audit obligations, and area 27 is the exact-operation,
projection, replay, and fixed-point control. Gate/control outcomes do not receive
invented semantic decision classes.

## Stages 3 And 4 — Two Complete Clean-Room Audits

Audit A starts from literal objects and chains, then closes families and the
container target. Audit B starts from destination, consent/routing ownership,
families, and the greenfield target, then proves every member and field. Both
complete every applicable semantic obligation in areas 2–26 using the same
decision schema.

Before approved external requirements are released, each audit seals a
source-only checkpoint. Audit B is also generated-candidate-blind until its
checkpoint. Later released candidates and requirements may add work, but cannot
rewrite checkpointed discovery.

Before reconciliation:

- each audit receives a separate allowlisted bundle and context ID;
- the execution host enforces a scope in which the peer bundle and prohibited
  downstream artifacts are inaccessible, then issues a receipt bound to the
  exact bundle manifest;
- neither can read the other's verdicts, scratch, discoveries, rationales, or
  target proposals;
- the orchestrator coordinates but authors neither result;
- sharding is allowed only by complete implementation family plus one shared-
  infrastructure unit;
- each audit performs global closure over shared configuration, consent, routing,
  destinations, identity, and architecture; and
- each complete audit is coverage-validated and immutably sealed.

The artifact validator proves bundle integrity, receipt binding, distinct context
IDs, coverage, and seals; it does not claim that self-authored JSON can prove host
access control. If the host cannot enforce both scoped contexts, block. An
amendment uses a fresh context bound to the prior seal and archives the previous
artifact and seal in append-only history.
Its audit artifact and fresh host receipt both cite the current prior audit-seal
hash while retaining the immutable source checkpoint and bundle identity. A
failed amendment leaves current and historical seals unchanged. Canonical sealing
closes this amendment path; later semantic repair uses a successor package.
Stage the new audit, new seal, and predecessor history together. A failed commit
must restore the prior current audit and seal byte-for-byte, remove partial
history, and clear staging. Every later sealed-audit gate revalidates the complete
contiguous parent chain and every archived audit, receipt, checkpoint, and release
binding; missing history is a blocker.
Restore only a target that the commit actually replaced, and only from a complete
hash-verified backup. If restoration itself cannot finish, retain the recovery
staging evidence and block all downstream work.

One workflow-wide identity registry owns context IDs and host-receipt IDs across
source checkpoints, current and historical source-audit seals, base neutrals,
projection reviews, projection neutrals, editorial versions, fidelity reviews,
and workbook-only reader reviews. An audit's initial checkpoint and seal are one
continuous owner and may carry the same IDs. Every different owner must use new
IDs. Stage-local pairwise uniqueness is insufficient; any cross-stage reuse
blocks before the affected artifact can seal.

## Stage 5 — Reconciliation And Neutral Verification

Compare atomic decisions by obligation, exact subject set, family, relationship,
and target. Classify agreement, compatible complementary conclusions, one-sided
finding, conflicting verdict, conflicting target, or different evidence boundary.
Do not vote, average, silently prefer an audit, or merge unmatched claims without
verification.

A fresh neutral verifier is mandatory for every disagreement or one-sided
finding and for all material-risk classes: consent ownership; client/server
routing; active deletion or consolidation; loader/destination/page-view,
ecommerce, paid-media, or identity change; code/template replacement; high-
fan-out or cross-market shared settings; unknown integrations; and projected High
or Critical operations.

The neutral bundle contains exact raw coordinates, independently reconstructed
facts, the contract, and a neutral question. It excludes audit identity,
rationale, vote count, and expected answer. The verifier may confirm, narrow,
reject, or keep the decision blocked; it cannot invent a third actionable target.
Every neutral bundle has its own deterministic manifest hash and one host-issued
isolation receipt bound to that hash. The neutral context and receipt must be
fresh against source checkpoints, both source audits, all peer neutrals, both
projection reviews, and every prior cycle; those prior contexts and prohibited
artifacts must be inaccessible.

## Stage 6 — Exact Operations And Fixed Point

Only reconciled and required-neutral-verified decisions enter target synthesis.
Operations support creates, additions, changes, named-field removals, remaps,
renames, pauses, and deletions with stable IDs, dependencies, exact source-bound
values, static
verification, and rollback. The synthesiser cannot make a new semantic choice.

Each projection cycle starts from the locked original and applies the complete
current packet in dependency order. Rerun the global scan and independent
assurance, regenerate obligations, and send every new or changed semantic
obligation through two fresh host-scoped projection reviews plus neutral verification
where required.

Record projected graph, scan, obligation, relationship, decision, and operation
hashes. A cycle is stable only when no new or changed actionable obligation
remains, prior operations still resolve their decisions, bounded outcomes remain
explicit, and scan plus assurance pass. Replay the stable packet once from the
locked original and require the complete hash tuple to match.

Allow at most three cycles including the first. Return
`non_convergent_target_state` when cycle three remains actionable, a prior hash
tuple recurs while actionable, a target oscillates, operations conflict, or no
exact safe operation exists. This block cannot be bypassed by dropping work or
weakening assurance.

Build a next-cycle candidate in an isolated staging directory. Validate the
candidate decision set, complete operation packet, consent-ownership safety,
global scan, and independent assurance before committing it. Commit packet,
projection decisions, and the cycle directory as one recoverable transition. On
any failure, restore the preceding packet and decision record, remove staging,
and return `non_convergent_target_state` with the deterministic reason.

## Stage 7 — Human Delivery

After fixed-point replay, seal one canonical record and transform it through the
rules in `references/03-rules/workbook-delivery.md`. The delivery layer may change
declared prose only. It cannot create a finding, target, operation, evidence
boundary, priority, or confidence value.

A missing or incorrect canonical delivery field stops Stage 7. Create a new
semantic-successor package from the same locked source, bind it to the sealed
predecessor canonical record plus an approved repair brief, and rerun all stages.
Each repair is released after source checkpoints as an obligation for both fresh
audits and neutral reconciliation. Stage 7 never patches or replaces a sealed
semantic record.

## Speed Without Weakening Trust

Speed comes from parallel Audit A/B work, family-local shards, one reusable fact
layer, focused assurance, targeted neutral checks instead of a third full audit,
per-shard validation, hash-bound resume, and deterministic workbook generation.
None may reduce obligation coverage, expose one audit to the other, turn judgment
into a fact, or skip projected closure.
