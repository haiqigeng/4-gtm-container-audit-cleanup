# Domain And Vendor Contracts

## Contents

- Contract ownership
- Google settings and triggers
- GA4 and ecommerce
- Consent and CMP
- Client-to-server transport and server evidence boundary
- Vendor integrations, templates, and Zones

## Contract Ownership

Use `vendor-registry.toml` first. For an unknown product, host, template, event,
or field, assign one deterministic research owner and link every dependent object
to it. Classify affected obligations as `container_evidence_limit`, state the
current official HTTPS source, access date, and applicable version needed, and
block dependent recommendations. Never update the registry during an audit.
Registry maintenance requires a separate explicitly requested skill-evolution
change and a new source-locked package. Help text, comments, licenses, generic
parameter words, and GTM UI URLs do not establish a vendor identity.

One object may implement several integrations. Preserve every behaviour-bearing
vendor/host and unmatched route as a separate obligation. A product contract
establishes expected syntax or semantics; it does not prove runtime behaviour or
that the supplied object meets the contract.

## Google Settings And Triggers

Primary sources:

- Google tag settings:
  https://support.google.com/tagmanager/answer/12131703
- reusable event settings:
  https://support.google.com/tagmanager/answer/13438771
- GA4 tags in GTM:
  https://support.google.com/tagmanager/answer/9442095
- triggers and exceptions:
  https://support.google.com/tagmanager/answer/7679318
- regex trigger operators:
  https://support.google.com/tagmanager/answer/7679109
- firing priority:
  https://support.google.com/tagmanager/answer/2772421
- tag sequencing:
  https://support.google.com/tagmanager/answer/6238868

Resolve effective values across Google tag/configuration, Configuration Settings
variables, Event Settings variables, event tags, and local overrides. Put
configuration-wide values in one configuration owner; put only truly shared
event values in Event Settings; keep event-specific parameters local. Repeated
effective values are candidates, not automatic consolidation. Prove type, timing,
destination, route, consent, source, and ownership compatibility first.

Event Settings can be applied to selected GA4 Event tags, not only to a Google
tag's general event settings. Evaluate a scoped shared bundle when an existing
global owner would spread fields too widely. Preserve each consumer's effective
inherited and local values, including justified overrides and variable evaluation
semantics. The reusable-event-settings documentation above confirms this
capability (consulted 2026-09-03); the choice of a useful group and its maintenance
benefit remains an evidence-based audit judgment.

A firing trigger defines occurrence; an exception/blocker suppresses eligibility
when both match the same event. Explicit priority controls start order only among
co-eligible tags. It does not wait for asynchronous completion. Remove explicit
zero, priority without a real competitor, and priority already represented by
sequencing.

For a proposed union of literal trigger alternatives, inspect the actual operator
semantics and all shared conditions and consumers. Preserve case, exact-string
boundaries (including line terminators), input types and listener options. The
availability of a regex operator does not prove that a proposed regex is equivalent
or that consolidation is appropriate. Source: Google Tag Manager's regex operator
documentation above, consulted 2026-09-03; the equivalence assessment is analyst
reasoning, not a claim that Google recommends every consolidation.

## GA4 And Ecommerce

Primary sources:

- events:
  https://developers.google.com/analytics/devguides/collection/ga4/reference/events
- recommended events:
  https://developers.google.com/analytics/devguides/collection/ga4/reference/recommended-events
- ecommerce:
  https://developers.google.com/analytics/devguides/collection/ga4/ecommerce
- event naming:
  https://support.google.com/analytics/answer/13316687

For each GA4 event inspect name, event trigger, destination, route, inherited and
local parameters, types, availability, user data, consent architecture, and
duplicate page-view/event ownership. Prefer recommended semantics only when they
fit the proven business action. The absence of a tag is not proof that an event
should exist.

For ecommerce inspect the complete `items` array, item fields, value/currency,
quantity, transaction/refund linkage, tax/shipping/coupon, duplicate routes,
legacy schemas, fixed product slots, and deduplication fields. Do not invent
defaults or claim transaction uniqueness from a static export.

## Consent And CMP

Primary sources:

- Google Consent Mode:
  https://developers.google.com/tag-platform/security/guides/consent
- Didomi events and variables:
  https://developers.didomi.io/cmp/web-sdk/third-parties/tags-management/events-and-variables
- Didomi GTM template:
  https://developers.didomi.io/cmp/web-sdk/third-parties/tags-management/tag-managers/google-tag-manager/didomis-gtm-template
- OneTrust JavaScript events:
  https://developer.onetrust.com/onetrust/docs/javascript-events-guide
- OneTrust SPA guidance:
  https://developer.onetrust.com/onetrust/docs/single-page-applications

Apply the four route classes in `audit-coverage.md` without ad-hoc exceptions.
For direct non-Advanced vendor routes, the positive trigger never carries the
granted-state condition. Use a CMP readiness/lifecycle event for page-load timing
or the real business event for later actions, plus one reusable denial blocker
per vendor/purpose/category. Unknown and absent state fail closed.

For each page-load route, resolve from locked configuration and current CMP
documentation whether a lifecycle/update event gives the tag another eligible
firing opportunity after a later grant, or whether an approved reload dependency
is explicit. If neither is established, return an `owner_decision` or
`container_evidence_limit`; do not recommend duplicating consent in the positive
trigger.

Do not use Additional Consent Checks as the configurable gate in this selected
architecture. Record Built-In Consent Checks as intrinsic template behaviour;
they cannot be disabled and do not prove Advanced Consent Mode. Confirm Advanced
Mode only when a closed locked approval row matches the exact destination and
direct-browser/client-to-server route (including the route host where applicable),
carries concrete approval evidence, and the source visibly contains coherent
default/update writers, consent types, and Consent Initialization timing.

Exact source-proven obligations are not discretionary semantic candidates. When
the locked evidence proves that a blocker event cannot intersect any positive
firing event, classify the blocker as defective and remove only that blocker.
When a visible default consent writer does not use Consent Initialization,
classify its timing as defective and move that writer to Consent Initialization.
When a configuration obligation carries a complete `source_known_repair`, keep
it actionable and implement exactly that repair for a retained object. Other
justified actions may accompany the repair. Explicit retirement of that same
object in the reviewed proposal supersedes its field edit; it is not a reason to
change a flag on an object that will no longer exist. Retirement remains subject
to the normal independent justification, consumer-safety, and neutral-review
requirements. Pausing or deleting a different object does not satisfy the repair.
In particular, enabled Custom
HTML `document.write` support with no `document.write` call is a material
optimisation, not an evidence limit. Do not apply these deterministic outcomes to
lookalike candidates lacking the same locked proof.

For Didomi resolve documented `didomi-ready`, `didomi-consent`, and
`didomi-consent-changed` timing plus exact `didomiVendorsEnabled` token matching.
For OneTrust resolve `OneTrustGroupsUpdated`, `OTConsentApplied`, and
`OnetrustActiveGroups` with exact group boundaries. A name containing “consent”
is not enough to prove control.

## Client-To-Server Transport And Server Evidence Boundary

Primary source:
https://developers.google.com/tag-platform/tag-manager/server-side/intro

A pure client transporter uses normal firing triggers only and inherits one
canonical complete consent-state value through its Google configuration/settings
owner. It has no positive consent condition, blocking consent trigger, Additional
Consent Check, inline per-event copies, or direct browser-vendor bypass. Pure
classification also requires locked approved context naming every route host as
having a downstream server consent-gating owner. Missing, multiple, inconsistent,
partially inherited, mixed, or ownership-unconfirmed routes are findings. An
ownership-unconfirmed route may be audited for forwarding quality, but any client-
gate removal remains an `owner_decision` or `container_evidence_limit` and cannot
enter the operation packet.

This skill never accepts a server-container export. Conclude only whether the
web-container transport and consent-forwarding contract is aligned. Downstream
client claiming, transformations, vendor gating, requests, enforcement,
responses, deduplication, and vendor receipt remain outside the evidence.

## Vendors, Templates, And Zones

For Ads, Floodlight, Meta, TikTok, Snapchat, Pinterest, LinkedIn, Microsoft Ads,
Criteo, Awin, GAM, affiliates, and other vendors, resolve current official setup
and event contracts. Check loader/action ownership, IDs and labels, event names,
values/currency/products, identity fields, required shapes, deduplication keys,
consent class, route, and deprecated configuration. Do not require browser/server
deduplication for a browser-only route.

Inspect installed custom-template metadata, permissions, allowed domains, and
version. Prefer native or reviewed template behaviour over custom code only when
full value/type/timing/consent/route equivalence is proven.

Treat `gtagConfig` and Zones as first-class web-container objects. For Zones
inspect child containers, boundary triggers, type restrictions, allowlists,
permissions, and duplicated parent/child ownership. An unseen child container is
an evidence boundary. Never model server-container Clients or Transformations.
