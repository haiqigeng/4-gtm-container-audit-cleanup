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
- GA4 tags in GTM:
  https://support.google.com/tagmanager/answer/9442095
- triggers and exceptions:
  https://support.google.com/tagmanager/answer/7679318
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

A firing trigger defines occurrence; an exception/blocker suppresses eligibility
when both match the same event. Explicit priority controls start order only among
co-eligible tags. It does not wait for asynchronous completion. Remove explicit
zero, priority without a real competitor, and priority already represented by
sequencing.

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

Do not use Additional Consent Checks as the configurable gate in this selected
architecture. Record Built-In Consent Checks as intrinsic template behaviour;
they cannot be disabled and do not prove Advanced Consent Mode. Confirm Advanced
Mode only from explicit approved context and coherent visible default/update
writers and consent types.

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

Treat `gtagConfig`, Zones, clients, and transformations as first-class objects.
For Zones inspect child containers, boundary triggers, type restrictions,
allowlists, permissions, and duplicated parent/child ownership. An unseen child
container is an evidence boundary.
