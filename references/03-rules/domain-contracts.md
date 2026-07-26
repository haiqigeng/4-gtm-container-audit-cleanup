# Domain And Vendor Contracts

Use the versioned `vendor-registry.toml` first. When a detected vendor or feature
has no suitable current entry, search the internet and use the vendor's official
documentation to update the versioned registry, validate it, and rebuild the
review. Record the exact official HTTPS URL only after that source/domain is
registry-bound to the vendor.

## Contents

- Topic-specific contract obligations
- Google Analytics 4 and ecommerce
- Consent and CMP
- Browser-to-server and server containers
- Google tag configurations and Zones
- Media, affiliate, publisher, and GTM mechanics

## Topic-Specific Obligations

The source scaffold generates one contract topic per applicable object and
downstream vendor context. Complete every topic exactly once. A single generic
`vendor setup checked` statement never satisfies the contract.

Typical obligations are:

- GA4: event name, destination/server route, event parameter names and types,
  consent/timing, and event-specific ecommerce/item/value rules;
- media/affiliate: event, destination ID, payload names/shapes/types,
  consent/timing, and event-ID or deduplication behavior;
- CMP: consent mapping, default/update timing, and downstream gating;
- variables consumed by vendor tags: terminal value shape/type and availability
  at the consuming event, plus consent semantics where relevant;
- custom templates, clients, and transformations: permissions/behavior,
  request claiming/routing, payload/consent handling, transformation scope, and
  allowlist/redaction behavior;
- Google tag configurations: destination/config command, inherited settings,
  variable-backed values, and overlap with tag destinations;
- Zones: child-container scope, boundary trigger behavior, type restrictions,
  and allowlists.

Each topic records the configured value, expected official rule, exact source
anchor, official URL, and verdict. A non-compliant topic becomes a defect. An
unproven topic cannot support a Correct object verdict.

The scaffold assigns each applicable topic a deterministic state. Visible
missing required fields and registry-listed unsupported/retired event names are
`known_noncompliant`; dynamic type, shape, availability, unresolved consent,
and unseen server behavior are `unproven_from_container`; other current-source
questions remain `source_check_required`. These states cannot be weakened to
`Not applicable`. Versioned `unsupported_standard_events` and
`event_replacements` metadata must be unique, structurally valid, and supported
by the vendor's registered official source; a replacement is a review cue, not
permission to mutate automatically.

An unrecognized external host, loaded script, or custom template is not a
reason to skip vendor validation. Assign one canonical research owner per
unknown host/template identity and link every other applicable object/topic to
that task. Record the detection cue, identify the vendor
or integration, find a current official HTTPS setup/reference page, add its
verified ownership/domain to the registry, validate, rebuild, and then complete
the generated contract topics. Before rebuild, the unknown-vendor topic remains
Unproven and cannot accept an arbitrary analyst-supplied URL as official proof.
Avoid broad vendor detection from generic parameter words.

One object can implement more than one downstream vendor. Preserve every
matched vendor context and generate separate obligations for each. An unmatched
external host remains its own mandatory research topic even when the same code
also contains a recognized vendor; a primary-vendor label must never hide the
second integration.

Only behavior-bearing fields can prove an integration host. Ignore GTM
UI/export URLs, paths, notes, fingerprints, workspace IDs, folder placement,
template terms/help/tests/licenses, and code comments for vendor inference. An
explicit server-transport endpoint in a recognized
vendor or Google tag configuration belongs to its server-routing contract; do
not duplicate it as an unknown vendor unless separate request/script evidence
shows another integration role.

## Google Analytics 4

Treat Google event tags as GA4/current Google tag unless the export proves
Universal Analytics through native UA type, `UA-` property, UA parameters, or
old ecommerce paths. When UA is proven, classify it explicitly as legacy and
use the official sunset/migration source rather than applying a GA4 event
contract silently.

Primary sources:

- events: https://developers.google.com/analytics/devguides/collection/ga4/reference/events
- recommended events: https://developers.google.com/analytics/devguides/collection/ga4/reference/recommended-events
- ecommerce: https://developers.google.com/analytics/devguides/collection/ga4/ecommerce
- event naming: https://support.google.com/analytics/answer/13316687

For every GA4 event check event name, firing event, event parameters, ecommerce
mode, item parameters, data types, user data, consent, destination/configuration,
and duplicate routes.

For standard ecommerce, prefer the official website/dataLayer `ecommerce`
contract. Typical checks include:

- `view_item`, `add_to_cart`, `remove_from_cart`, `view_cart`, and
  `begin_checkout`: appropriate `items`; currency/value when revenue value is sent;
- `add_shipping_info` and `add_payment_info`: items and relevant method field;
- `purchase`: unique `transaction_id`, currency, numeric value, tax/shipping,
  coupon when used, and complete `items`;
- `refund`: `transaction_id` linked to the original purchase, refunded items,
  and values where applicable;
- item arrays use item objects and appropriate item-level fields;
- value and quantity come from event-time ecommerce data, not fixed product
  positions or unrelated custom formulas.

Do not create custom JavaScript merely because the audit agent did not inspect
the official dataLayer path. First verify the event's official ecommerce object
and the exported dataLayer variables.

Missing standard events may be proposed as an optional tracking-plan/dataLayer
improvement. Do not create tags when the required website dataLayer event is absent.

## Consent And CMP

Primary Google setup source:
https://developers.google.com/tag-platform/security/guides/consent

Check:

- default and update timing;
- `analytics_storage`, `ad_storage`, `ad_user_data`, and
  `ad_personalization` independently;
- CMP purpose/group mapping and sibling variables with identical conditions;
- native consent requirements and trigger-level blocking;
- external scripts loading before consent;
- consent values forwarded to server routes;
- duplicate CMP listeners or consent-update tags.

Interpret exported manual-consent status using the GTM API enum exactly:
`needed` means the tag declares additional consent checks; `notNeeded` means it
declares that no additional check is needed; and `notSet` means no manual choice
is recorded. Only `needed` proves an additional-consent requirement. Native
consent capability, a consent-looking name, or `notSet` is candidate evidence,
not proof that the effective route is gated. Unknown or malformed enum values
are configuration defects rather than values to normalize by inference.
Likewise, an event/object name containing `consent` and an arbitrary blocking
trigger do not prove that consent is forwarded or that the blocker can affect
the firing route. Preserve all vendors detected in mixed custom code.

Do not make legal decisions. A mapping that cannot be identified from container
evidence requires one precise owner/legal question.

## Browser-To-Server And Server Containers

Primary source:
https://developers.google.com/tag-platform/tag-manager/server-side/intro

Classify web tags that route through a server endpoint before flagging missing
measurement IDs or consent blockers. A web Google configuration/event tag may
rely on a server-managed destination, and consent may be forwarded as event or
settings parameters. Inspect transport/server URL, tag settings, event
parameters, client-to-server role, and deduplication fields.

Two client-side consent-control models are valid when their exported contract is
internally coherent:

1. **Client-enforced control:** native Consent Mode, additional consent checks,
   or firing/blocking logic controls browser-side vendor execution.
2. **Server-enforced transport:** transporter tags may send every event to the
   first-party server endpoint without a client-side blocking trigger, while a
   Google tag/configuration setting, event-settings variable, event parameter,
   or equivalent inherited variable forwards the consent state needed by the
   server container to decide downstream vendor delivery.

For the server-enforced model, trace the forwarding parameter and every
referenced variable to the CMP/default/update source. Check that the required
consent purposes or an approved complete CMP-state object are available at
event time, inherited by every transporter in the route, and not contradicted
by direct browser-to-vendor tags. Missing client blocking is not itself a
defect. Record a defect only for a missing, partial, stale, swapped, or
inconsistently applied forwarding contract. When the web-side contract is
coherent, use a disposition such as `client transport contract aligned; server
enforcement not audited`, not a privacy alert or unresolved owner decision
solely because the receiving container is unseen.
Do not label a value as forwarded unless the same exported route contains a
server endpoint and a behavior-bearing payload/settings chain. Keep a separate
detected-consent-payload fact when consent-like values exist without a server
route.

The web export cannot prove what the server container forwards, transforms,
redacts, blocks, or deduplicates. Audit those claims only when the complete
server-container export is supplied. For server exports, include clients,
transformations, request claiming, outgoing tags, permissions, consent, and
event-data transformations.

## Google Tag Gateway For Advertisers

Primary sources:

- setup guide: https://developers.google.com/tag-platform/tag-manager/gateway/setup-guide
- GTM/CDN setup and status: https://support.google.com/tagmanager/answer/16222402

Identify explicit gateway fields or first-party Google transport hosts when they
are exported. Distinguish Google tag gateway from a custom server-side GTM
transport because their ownership and forwarding behavior differ. Record
`not_visible_in_container_export` when the export has no evidence: active-domain
status can live in GTM Admin/CDN configuration and must not be invented from an
ordinary Google tag alone. Consent review remains mandatory because first-party
routing changes the request path, not the visitor's consent choice.

## Google Tag Configurations And Zones

Primary sources:

- Google tag configuration resource: https://developers.google.com/tag-platform/tag-manager/api/reference/rest/v2/accounts.containers.workspaces.gtag_config
- Zone resource: https://developers.google.com/tag-platform/tag-manager/api/reference/rest/v2/accounts.containers.workspaces.zones
- ContainerVersion layers: https://developers.google.com/tag-platform/tag-manager/api/reference/rest/v2/accounts.containers.versions

Treat exported `gtagConfig` and `zone` entities as first-class configuration
objects, not opaque metadata. For a Google tag configuration, inspect the
destination/config ID, every parameter and variable reference, and any shared
destination already configured by tags. A shared destination is an architecture
candidate, not automatic duplication: configuration, routing, scope, and intent
still decide whether consolidation is safe.

For each Zone, inspect every child-container public ID, boundary trigger,
allowlist and type-restriction control, and variable dependency. Flag malformed,
empty, duplicate, or missing child entries and structurally unbounded boundaries.
Two Zones managing the same child set are an architecture candidate, not proof
of equivalence. The web export cannot prove the state or behavior inside an
unseen child container.

## Media, Affiliate, And Publisher Vendors

For Meta, TikTok, Snapchat, Pinterest, LinkedIn, Microsoft Ads, Criteo, Awin,
Floodlight, Google Ads, GAM, and other detected vendors, resolve the current
official event documentation before judging the tag.

Check:

- base/config loader versus event tag and duplicate loaders;
- pixel/account/advertiser/conversion IDs and labels;
- standard versus custom event name;
- event-time trigger and business action;
- product/content identifiers, category/content type, contents/items arrays,
  quantity, currency, numeric value, order/transaction ID, hashed user data,
  and deduplication ID in the vendor-required format;
- scalar, array, and object shapes through recursive variable output review;
- consent before external script or request initiation;
- browser/server duplicate paths and event-ID consistency.

The versioned registry locks common Meta standard-event identities and the
source-visible `Purchase` value/currency contract. Inspect fields inside the
actual `fbq()` payload rather than treating a Custom HTML parameter table as
empty. Do not require a browser/server deduplication ID on a browser-only Meta
route; require it only when the audited architecture proves both delivery
paths.

For Google Ads and Floodlight, review conversion-linking coverage
conditionally. An all-pages Google tag can make a separate Conversion Linker
unnecessary, and current conversion tags may load Google tag capability; the
absence of a standalone linker is therefore not an automatic defect. When
`url_passthrough` or `ads_data_redaction` is configured, create an explicit
consent-contract review. A `*.run.app` transport is a production-domain review
candidate, not proof of broken routing; recommend an approved first-party
domain where applicable without upgrading the route to an Issue by hostname
alone.

A dataLayer variable is valid when it already returns the required array/object.
Custom JavaScript is justified only for a real documented transformation, and
its output must be inspected line by line.

## Official GTM Mechanics

- tag sequencing: https://support.google.com/tagmanager/answer/6238868
- firing priority: https://support.google.com/tagmanager/answer/2772421
- import/export: https://support.google.com/tagmanager/answer/6106997

Use these mechanics when judging setup/teardown dependencies, priority, and JSON
routes. They do not replace business-purpose review.
