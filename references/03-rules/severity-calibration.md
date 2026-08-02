# Severity Calibration

Use this reference when assigning severity and priority. Severity describes
impact. Priority describes when to act.

## Severity Scale

| Severity | Use when |
| --- | --- |
| Critical | Clear consent/legal violation, major analytics/conversion collection broken, production mutation can cause immediate data loss, or revenue-critical events are unusable. |
| High | Material data quality, privacy, attribution, or revenue risk that is likely to affect decisions or media optimization. |
| Medium | Functional but fragile, duplicated, inconsistent, hard to maintain, or likely to cause future errors. |
| Low | Minor hygiene, naming, documentation, or low-risk maintainability issue. |
| Info | Observation, context, or verified correct behavior with no change recommended. |

Operation priority values are `Critical`, `High`, `Medium`, and `Low`.
Unresolved ownership is represented by execution readiness/disposition, not by
inventing a fifth priority.

Every reconciled operation carries an evidence-based `priority_basis`:

- active reachability: active, paused-only, inactive/unreferenced,
  metadata-only, or unknown;
- impact class: consent/privacy, security, measurement loss/corruption,
  duplicate delivery/attribution, routing/integration, or maintainability;
- evidence confidence;
- reversibility of the proposed mutation;
- owner dependency.

The compiler records a conservative evidence floor and whether the analyst's
assigned priority is below it. This is a review signal, not a new delivery or
approval gate. Do not hide low confidence by reducing possible impact, and do
not make an inactive naming/folder issue urgent merely because its proof is
strong.

## Calibration Examples

| Finding | Suggested severity | Priority basis / usual priority |
| --- | --- | --- |
| A direct active browser marketing/vendor request is initiated before its required consent. | Critical | Active consent/privacy, high confidence: Critical |
| A first-party server transporter fires without a client blocker but forwards a complete consent contract for server enforcement. | Info; no client-side defect by itself | No action unless the forwarding contract is incomplete |
| Purchase event does not fire or is blocked for all users. | Critical | Active measurement loss, high confidence: Critical |
| GA4 purchase value/currency/item payload is materially wrong. | High | Active measurement corruption: High |
| Ads/Floodlight/Meta purchase conversion lacks an approved order ID or value. | High | Active attribution/revenue impact: High |
| Active GA4 ecommerce uses UA paths without mapper proof. | High | Active measurement corruption, medium/high confidence: High |
| CMP-ready/pageview gating differs across same-vendor routes. | High or Medium | Consent impact and active reach; owner/runtime uncertainty stays explicit: High or Medium |
| Custom HTML injects a third-party script without consent or origin rationale. | High | Active consent/security and field-level rollback: High |
| An active postMessage listener uses substring origin matching or pushes an unvalidated payload to dataLayer. | High | Active security/measurement corruption with a source-visible code repair: High |
| Default consent is configured on a later custom event instead of Consent Initialization. | High | Active consent sequencing with an exact trigger repair: High |
| Consent mapping can throw because `.includes()` reads a no-default DLV. | High or Medium | Active consent/measurement path and consumer reach: High or Medium |
| Recursive vendor polling has no finite bound. | Medium; High when it blocks or multiplies a critical sender | Active stability/performance plus affected measurement reach |
| A cookie day count has an extra multiplier or omits approved set attributes. | High or Medium | Consent/privacy or functional retention impact, calibrated by cookie purpose and active reach |
| Custom JS fixed-index item variables power multi-item payloads. | High or Medium | Active measurement impact and consumer reach: High or Medium |
| Duplicate page_view/PageView hits feed billing or optimization. | High; otherwise Medium | Active duplicate delivery: High or Medium |
| A trigger group has one member and adds no behavior. | Medium | Active maintainability with reversible remap: Medium |
| An unused trigger/variable has no reachable consumers. | Low or Medium | Inactive maintenance; raise only for proven release risk: Low or Medium |
| Duplicate names obscure maintenance but behavior is correct. | Low | Metadata/maintenance and easy rollback: Low |
| Folder organization is missing. | Low | Metadata-only: Low |
| External behavior is unprovable from the export. | Info/boundary | Container-evidence boundary; priority follows any separate source-visible operation |

## Escalation Rules

Escalate when:

- consent/privacy risk is involved;
- revenue/conversion or paid-media optimization is affected;
- a shared helper or trigger powers many tags;
- a custom-code error can break several vendors;
- a server-bound route has missing, partial, swapped, stale, or inconsistent
  consent forwarding and the affected destination risk is high;
- an issue affects all pageviews or all purchases.

Downgrade when:

- object is paused and has no consumers;
- stronger container or owner evidence proves no impact;
- issue is naming-only with no behavior risk;
- issue is inside a user-excluded scope.

## Confidence

Always pair severity with confidence:

- `High`: complete export/API evidence and the official contract agree.
- `Medium`: export/API evidence is strong but external behavior is not
  verifiable from the container.
- `Low`: inference from names, old evidence, partial screenshots, or missing
  official documentation.

Do not hide low confidence by lowering severity. Use severity for possible
impact and confidence for evidentiary strength.
