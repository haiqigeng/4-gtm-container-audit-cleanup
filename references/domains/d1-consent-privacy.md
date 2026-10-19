# D1 Consent, Privacy And Security

Areas: A09 CMP and consent infrastructure, A10 direct consent architecture, A11 Advanced
Consent Mode, A12 client-to-server transport, A13 server handoff boundary, A21 identity,
personal data and secrets. Pack: `packs/D1*.md`.

## Check

**Consent infrastructure**
- One consent default writer fires on Consent Initialization before any dependent tag. It
  covers `ad_storage`, `analytics_storage`, `ad_user_data` and `ad_personalization`.
- The CMP pushes an update on every choice.
- There are no competing writers, and the CMP template settings match the default.

**Every vendor tag**
- Classify its route with the consent table in policy.md.
- Direct routes need a consent-free positive trigger and a reusable denial blocker. The
  blocker must fail closed (block when consent is absent, unknown or denied) and must
  evaluate on the same events the tag fires on.

**Consent values**
- Token matching uses exact boundaries (`iab:91` must not match `iab:910`; numeric
  substrings are unsafe).
- Key spelling and case are consistent.
- Analytics tokens never grant advertising consent types.
- A blocker that only matches an explicit refusal fails open.

**Later grant**
- For page-load routes, check whether a CMP update event re-evaluates the blocker after a
  later grant on the same page. If unknown, use the `cmp_lifecycle` answer, or make it a
  `decision`.

**Advanced Consent Mode**
- Apply only to destinations listed in `consent_mode_destinations`. Check that defaults,
  updates and timing are visible.

**Server routes**
- `server_container_url` and `transport_url` hosts, the forwarded consent value, and
  direct browser bypasses.
- Removing a client consent gate needs the route host in `consent_owned_hosts`.
  Otherwise use `decision` or `evidence_limit`, and write no removal.

**Personal data**
- `user_id` from personal data.
- Personal data in GA4 parameters, user properties, URLs or Floodlight variables.
- Personal data written to cookies or web storage.
- Form values pushed to the dataLayer.
- Hashed personal data sent as ordinary parameters.
- On a tag routed to a server container, a personal-data field may feed server-side
  tags (for example enhanced conversions). Its removal is `conditional` on the server
  container's owner (readiness rule in policy.md).

**User-provided data and enhanced conversions**
- These channels may carry personal data (raw or hashed per field and method).
- Never put it in GA4 parameters, user properties or User-ID.
- Judge each field against its exact method: GTM's manual user-provided data variable
  accepts hashed or unhashed values; code (gtag) keys differ for raw and hashed
  (`email` versus `sha256_email_address`). Check normalisation before hashing (trim,
  lowercase, E.164 phone), SHA-256 hex encoding, availability when the tag fires, the
  country as ISO alpha-2, automatic scraping mode, and a consent gate on collection.

**Secrets**
- Credential-like literals (API keys, tokens, consumer secrets) are `Critical`. Recommend
  removal and rotation; never quote the value.

## Typical operations

- Create one blocker trigger per vendor or purpose. `add` it to each tag's
  `blockingTriggerId`.
- Remove the consent condition from the positive trigger; keep the exact business event.
- Fix a token condition: for example set `filter[0].parameter:arg1.value` to an anchored
  regex, and set `type` to `MATCH_REGEX`.
- Move the consent default writer to Consent Initialization. Add the missing consent types.
- Remove a personal-data parameter row, or route it through the user-provided data variable.
- Delete a secret-bearing parameter as `conditional` work: its `preconditions` name the
  rotation and any server-side replacement, because the credential was exposed in every
  published version.
