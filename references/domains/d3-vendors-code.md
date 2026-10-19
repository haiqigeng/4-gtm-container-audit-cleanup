# D3 Vendors, Templates And Custom Code

Areas: A06 tag and template configuration, A19 non-Google vendors, A20 value semantics for
these, A22 custom templates and code. Pack: `packs/D3*.md` (full code is included).

## Check

**Tracking plan** (when `packs/plan.md` exists)
- Compare vendor events and conversions with the plan in the same way as D2.

**Each vendor**
- Which tag loads the library and which tags send actions.
- Initialise each pixel or account once.
- With several Meta pixels, `fbq('track')` sends every event to every pixel; use
  `trackSingle` per pixel.
- Standard versus custom event types.
- Payload fields, value and currency source, product IDs.
- Deduplication `event_id` when a server route exists.
- Advanced-matching field mapping (first and last name must come from different sources).
- Unresolved placeholders (`##VALUE##`, `{ORDER_ID}`, `insert_...`); plain `http://`
  requests.

**Templates**
- Gallery or custom; archived repository or locally modified copy (no gallery updates).
- Permissions and injected domains.
- Sandboxed code calls `data.gtmOnSuccess()` or `data.gtmOnFailure()` on every path,
  including a failed load.
- Prefer a maintained gallery template over Custom HTML when behaviour is equivalent.

**Custom HTML and Custom JavaScript.** Read the code; never execute it.
- Script context: code outside `<script>` is rendered as text.
- Syntax errors; `document.write`; `eval`.
- Globals, listeners and timers (`setInterval` without clear); jQuery dependency.
- Cookies and storage writes.
- Network calls and their payloads.
- `JSON.parse` without a guard; reading the first dataLayer push instead of the current
  one; parsing `_ga` cookie internals.
- Functions defined and never called.
- Custom JavaScript variables without `return`.
- Explain every material side effect. Opaque or external code is an `evidence_limit`, never
  a clean verdict.

**Unknown vendors**
- Research the official documentation once and cite it.
- A missing or inaccessible contract makes the dependent change `conditional` or
  `evidence_limit`; it is not proof of a defect.

## Typical operations

- Set a parameter (`parameter:eventName.value`, `parameter:pixelId.value`).
- Replace Custom HTML code with `set` on `parameter:html.value`, only when value, type,
  timing, consent, route and destination stay equivalent. Describe the exact difference in
  the finding.
- Delete a duplicate initialisation tag after remapping or retiring what depends on it.
- Pause a tag whose vendor contract is unknown only if the owner asked for it; otherwise
  raise a `decision`.
