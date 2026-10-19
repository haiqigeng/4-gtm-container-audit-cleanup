# D2 Google Measurement

Areas: A15 Google settings ownership, A16 destinations, loaders and page views, A17 GA4
events and parameters, A18 ecommerce, A19 Google Ads and Floodlight, A20 value semantics
for these. Pack: `packs/D2*.md`.

## Check

**Tracking plan** (when `packs/plan.md` exists)
- Compare configured GA4 and Ads events with the plan: required events or parameters
  missing, configured differently (name, parameter, value source, trigger) or not in the plan.
- Cite the plan row in `situation`. A plan label that does not name an exact event is
  a `decision`, not a missing-event defect.

**Destinations**
- One Google tag owns each measurement ID.
- `send_page_view` fires only on page loads (or history changes for single-page sites).
  A second Google tag or a manual `page_view` duplicates page views.
- Placeholder or preproduction IDs are not used on live routes.
- An event sent to an ID with no Google tag is a broken destination.

**Settings ownership**
- Values that apply to the whole configuration belong on the Google tag or its
  configuration settings variable.
- Parameter rows repeated across a compatible group of event tags belong in one scoped
  Event Settings variable. Event-specific values and justified overrides stay local.
- Do not create one settings variable per repeated field.

**GA4 events**
- Use the recommended event and parameter names when they fit; custom names otherwise.
- Event and parameter names: at most 40 characters, starting with a letter, not reserved.
- At most 25 parameters per event.
- Universal Analytics leftovers: UA tags and settings variables are removable once
  nothing uses them. UA-style parameters on GA4 events (`event_category`,
  `event_action`, `event_label`) may feed the property's custom definitions or reports,
  so their removal, like an event rename, is `conditional` on the property owner.
- `debug_mode` in a live container is a defect to remove entirely (`false` still sends the
  field). The removal is `conditional` on confirming the environment, since a staging or
  debugging workflow may rely on it.
- `user_id` belongs in the Google tag configuration, not in event parameters or user
  properties.
- `value` always comes with `currency`.

**Ecommerce**
- Where `items` comes from (dataLayer, or a variable that builds it).
- `transaction_id`, `value` and `currency` on purchase.
- Item-level price and quantity; quantity defaults to 1, and 0 is not omission.
- Legacy UA enhanced-ecommerce paths (`ecommerce.purchase.actionField`…) still feeding
  GA4 tags.
- A parameter read from another event's ecommerce scope is a configuration defect.

**Ads and Floodlight**
- A Conversion Linker on all pages.
- Conversion value and currency.
- A stable transaction ID for deduplication (random IDs defeat it).
- One tag per conversion label on overlapping events.
- Call-conversion (number swap) tags fire on page load, not on click.
- Enhanced-conversion fields are handled with D1.

**Your conventions**
- Official recommended events and parameters first.
- String values in lowercase snake_case, except ISO currency (uppercase), identifiers,
  numbers and booleans.
- Personal data only through user-provided data.

## Typical operations

- Set `send_page_view` to false in the configuration settings table, or remove a duplicate
  Google tag after remapping its consumers.
- Create an Event Settings variable (`gtes`) holding the shared rows. Set each group tag's
  `parameter:eventSettingsVariable.value`, and `remove` the duplicated rows.
- Remove the `debug_mode` row; delete UA tags and variables once nothing else uses them.
- Add the missing currency row; replace a random transaction ID with the order ID variable.
