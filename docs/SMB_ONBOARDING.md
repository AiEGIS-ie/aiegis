# Grid SMB Onboarding — Zero to Shoppable in 4 Steps

Your business publishes a catalog. AI agents shop it. Tesco-style end-to-end. You handle payment + fulfillment directly with the agent's principal. Grid just makes you discoverable.

This guide walks the four concrete files you need.

> **Note.** `aiegis.ie` is the spec home, not a Grid publisher — there is no live manifest at `https://aiegis.ie/.well-known/grid.json` to copy from. See [`spec/grid_example_smb.json`](../spec/grid_example_smb.json) for a complete reference manifest in the shape we expect publishers to ship. Dogfood (AiEGIS itself publishing a real Grid manifest) is planned for v0.8 once an operator DID + live binding-proof are issued.

## Prerequisite

You need:
- A domain you control (e.g. `your-business.example`)
- HTTPS terminating to that domain (Let's Encrypt + nginx/Caddy fine)
- The ability to drop a static file at `/.well-known/grid.json`
- A way to serve a JSON catalog (static file OR dynamic endpoint OK)
- A payment/checkout endpoint that accepts agent orders

**You DO NOT need:** Grid SDK install, Grid SaaS account, payment-rails integration with Grid. Grid is read-only discovery; everything else stays with you.

## Step 1 — Publish the manifest

Drop a file at `https://your-business.example/.well-known/grid.json`. Use the template at [`grid_example_smb.json`](../spec/grid_example_smb.json) and replace the obvious fields.

Minimum required fields:
- `publisher.name`, `publisher.legal_entity`, `publisher.homepage`, `publisher.jurisdiction`
- `catalog.url` — where AI agents fetch your product list
- `payment.endpoint` — where AI agents place orders
- `payment.methods`, `payment.currencies`
- `fulfillment.endpoint`, `fulfillment.delivery_regions`

**Free tier:** leave `verification.aiegis_verified: false` and `aiegis_tier: "free-listing"`. Your business is discoverable but not Grid-verified. Most SMBs start here.

**Verified tier:** apply at [aiegis.ie/verify](https://aiegis.ie/verify). Grid issues an `aiegis_verification_signature` (W3C VC + eddsa-rdfc-2022) you embed in the manifest. Higher rank in agent searches + verified-merchant badge.

## Step 2 — Serve the catalog

Your `catalog.url` returns product JSON shaped like [`grid_catalog_example.json`](../spec/grid_catalog_example.json). Each product has:
- Identity: `id`, `sku`, `name`, `brand`, `category`
- Commerce: `price.amount + currency`, `availability`
- Visuals: `media[]` for agent UIs
- Attributes: `weight_g`, `allergens`, `ingredients`, etc — agent-readable filters
- Agent-metadata: `shoppable_by_agent`, `human_confirmation` (enum), `min/max_order_quantity`

**Fail-closed default**: for high-value or customizable items (>€100, custom-order, age-restricted), set `human_confirmation: "pre_order"` with a `human_confirmation_reason`. The agent will escalate to its principal before placing the order, instead of auto-buying. This protects both you and the agent's user.

## Step 3 — Sign the catalog (optional but recommended)

Wrap your catalog response in a [W3C VC envelope](../spec/grid_signed_catalog_envelope.json) so agents can verify your catalog hasn't been tampered with in flight. Format: DataIntegrityProof + cryptosuite `eddsa-rdfc-2022` per W3C VC-DI EdDSA REC 2025-05-15.

If you don't have the keys for VC signing yet, skip this step — agents will fetch your catalog over HTTPS unsigned. Signing is recommended for high-value categories + verified-merchants.

## Step 4 — Accept agent orders

Your `payment.endpoint` receives POSTs from agents shaped:
```
{
  "agent_did": "did:aiegis:agent:z6Mk...",
  "publisher_did": "did:aiegis:operator:z6Mk... (yours)",
  "items": [{"sku": "...", "quantity": N, "unit_price": ...}],
  "currency": "EUR",
  "agent_signature_hex": "<Ed25519 signature of order JSON>",
  "cryptosuite": "eddsa-rdfc-2022"
}
```

You verify the `agent_signature_hex` against the agent's `did:aiegis:agent:` pubkey (resolve via standard `did:key`/`did:aiegis` resolver), confirm pricing + availability, charge the agent's principal via your normal payment rails (Stripe / Adyen / Open Banking / whatever), and respond with:
```
{
  "order_id": "...",
  "fulfillment_status": "confirmed",
  "delivery_estimate_iso": "..."
}
```

## Step 5 — Verify your setup before announcing

Catch typos, wrong MIME types, and empty catalogs *before* agents start hitting you. Run these three checks against your live domain:

```bash
# (i) manifest reachable + correct MIME type
curl -fIs https://your-business.example/.well-known/grid.json \
  | grep -i '^content-type:.*application/json' \
  && echo "manifest OK"

# (ii) publisher.did present + format-valid
curl -fs https://your-business.example/.well-known/grid.json \
  | jq -e '.publisher.did | test("^did:aiegis:operator:")' \
  && echo "publisher.did OK"

# (iii) catalog reachable + non-empty + structurally sound
CATALOG_URL=$(curl -fs https://your-business.example/.well-known/grid.json | jq -r '.catalog.url')
curl -fs "$CATALOG_URL" \
  | jq -e '.pagination.total > 0 and (.products[0] | has("sku") and has("price") and has("agent_metadata"))' \
  && echo "catalog OK"
```

All three must print `OK` before you advertise the manifest. If anything fails, fix it locally — agents will not retry once they've cached a bad response.

**Optional CORS check.** If your manifest is served with restrictive CORS, agents from other origins may be blocked even though your `curl` works. Add `-H "Origin: https://agent.example.com"` to the calls above and confirm the response headers do not include `Access-Control-Allow-Origin: <empty>` or block on preflight.

## Reference: agent-side reference code

See [`grid_agent_example.py`](../spec/grid_agent_example.py) for the full agent-side flow: fetch manifest → verify publisher → walk catalog → filter agent-shoppable → place order → handle escalation for high-value items.

## What Grid does NOT do

- Grid does NOT process payments. Your payment endpoint handles everything.
- Grid does NOT take a transaction cut. Listings + verified badges + analytics are how Grid makes money.
- Grid does NOT see your customer data. Agents POST directly to your endpoint.
- Grid does NOT lock you in. Drop the manifest, drop the catalog endpoint, you're out.

## Privacy + Regulation

- **GDPR**: you're the data controller for the agent's principal data, same as any direct-to-consumer sale. Reference your existing privacy policy in `policy.return_policy_url` and `policy.agent_terms_url`.
- **EU AI Act Article 50**: Article 50 transparency obligation is on the AI agent OPERATOR at point of interaction with end users, NOT on the catalog publisher. You don't need to publish AI Act disclosure in your `grid.json`. (Per W3C VC-DI EdDSA Article 50 scope analysis, May 2026.)
- **Verification + identity**: when your business has `aiegis_verified: true`, agents can cryptographically prove they shopped you (not a phishing clone). This protects YOUR brand from clone-site attacks too.

## Questions?

- Email: hello@aiegis.ie
- Schema (canonical, machine-readable): [`grid.schema.json`](../spec/grid.schema.json)
- Schema overview (prose, design intent): [`GRID_SCHEMA_OVERVIEW.md`](../spec/GRID_SCHEMA_OVERVIEW.md)
- Sample: [`grid_example_smb.json`](../spec/grid_example_smb.json)
- License: Apache-2.0 (this guide + sample files)
