# grid.json — Wholesale Catalog Manifest for AI-Agent Commerce

**v0 DRAFT, 2026-05-11 (V+N joint).** Published at `/.well-known/grid.json` on the business's domain. AI agents discover + walk catalogs without scraping.

## Top-level shape

```json
{
  "grid_version": "0.1",
  "publisher": {
    "name": "Tesco Ireland",
    "legal_entity": "Tesco Ireland Ltd, CRO 12345",
    "did": "did:aiegis:operator:z6MkXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "homepage": "https://www.tesco.ie",
    "logo_url": "https://www.tesco.ie/static/logo.svg",
    "jurisdiction": "IE",
    "binding_proof": "https://www.tesco.ie/.well-known/aiegis-binding.json"
  },
  "catalog": {
    "type": "url",
    "url": "https://catalog.tesco.ie/v1/products",
    "format": "application/grid-catalog+json",
    "auth": "none | bearer | mtls",
    "rate_limit_per_min": 600,
    "last_updated": "2026-05-11T07:00:00Z",
    "signature": {
      "url": "https://www.tesco.ie/.well-known/catalog-manifest.sig",
      "cryptosuite": "eddsa-rdfc-2022",
      "type": "DataIntegrityProof"
    }
  },
  "payment": {
    "endpoint": "https://checkout.tesco.ie/v1/agent-order",
    "methods": ["card", "open_banking", "agent_wallet"],
    "currencies": ["EUR", "GBP"],
    "supports_pre_auth": true,
    "supports_partial_refund": true
  },
  "fulfillment": {
    "endpoint": "https://fulfillment.tesco.ie/v1/orders",
    "delivery_regions": ["IE", "NI"],
    "estimated_lead_time_hours": 24,
    "pickup_supported": true
  },
  "policy": {
    "return_policy_url": "https://www.tesco.ie/policies/returns",
    "agent_terms_url": "https://www.tesco.ie/policies/agent-commerce",
    "data_protection": "GDPR-2016-679"
  },
  "verification": {
    "aiegis_verified": true,
    "aiegis_tier": "verified-merchant",
    "verified_since": "2026-05-11T07:00:00Z",
    "verification_url": "https://aiegis.ie/v/tesco-ie",
    "aiegis_verification_signature": {
      "cryptosuite": "eddsa-rdfc-2022",
      "type": "DataIntegrityProof",
      "verificationMethod": "did:aiegis:operator:z6MkYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY#key-1",
      "proofValue": "z3..."
    }
  }
}
```

**Note on AI Act Article 50 scope:** the Article 50 transparency disclosure obligation is on the AI **agent operator** at point of interaction with the end user — NOT on the catalog publisher. Grid does not duplicate this scope in the publisher manifest.

## Per-product shape (returned by `catalog.url`)

```json
{
  "products": [
    {
      "id": "5012345678901",
      "name": "Organic Salmon Fillet 200g",
      "sku": "TESCO-FRESH-SALM-200",
      "category": "food/seafood/fresh",
      "brand": "Tesco Finest",
      "price": {
        "amount": 5.99,
        "currency": "EUR",
        "vat_included": true,
        "unit": "each"
      },
      "availability": {
        "in_stock": true,
        "stock_level_hint": "high",
        "regions_available": ["IE", "NI"]
      },
      "media": [
        { "url": "https://cdn.tesco.ie/p/5012345678901.jpg", "alt": "Organic Salmon Fillet 200g" }
      ],
      "attributes": {
        "weight_g": 200,
        "diet": ["pescatarian"],
        "allergens": ["fish"],
        "country_of_origin": "IE"
      },
      "agent_metadata": {
        "shoppable_by_agent": true,
        "human_confirmation": "none",
        "min_order_quantity": 1,
        "max_order_quantity": 50
      }
    }
  ],
  "pagination": {
    "next": "https://catalog.tesco.ie/v1/products?page=2",
    "total": 124857
  }
}
```

## Discovery flow

1. Agent visits `https://<domain>/.well-known/grid.json`
2. Resolves `publisher.binding_proof` to verify business identity
3. Fetches `catalog.url`, walks product pages, picks items
4. Places order via `payment.endpoint` (no Grid involvement; agent pays business direct)
5. Tracks via `fulfillment.endpoint`

## Design principles

- **Grid never touches payment.** All payment endpoints belong to the publisher.
- **Identity is foundation, not product.** `publisher.did` + `binding_proof` come from AiEGIS substrate stack but are referenced, not gated.
- **Crawlable + cacheable.** Like robots.txt — predictable path, static-friendly, no auth required to read the manifest itself.
- **Agent-friendly metadata.** Each product has `agent_metadata` so agents know what's shoppable autonomously vs needs human confirmation.
- **Fail-closed for high-value categories.** Products over a threshold default to `human_confirmation: "pre_order"` or stricter until the merchant overrides. Allowed values: `"none"` / `"post_order_review"` / `"pre_order"` / `"out_of_band_approval"`.

## Open questions (v0 → v0.1)

- Catalog delta-feed format (websocket / SSE / poll) for high-velocity merchants
- Substrate-attested order signing (agent signs the order with did:aiegis key before submitting to merchant)
- AI Act Article 50 disclosure inline vs URL-referenced
- Multi-publisher manifest aggregation (Tesco group, AmazonStore)

## Compose with

- AiEGIS substrate-binding spec (publisher identity)
- did:aiegis DID method (publisher.did resolution)
- VC Envelope Export spec (catalog signature attestation)
