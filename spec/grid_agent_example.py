"""Agent-side reference for shopping a Grid-listed business.

Demonstrates the discovery flow end-to-end:
  1. Fetch /.well-known/grid.json from publisher domain
  2. Resolve publisher.binding_proof to verify business identity
  3. Walk catalog via catalog.url
  4. Place order via payment.endpoint
  5. Track via fulfillment.endpoint

This is REFERENCE code. Production agents wrap this in their own
identity-signing + retry + observability layer.

Compose with:
- AiEGIS aiegis-agent-sdk (agent identity + signing)
- did:aiegis DID method (publisher.did resolution + binding_proof verify)
- W3C VC Data Integrity 1.0 (signature verify)
"""
from __future__ import annotations

import json
import httpx

from typing import Any
from aiegis_agent import create_agent  # type: ignore


def verify_binding_proof(binding_proof: dict, *, expected_did: str) -> None:
    """Verify a publisher binding_proof against the AiEGIS substrate-pack.

    Production agents MUST implement this before placing orders. A correct
    implementation:
      1. Resolves expected_did via the did:aiegis DID method
      2. Calls into aiegis substrate-pack verifiers (TPM / SE / TDX / SEV-SNP)
         to check the binding_proof's signature was produced by the substrate
         bound to expected_did
      3. Raises if anything is off — wrong cryptosuite, stale freshness window,
         missing substrate attestation, signature mismatch.

    This stub raises NotImplementedError on purpose so that copy-pasted code
    fails loud rather than silently shipping an unverified order flow.
    """
    raise NotImplementedError(
        "implement binding_proof verification via aiegis substrate-pack before "
        "production use; do not bypass without explicit risk acceptance"
    )


def shop_publisher(
    publisher_domain: str,
    *,
    agent_name: str = "shop-bot",
    desired_items: list[dict] | None = None,
) -> dict:
    """End-to-end Grid shopping flow for one publisher.

    Args:
        publisher_domain: e.g. "sample-bakery.example"
        agent_name: name for the shopping agent identity
        desired_items: list of {"sku": str, "quantity": int}

    Returns:
        Order receipt from publisher's payment endpoint.
    """
    # ── 1. Create / load agent identity ──
    agent = create_agent(name=agent_name)
    print(f"Agent DID: {agent.did}")

    # ── 2. Fetch grid.json manifest ──
    manifest_url = f"https://{publisher_domain}/.well-known/grid.json"
    print(f"Fetching {manifest_url}")
    with httpx.Client(timeout=10.0) as http:
        manifest = http.get(manifest_url).raise_for_status().json()

    publisher_did = manifest["publisher"]["did"]
    print(f"Publisher: {manifest['publisher']['name']} ({publisher_did})")

    # ── 3. Verify publisher binding_proof (substrate-attested operator) ──
    binding_proof_url = manifest["publisher"]["binding_proof"]
    with httpx.Client(timeout=10.0) as http:
        binding_proof = http.get(binding_proof_url).raise_for_status().json()
    verify_binding_proof(binding_proof, expected_did=publisher_did)
    print(f"Binding proof: {binding_proof.get('cryptosuite', 'unknown')}")

    # ── 4. Walk catalog ──
    catalog_url = manifest["catalog"]["url"]
    with httpx.Client(timeout=10.0) as http:
        catalog = http.get(catalog_url).raise_for_status().json()
    print(f"Catalog: {catalog['pagination']['total']} products")

    # ── 5. Pick items + check agent_metadata ──
    items_to_order = []
    for desired in desired_items or []:
        product = next((p for p in catalog["products"] if p["sku"] == desired["sku"]), None)
        if product is None:
            print(f"  ✗ SKU {desired['sku']} not in catalog")
            continue
        meta = product["agent_metadata"]
        if not meta["shoppable_by_agent"]:
            print(f"  ✗ {product['name']} not shoppable by agents")
            continue
        if meta["human_confirmation"] != "none":
            print(f"  ⚠ {product['name']} requires human_confirmation={meta['human_confirmation']!r}")
            print(f"      reason: {meta.get('human_confirmation_reason', 'not specified')}")
            print(f"      escalating to operator before order")
            # Production: call out to human-in-the-loop UI / Slack / email
            # For demo, we skip pre_order items
            continue
        qty = min(desired["quantity"], meta["max_order_quantity"])
        items_to_order.append({"sku": product["sku"], "quantity": qty, "unit_price": product["price"]["amount"]})
        print(f"  ✓ {product['name']} x{qty}")

    if not items_to_order:
        print("No items selected for order. Done.")
        return {}

    # ── 6. Build + sign + place order ──
    # Signed scope: all 4 top-level keys (agent_did, publisher_did, items, currency)
    # AND each items[].unit_price are inside the signed bytes. The agent crypto-
    # commits to the per-fetch price; publisher cannot raise the price between
    # fetch and POST without breaking the signature.
    order_payload = {
        "agent_did": agent.did,
        "publisher_did": publisher_did,
        "items": items_to_order,   # each entry: sku, quantity, unit_price
        "currency": manifest["payment"]["currencies"][0],
    }
    # Sign the order with agent's ed25519 key (Ed25519 from agent.sign per SDK)
    order_signature = agent.sign(json.dumps(order_payload, sort_keys=True).encode("utf-8")).hex()

    payment_endpoint = manifest["payment"]["endpoint"]
    print(f"Placing order at {payment_endpoint}")
    with httpx.Client(timeout=30.0) as http:
        order_response = http.post(
            payment_endpoint,
            json={
                **order_payload,
                "agent_signature_hex": order_signature,
                "cryptosuite": "eddsa-rdfc-2022",
            },
        )
    order_response.raise_for_status()
    receipt = order_response.json()

    print(f"Order placed. ID: {receipt.get('order_id', '<no id>')}")
    print(f"Fulfillment status: {receipt.get('fulfillment_status', '<no status>')}")
    return receipt


if __name__ == "__main__":
    # Demo: shop the example bakery
    receipt = shop_publisher(
        publisher_domain="sample-bakery.example",
        agent_name="health-bot-trav",
        desired_items=[
            {"sku": "BAKERY-SOURDOUGH-800", "quantity": 1},
            {"sku": "BAKERY-CROISSANT-1", "quantity": 6},
            {"sku": "BAKERY-WEDDING-CAKE-3T", "quantity": 1},  # gets escalated
        ],
    )
    print(json.dumps(receipt, indent=2))
