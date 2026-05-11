"""
First-agent walkthrough — copy-paste into your project to test SDK.

Run:
    pip install aiegis-agent-sdk
    AIEGIS_OPERATOR_ID=your-operator python examples/first_agent.py
"""

from __future__ import annotations

import json

import aiegis_agent


def main() -> None:
    # 1. Create or load an identity. First call generates Ed25519 keypair +
    #    stores private key in OS keychain. Subsequent calls reuse the same
    #    DID — stable across process restarts.
    agent = aiegis_agent.create_agent(
        name="my-first-agent",
        operator_id="operator-test",
    )
    print(f"agent.name = {agent.name}")
    print(f"agent.did  = {agent.did}")

    # 2. Sign arbitrary bytes with the agent's key. The signature is
    #    deterministic per RFC 8032 — same payload always produces same sig.
    payload = b"any bytes you want signed"
    sig = agent.sign(payload)
    print(f"signature  = {sig.hex()[:32]}... ({len(sig)} bytes)")

    # 3. Build a passport ready to send to /api/agent/issue. The dict is
    #    pre-validated for the 5 mandatory governance pillars + the
    #    risk_classification enum.
    passport = agent.passport(risk_classification="minimal")
    print("passport:")
    print(json.dumps(passport, indent=2))


if __name__ == "__main__":
    main()
