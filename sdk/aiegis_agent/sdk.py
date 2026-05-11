"""
Public SDK surface — Agent + create_agent.

v0.6.1 wires the four private modules (_crypto, _storage, _client) into
a single one-line public API:

    import aiegis_agent
    agent = aiegis_agent.create_agent(name="support-bot", operator_id="acme")
    sig = agent.sign(payload)
    passport = agent.passport()  # dict ready for /api/agent/issue
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional

from aiegis_agent import _crypto, _storage
from aiegis_agent.errors import IdentityError


@dataclass
class Agent:
    """Public agent handle. Construct via create_agent() — never directly."""

    name: str
    did: str
    public_key_hex: str
    operator_id: Optional[str]
    _stored: "_storage.StoredAgent"

    def sign(self, payload: bytes) -> bytes:
        """Sign payload bytes with the agent's Ed25519 private key.

        Returns raw 64-byte signature. Deterministic per RFC 8032 § 5.1.6 —
        same (key, payload) produces the same bytes every call.
        """
        priv = _storage.load_private_key(self.name)
        return _crypto.sign(priv, payload)

    def passport(
        self,
        *,
        risk_classification: str = "minimal",
        ttl_seconds: int = 86400,
    ) -> dict:
        """Build a signed passport conforming to agent_passport_schema_v1_8.

        The returned dict is ready to pass to AiegisClient.issue_passport()
        as the body fields. Caller is still responsible for the PoP challenge
        flow — passport() does NOT call /api/agent/issue/challenge automatically.
        """
        if risk_classification not in {"minimal", "limited", "high", "critical"}:
            raise IdentityError(f"risk_classification must be minimal|limited|high|critical, got {risk_classification!r}")
        now = int(time.time())
        return {
            "agent_id": self.name,
            "operator_id": self.operator_id,
            "agent_pubkey_hex": self.public_key_hex,
            "did": self.did,
            "credentials": {
                "type": "Ed25519",
                "issued_at": now,
                "expires_at": now + ttl_seconds,
            },
            "risk_classification": risk_classification,
            "governance_payload": {
                "pillars_version": "1.0",
                "accountability_enforced": True,
                "transparency_enforced": True,
                "audit_trail_enabled": True,
                "intervention_capable": True,
            },
        }


def create_agent(
    name: str,
    *,
    operator_id: Optional[str] = None,
    api_base: str = "https://aiegis.ie",
) -> Agent:
    """Create or load an agent identity for `name`.

    First call: generates Ed25519 keypair, stores private key in OS keyring,
    writes public metadata to $AIEGIS_HOME/agents/<name>.json.

    Subsequent calls with the same name: loads the existing identity from
    keyring + sidecar.

    Args:
        name: human-readable agent name (e.g. "support-bot-prod-1").
        operator_id: AiEGIS operator that the agent rolls up to.
            Defaults to the AIEGIS_OPERATOR_ID environment variable.
        api_base: AiEGIS instance URL (kept for forward compatibility; v0.6.1
            does not call the network during create_agent — registration is
            a separate explicit step via AiegisClient).

    Returns:
        Agent with .did, .public_key_hex, .name, .operator_id populated.
    """
    if not name or "/" in name or name.startswith("."):
        raise IdentityError(f"invalid agent name: {name!r}")
    op = operator_id or os.environ.get("AIEGIS_OPERATOR_ID")
    stored = _storage.load_or_create(name, operator_id=op)
    return Agent(
        name=stored.name,
        did=stored.did,
        public_key_hex=stored.public_key_hex,
        operator_id=stored.operator_id,
        _stored=stored,
    )
