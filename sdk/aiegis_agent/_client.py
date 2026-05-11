"""
HTTPS client for /api/agent/* endpoints. Mirrors deployed wire-protocol
per agent_passport_schema_v1_8 + governance_payload 5-pillar contract +
risk_classification ∈ {minimal, limited, high, critical}.

Wire endpoints (deployed reality, NOT proposal):
  POST /api/agent/issue/challenge
    request:  empty body, Bearer auth
    response: {challenge_id, challenge_nonce_hex, ttl_seconds, instructions}
  POST /api/agent/issue
    request: FLAT {agent_id, operator_id, agent_pubkey_pem, credentials,
                   challenge_id, challenge_signature_hex, risk_classification,
                   governance_payload}
    response: {agent_id, status, reason?, issued_at}
  POST /api/agent/verify
    request:  {passport: <agent_passport_schema_v1_8>}
    response: {valid, checks: {...}, agent_id?, operator_id?, reason?}

Authored from deployed code, not from imagination — per
feedback_grep_canonical_before_writing_wire_protocol.md.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from aiegis_agent.errors import NetworkError

DEFAULT_API_BASE = "https://aiegis.ie"
DEFAULT_TIMEOUT_SECONDS = 10.0
USER_AGENT = "aiegis-agent-sdk-python/0.6.3"


@dataclass(frozen=True)
class ChallengeResponse:
    challenge_id: str
    challenge_nonce_hex: str
    ttl_seconds: int
    instructions: str


@dataclass(frozen=True)
class IssueResponse:
    agent_id: str
    status: str  # 'issued' | 'rejected'
    issued_at: int
    reason: Optional[str] = None


@dataclass(frozen=True)
class VerifyResponse:
    valid: bool
    checks: dict
    agent_id: Optional[str] = None
    operator_id: Optional[str] = None
    reason: Optional[str] = None


class AiegisClient:
    """HTTPS client. One instance per (api_base, bearer) pair.

    Stateless beyond config — safe to construct fresh per request or share
    across an SDK consumer's lifetime. Underlying httpx.Client is created
    on demand and closed via context-manager or .close().
    """

    def __init__(
        self,
        api_base: str = DEFAULT_API_BASE,
        bearer_token: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self._bearer = bearer_token
        self._timeout = timeout
        self._client: Optional[httpx.Client] = None

    def __enter__(self) -> "AiegisClient":
        self._client = httpx.Client(timeout=self._timeout)
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def _headers(self) -> dict[str, str]:
        h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if self._bearer:
            h["Authorization"] = f"Bearer {self._bearer}"
        return h

    def _client_or_default(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        # caller didn't use context-manager — create one-shot client
        return httpx.Client(timeout=self._timeout)

    def _post(self, path: str, *, json_body: Optional[dict] = None) -> dict:
        url = f"{self.api_base}{path}"
        client = self._client_or_default()
        try:
            resp = client.post(url, json=json_body, headers=self._headers())
        except httpx.HTTPError as e:
            raise NetworkError(f"HTTPS call to {path} failed: {e}") from e
        finally:
            if self._client is None:
                client.close()
        if resp.status_code >= 500:
            raise NetworkError(
                f"server error {resp.status_code} on {path}: {resp.text[:200]}"
            )
        try:
            data = resp.json()
        except json.JSONDecodeError as e:
            raise NetworkError(f"non-JSON response from {path}: {e}") from e
        if resp.status_code >= 400:
            reason = data.get("reason") or data.get("detail") or data.get("error") or "unknown"
            raise NetworkError(f"{path} returned {resp.status_code}: {reason}")
        return data

    def request_challenge(self) -> ChallengeResponse:
        """POST /api/agent/issue/challenge — empty body, Bearer auth.

        Server returns hex-encoded nonce (NOT base64-url) per deployed contract.
        """
        data = self._post("/api/agent/issue/challenge", json_body=None)
        try:
            return ChallengeResponse(
                challenge_id=data["challenge_id"],
                challenge_nonce_hex=data["challenge_nonce_hex"],
                ttl_seconds=int(data["ttl_seconds"]),
                instructions=data.get("instructions", ""),
            )
        except (KeyError, TypeError, ValueError) as e:
            raise NetworkError(f"malformed /challenge response: {e}") from e

    def issue_passport(
        self,
        *,
        agent_id: str,
        operator_id: str,
        agent_pubkey_pem: str,
        credentials: dict,
        challenge_id: str,
        challenge_signature_hex: str,
        risk_classification: str,
        governance_payload: dict,
    ) -> IssueResponse:
        """POST /api/agent/issue — FLAT request body (deployed contract).

        Caller is responsible for:
          • signing canonical bytes(challenge_id || nonce || passport-fields)
            and hex-encoding the resulting 64-byte signature
          • producing governance_payload with all 5 mandatory pillars
          • picking risk_classification ∈ {minimal, limited, high, critical}
        """
        if risk_classification not in {"minimal", "limited", "high", "critical"}:
            raise NetworkError(
                f"risk_classification must be minimal|limited|high|critical, got {risk_classification!r}"
            )
        required_pillars = {
            "pillars_version",
            "accountability_enforced",
            "transparency_enforced",
            "audit_trail_enabled",
            "intervention_capable",
        }
        missing = required_pillars - set(governance_payload.keys())
        if missing:
            raise NetworkError(f"governance_payload missing pillars: {sorted(missing)}")

        body = {
            "agent_id": agent_id,
            "operator_id": operator_id,
            "agent_pubkey_pem": agent_pubkey_pem,
            "credentials": credentials,
            "challenge_id": challenge_id,
            "challenge_signature_hex": challenge_signature_hex,
            "risk_classification": risk_classification,
            "governance_payload": governance_payload,
        }
        data = self._post("/api/agent/issue", json_body=body)
        try:
            return IssueResponse(
                agent_id=data["agent_id"],
                status=data["status"],
                issued_at=int(data["issued_at"]),
                reason=data.get("reason"),
            )
        except (KeyError, TypeError, ValueError) as e:
            raise NetworkError(f"malformed /issue response: {e}") from e

    def verify_passport(self, passport: dict) -> VerifyResponse:
        """POST /api/agent/verify — passport bytes returned in nested 'passport' field per deployed contract."""
        data = self._post("/api/agent/verify", json_body={"passport": passport})
        try:
            return VerifyResponse(
                valid=bool(data["valid"]),
                checks=data.get("checks", {}),
                agent_id=data.get("agent_id"),
                operator_id=data.get("operator_id"),
                reason=data.get("reason"),
            )
        except (KeyError, TypeError) as e:
            raise NetworkError(f"malformed /verify response: {e}") from e
