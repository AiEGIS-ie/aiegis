"""
AiEGIS BindingProof — operator-signed linkage between logical agent DID and
host-substrate-attested DID.

Authored: 2026-05-10 ~20:06 IST per Trav cadence directive.
Composes with HOST_SUBSTRATE_FINGERPRINT_BINDING_SPEC §"Multi-substrate logical
agent (single attachment point invariant)".

WHY THIS EXISTS

The spec defines that an AiEGIS agent has ONE logical identity
(did:aiegis:agent:<logical-pubkey>) that can be bound to N host-substrate
identities (did:aiegis:tpm:..., did:aiegis:apple-se:..., did:aiegis:tee:...).

But "bound to" needs a cryptographic primitive. Otherwise a regulator
auditing the compliance bundle has no way to verify that this particular
agent's logical identity is really associated with this particular host
substrate — anyone could claim the linkage in a JSON field.

The BindingProof IS that primitive:

  BindingProof = sign_operator(
      hash(logical_agent_did || host_substrate_did || host_attestation_blob ||
           binding_timestamp || nonce)
  )

Operator signs because:
1. Agent shouldn't self-attest (Trav invariant: non-volitional).
2. Operator is the trust root (DID method spec).
3. Per OPERATOR_KEY_CUSTODY_SPEC, operator root is FIPS 140-2 L3 HSM-bound.

VERIFIER FLOW

Regulator extracts BindingProof from bundle, validates:
  1. Signature is valid Ed25519 (or v0.7+ hybrid Ed25519+ML-DSA-65) under operator pubkey.
  2. Operator pubkey matches the issuer DID in the bundle.
  3. host_substrate_did inside the BindingProof matches the substrate-attestation
     field of the bundle.
  4. binding_timestamp is within acceptable freshness window (operator policy).

This module ships REFERENCE generation + verification of BindingProof. Real
production swaps operator-key access for YubiHSM 2 PKCS#11 calls per
OPERATOR_KEY_CUSTODY_SPEC.

Composes with HOST_SUBSTRATE_FINGERPRINT_BINDING_SPEC_V01.md
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass

from substrate_errors import SubstrateError, ErrorCode


_VALID_CRYPTOSUITES = frozenset({
    "eddsa-rdfc-2022",  # v0.7 baseline (W3C VC Data Integrity)
    "ml-dsa-65-rdfc-2026",  # v0.7+ hybrid PQC (placeholder name)
    "eddsa-ml-dsa-65-hybrid-2026",  # v0.7+ hybrid (final name TBD by W3C VC DI WG)
})
# NOTE on eddsa-jcs-2022: v0.7 verifier does NOT accept this cryptosuite label
# because _canonical_message() below does JSON-sort+UTF-8 (NOT true JCS RFC 8785).
# Accepting the label without implementing JCS-driven canonicalization would
# silently mis-verify v0.6-canonical-bytes-labeled-jcs bundles (V red-team
# lap-388, 2026-05-11). v0.8 adds eddsa-jcs-2022 with proper JCS canonicalization
# branched on the cryptosuite label. Until then, v0.7 issuers MUST use
# eddsa-rdfc-2022 and v0.7 verifiers reject eddsa-jcs-2022 with loud
# "must be one of [...]" rather than silent signature-mismatch.

# Signature length per cryptosuite (in hex chars; 2 hex per byte).
# Ed25519 sig = 64B, ML-DSA-65 sig = 3293B (verified pq-crystals.org Dilithium3 2026-05-11), hybrid = concat = 3357B.
_CRYPTOSUITE_SIG_HEX_LEN = {
    "eddsa-rdfc-2022": 128,
    "ml-dsa-65-rdfc-2026": 6586,  # 3293 bytes × 2 hex chars; corrected lap 75 2026-05-11 03:09 IST per pq-crystals.org/dilithium/ Dilithium3 (was 6618 = 3309 × 2, defective by 32 hex chars)
    "eddsa-ml-dsa-65-hybrid-2026": 6714,  # (64 + 3293) × 2; corrected from 6746 = (64+3309)×2
}

# DID body charset: alphanumeric (UPPER+lower for base58/base64url bodies
# like did:key z6Mk... multibase identifiers) + safe DID method-specific
# chars. Per W3C DID Core §3.1 method-specific-id grammar.
# Explicitly EXCLUDES: '/' '\\' whitespace control-chars — these enable
# path-traversal / smuggling in audit fields.
_DID_BODY_ALLOWED = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    ":-_."
)


def _is_lowercase_hex(s: str, expected_len: int | None = None) -> bool:
    """True if s is lowercase hex of optional fixed length."""
    if not isinstance(s, str):
        return False
    if expected_len is not None and len(s) != expected_len:
        return False
    if not all(c in "0123456789abcdef" for c in s):
        return False
    return True


def _validate_did_aiegis(did: str, expected_prefix: str, field_name: str) -> None:
    """Reject malformed did:aiegis: bodies (charset + length)."""
    if not did.startswith(expected_prefix):
        raise SubstrateError(
            ErrorCode.SHAPE_INVALID,
            detail=f"{field_name} must start with {expected_prefix!r}",
        )
    body = did[len(expected_prefix):]
    if not body:
        raise SubstrateError(
            ErrorCode.SHAPE_INVALID,
            detail=f"{field_name} body must be non-empty after prefix",
        )
    if len(body) > 256:
        raise SubstrateError(
            ErrorCode.LENGTH_CAP_EXCEEDED,
            detail=f"{field_name} body too long (>256 chars; got {len(body)})",
        )
    bad = set(body) - _DID_BODY_ALLOWED
    if bad:
        raise SubstrateError(
            ErrorCode.CHARSET_VIOLATION,
            detail=(
                f"{field_name} body contains disallowed chars (charset guard); "
                f"allowed: alphanumeric + ':-_.' (no '/' '\\' or control chars)"
            ),
        )


def _validate_rfc3339_shape(ts: str, field_name: str) -> None:
    """Loose RFC 3339 shape check — must have 'T' and Z/offset suffix."""
    if not ts or "T" not in ts:
        raise SubstrateError(
            ErrorCode.TIMESTAMP_INVALID,
            detail=f"{field_name} must be RFC 3339 with 'T' separator",
        )
    if not (ts.endswith("Z") or "+" in ts[10:] or "-" in ts[10:]):
        raise SubstrateError(
            ErrorCode.TIMESTAMP_INVALID,
            detail=f"{field_name} must end with 'Z' or +/- UTC offset (RFC 3339)",
        )


@dataclass(frozen=True)
class BindingProofInput:
    """Inputs to BindingProof generation (operator-side)."""

    logical_agent_did: str  # e.g. "did:aiegis:agent:z6Mk..."
    host_substrate_did: str  # e.g. "did:aiegis:tpm:..." or "did:aiegis:apple-se:..."
    host_attestation_blob_sha256: str  # SHA-256 hex of the substrate_attestation dict
    binding_timestamp_iso: str  # RFC 3339 UTC, e.g. "2026-05-10T20:00:00Z"
    nonce_hex: str  # 32-byte random hex, anti-replay

    def __post_init__(self):
        # Audit-trail integrity: reject malformed inputs at construction time
        # so they can't ship into a regulator-handed bundle. Mirrors Velo's
        # BeaconEvent.decision validation pattern (2026-05-10 20:54 IST).
        # Strengthened 2026-05-10 23:08 IST per asymmetry self-audit.
        _validate_did_aiegis(
            self.logical_agent_did, "did:aiegis:agent:", "logical_agent_did"
        )
        if not self.host_substrate_did.startswith("did:aiegis:"):
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="host_substrate_did must start with 'did:aiegis:'",
            )
        # Validate body charset on substrate too (any tier prefix).
        _known_substrate_prefixes = (
            "did:aiegis:tpm:", "did:aiegis:apple-se:", "did:aiegis:tee:"
        )
        matched_prefix = next(
            (p for p in _known_substrate_prefixes
             if self.host_substrate_did.startswith(p)), None
        )
        if matched_prefix is None:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail=(
                    "host_substrate_did must start with one of "
                    f"{_known_substrate_prefixes}"
                ),
            )
        _validate_did_aiegis(
            self.host_substrate_did, matched_prefix, "host_substrate_did"
        )
        if not _is_lowercase_hex(self.host_attestation_blob_sha256, expected_len=64):
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="host_attestation_blob_sha256 must be 64-char lowercase hex (SHA-256)",
            )
        if not _is_lowercase_hex(self.nonce_hex, expected_len=64):
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="nonce_hex must be 64-char lowercase hex (32 bytes)",
            )
        _validate_rfc3339_shape(self.binding_timestamp_iso, "binding_timestamp_iso")


@dataclass(frozen=True)
class BindingProof:
    """The operator-signed BindingProof structure."""

    logical_agent_did: str
    host_substrate_did: str
    host_attestation_blob_sha256: str
    binding_timestamp: str
    nonce: str
    operator_did: str  # "did:aiegis:operator:..."
    signature_hex: str  # Ed25519 signature (or v0.7+ hybrid)
    cryptosuite: str  # "eddsa-rdfc-2022" today; v0.7+ "eddsa-ml-dsa-65-hybrid-2026"

    def __post_init__(self):
        # Symmetrize with BindingProofInput.__post_init__ — this is the
        # structure that ships to regulators, so it MUST validate every
        # field, not just operator_did/signature/cryptosuite. Caller can
        # construct BindingProof directly (e.g. deserialize from bundle),
        # bypassing Input-side validation entirely.
        _validate_did_aiegis(
            self.logical_agent_did, "did:aiegis:agent:", "logical_agent_did"
        )
        # host_substrate_did has multiple valid prefixes (tpm/apple-se/tee/...)
        if not self.host_substrate_did.startswith("did:aiegis:"):
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="host_substrate_did must start with 'did:aiegis:'",
            )
        # Validate the substrate-tier prefix is one of the known set + body charset.
        _known_substrate_prefixes = (
            "did:aiegis:tpm:", "did:aiegis:apple-se:", "did:aiegis:tee:"
        )
        matched_prefix = next(
            (p for p in _known_substrate_prefixes
             if self.host_substrate_did.startswith(p)), None
        )
        if matched_prefix is None:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail=(
                    "host_substrate_did must start with one of "
                    f"{_known_substrate_prefixes}"
                ),
            )
        _validate_did_aiegis(
            self.host_substrate_did, matched_prefix, "host_substrate_did"
        )
        _validate_did_aiegis(
            self.operator_did, "did:aiegis:operator:", "operator_did"
        )
        if not _is_lowercase_hex(self.host_attestation_blob_sha256, expected_len=64):
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="host_attestation_blob_sha256 must be 64-char lowercase hex (SHA-256)",
            )
        if not _is_lowercase_hex(self.nonce, expected_len=64):
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="nonce must be 64-char lowercase hex (32 bytes)",
            )
        _validate_rfc3339_shape(self.binding_timestamp, "binding_timestamp")
        if self.cryptosuite not in _VALID_CRYPTOSUITES:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail=f"cryptosuite must be one of {sorted(_VALID_CRYPTOSUITES)}",
            )
        # Cryptosuite-aware signature length check. Was: bare hex check,
        # which accepted 1-byte and 10MB signatures equally.
        expected_sig_hex_len = _CRYPTOSUITE_SIG_HEX_LEN.get(self.cryptosuite)
        if expected_sig_hex_len is None:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail=f"no signature length defined for cryptosuite {self.cryptosuite!r}",
            )
        if not _is_lowercase_hex(self.signature_hex, expected_len=expected_sig_hex_len):
            raise SubstrateError(
                ErrorCode.PROOFVALUE_HEX_INVALID,
                detail=(
                    f"signature_hex must be {expected_sig_hex_len}-char lowercase hex "
                    f"for cryptosuite {self.cryptosuite!r} (got {len(self.signature_hex)})"
                ),
            )


@dataclass(frozen=True)
class BindingProofVerifyResult:
    """Verification outcome with field-level reasons."""

    valid: bool
    signature_valid: bool
    timestamp_fresh: bool
    binding_age_seconds: float
    operator_did_match: bool
    substrate_did_match_bundle: bool
    failure_reasons: tuple[str, ...]


def _canonical_message(inputs: BindingProofInput, operator_did: str) -> bytes:
    """
    Build the canonical bytes that the operator signs.

    Current v0.6.x + v0.7 impl: key-sorted JSON + UTF-8 encoding via
    `json.dumps(sort_keys=True, separators=(",", ":")).encode("utf-8")`.
    This is NOT full JCS (RFC 8785) — JCS additionally requires
    JSON.stringify-style number serialization (e.g., 1.0 → "1"),
    Unicode NFC normalization, and lowercase hex escapes for control chars.

    v0.8 will migrate to true JCS via the `jcs` Python lib + corresponding
    cryptosuite rename `eddsa-rdfc-2022` → `eddsa-jcs-2022`. The v0.8
    migration MUST include label-driven canonicalization branching here —
    accepting the `eddsa-jcs-2022` label without that branch would silently
    mis-verify v0.7-canonical bundles (V red-team lap-388, 2026-05-11).
    """
    payload = {
        "binding_timestamp": inputs.binding_timestamp_iso,
        "host_attestation_blob_sha256": inputs.host_attestation_blob_sha256,
        "host_substrate_did": inputs.host_substrate_did,
        "logical_agent_did": inputs.logical_agent_did,
        "nonce": inputs.nonce_hex,
        "operator_did": operator_did,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_binding_proof(
    inputs: BindingProofInput,
    operator_priv_bytes: bytes,
    operator_did: str,
) -> BindingProof:
    """
    Generate an operator-signed BindingProof.

    Args:
        inputs: BindingProofInput with all message fields.
        operator_priv_bytes: 32-byte Ed25519 private key (raw, not PEM).
            Real impl uses YubiHSM 2 PKCS#11 signing call; this reference
            uses cryptography's ed25519.
        operator_did: "did:aiegis:operator:..."

    Returns:
        BindingProof with Ed25519 signature.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519

    if len(operator_priv_bytes) != 32:
        raise SubstrateError(
            ErrorCode.KEY_FORMAT_INVALID,
            detail=f"operator_priv_bytes must be 32 bytes (raw Ed25519), got {len(operator_priv_bytes)}",
        )

    message = _canonical_message(inputs, operator_did)
    key = ed25519.Ed25519PrivateKey.from_private_bytes(operator_priv_bytes)
    signature = key.sign(message)

    return BindingProof(
        logical_agent_did=inputs.logical_agent_did,
        host_substrate_did=inputs.host_substrate_did,
        host_attestation_blob_sha256=inputs.host_attestation_blob_sha256,
        binding_timestamp=inputs.binding_timestamp_iso,
        nonce=inputs.nonce_hex,
        operator_did=operator_did,
        signature_hex=signature.hex(),
        cryptosuite="eddsa-rdfc-2022",
    )


def verify_binding_proof(
    proof: BindingProof,
    operator_pub_bytes: bytes,
    *,
    bundle_substrate_did: str | None = None,
    bundle_operator_did: str | None = None,
    freshness_window_seconds: int = 7 * 24 * 3600,  # 7 days default
) -> BindingProofVerifyResult:
    """
    Verify an operator-signed BindingProof.

    Args:
        proof: BindingProof to verify.
        operator_pub_bytes: 32-byte Ed25519 public key (raw).
        bundle_substrate_did: if provided, MUST match proof.host_substrate_did
            (prevents binding-proof swap across bundles).
        bundle_operator_did: if provided, MUST match proof.operator_did
            (prevents operator-impersonation).
        freshness_window_seconds: maximum age of BindingProof.

    Returns:
        BindingProofVerifyResult with field-level failure reasons.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    from datetime import datetime, timezone

    reasons: list[str] = []

    # 1. Signature validation
    try:
        inputs = BindingProofInput(
            logical_agent_did=proof.logical_agent_did,
            host_substrate_did=proof.host_substrate_did,
            host_attestation_blob_sha256=proof.host_attestation_blob_sha256,
            binding_timestamp_iso=proof.binding_timestamp,
            nonce_hex=proof.nonce,
        )
        message = _canonical_message(inputs, proof.operator_did)
        pubkey = ed25519.Ed25519PublicKey.from_public_bytes(operator_pub_bytes)
        pubkey.verify(bytes.fromhex(proof.signature_hex), message)
        signature_valid = True
    except (InvalidSignature, ValueError, Exception) as e:
        signature_valid = False
        reasons.append(f"signature_invalid: {type(e).__name__}")

    # 2. Freshness check
    try:
        ts_str = proof.binding_timestamp.rstrip("Z") + "+00:00"
        # Handle both "Z" and "+00:00" suffixes; default to UTC.
        binding_dt = datetime.fromisoformat(proof.binding_timestamp.replace("Z", "+00:00"))
        if binding_dt.tzinfo is None:
            binding_dt = binding_dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age = (now - binding_dt).total_seconds()
        timestamp_fresh = 0 <= age <= freshness_window_seconds
        if not timestamp_fresh:
            if age < 0:
                reasons.append(f"timestamp_in_future: {age:.0f}s")
            else:
                reasons.append(
                    f"timestamp_stale: {age:.0f}s > {freshness_window_seconds}s window"
                )
    except (ValueError, Exception) as e:
        timestamp_fresh = False
        age = -1.0
        # Class-name only — see Velo red-team 2026-05-10 20:43 IST.
        reasons.append(f"timestamp_parse_failure: {type(e).__name__}")

    # 3. Operator DID match (defends operator-impersonation)
    if bundle_operator_did is not None and bundle_operator_did != proof.operator_did:
        operator_did_match = False
        reasons.append(
            f"operator_did_mismatch (bundle says {bundle_operator_did}, "
            f"proof says {proof.operator_did})"
        )
    else:
        operator_did_match = True

    # 4. Substrate DID match (defends binding-proof swap across bundles)
    if bundle_substrate_did is not None and bundle_substrate_did != proof.host_substrate_did:
        substrate_did_match_bundle = False
        reasons.append(
            f"substrate_did_mismatch (bundle says {bundle_substrate_did}, "
            f"proof says {proof.host_substrate_did})"
        )
    else:
        substrate_did_match_bundle = True

    valid = (
        signature_valid
        and timestamp_fresh
        and operator_did_match
        and substrate_did_match_bundle
    )

    return BindingProofVerifyResult(
        valid=valid,
        signature_valid=signature_valid,
        timestamp_fresh=timestamp_fresh,
        binding_age_seconds=age,
        operator_did_match=operator_did_match,
        substrate_did_match_bundle=substrate_did_match_bundle,
        failure_reasons=tuple(reasons),
    )


def hash_attestation_blob(substrate_attestation: dict) -> str:
    """
    Compute SHA-256 hex of a substrate_attestation dict in canonical form.

    Uses the same JCS-style canonicalization as _canonical_message so the
    hash is deterministic across implementations.
    """
    canon = json.dumps(
        substrate_attestation, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


__all__ = [
    "BindingProofInput",
    "BindingProof",
    "BindingProofVerifyResult",
    "generate_binding_proof",
    "verify_binding_proof",
    "hash_attestation_blob",
]
