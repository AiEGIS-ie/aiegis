"""
AiEGIS Apple Secure Enclave / App Attest Assertion Verifier — operator-side reference.

Authored: 2026-05-10 ~19:35 IST per Trav cadence directive.
Composes with HOST_SUBSTRATE_FINGERPRINT_BINDING_SPEC_V01.md (sha aa2fd76c) Lane B.

Apple App Attest flow (server-side, per Apple Developer docs):
  1. Agent (Mac/iPhone/iPad app) generates SE-backed keypair via DCAppAttestService.
  2. Agent provides attestation object (CBOR) on first ship — binds keypair to
     Apple device + team-id.
  3. Per-request: agent generates assertion via SE — signature over (clientData,
     authenticatorData) where clientData embeds the operator-supplied nonce.
  4. Operator verifies assertion: signature valid + counter monotonic + RP-ID
     hash matches expected + nonce matches what we sent.

This file implements ASSERTION verification (per-request, not the one-time
attestation-object validation). Attestation-object validation is the install-
time ceremony; assertion is the runtime authentication.

WIRE: agent provides:
  - assertion_object: bytes (CBOR or raw) containing:
      * authenticatorData: bytes (per WebAuthn / CTAP2 layout)
      * signature: bytes (over authenticatorData || sha256(clientDataJSON))
  - client_data_json: bytes (JSON with operator nonce as challenge field)
  - attested_pubkey_der: bytes (the SE-attested ES256 pubkey from install-time)

OPERATOR provides:
  - expected_rp_id: str ("aiegis.ie") — hashed and compared against authenticatorData
  - expected_nonce: bytes — the challenge embedded in client_data_json.challenge
  - last_known_counter: int — monotonic counter from previous assertion (or -1)
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass

from substrate_errors import SubstrateError, ErrorCode


# Apple App Attest RP ID for AiEGIS.
AIEGIS_APP_ATTEST_RP_ID = "aiegis.ie"


@dataclass(frozen=True)
class AppleSeAssertionVerifyInput:
    """Inputs for verifying a single App Attest assertion."""

    authenticator_data: bytes
    signature: bytes
    client_data_json: bytes
    attested_pubkey_der: bytes
    expected_rp_id: str
    expected_nonce: bytes
    last_known_counter: int

    def __post_init__(self) -> None:
        for field_name in (
            "authenticator_data", "signature", "client_data_json",
            "attested_pubkey_der", "expected_nonce",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, (bytes, bytearray)):
                raise TypeError(
                    f"AppleSeAssertionVerifyInput.{field_name} must be bytes, "
                    f"got {type(value).__name__}"
                )
            if len(value) == 0:
                raise SubstrateError(
                    ErrorCode.SHAPE_INVALID,
                    detail=f"AppleSeAssertionVerifyInput.{field_name} must be non-empty",
                )
        if not isinstance(self.expected_rp_id, str):
            raise TypeError(
                "AppleSeAssertionVerifyInput.expected_rp_id must be str, "
                f"got {type(self.expected_rp_id).__name__}"
            )
        if not self.expected_rp_id:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="AppleSeAssertionVerifyInput.expected_rp_id must be non-empty",
            )
        # Reject ASCII control chars (incl. NUL) — embedded NUL enables
        # smuggling against RP-ID matching against authenticatorData rpIdHash.
        for ch in self.expected_rp_id:
            if ord(ch) < 0x20 or ord(ch) == 0x7F:
                raise SubstrateError(
                    ErrorCode.CHARSET_VIOLATION,
                    detail="AppleSeAssertionVerifyInput.expected_rp_id must not contain ASCII control characters (NUL/CTL smuggling guard)",
                )
        if not isinstance(self.last_known_counter, int) or isinstance(self.last_known_counter, bool):
            raise TypeError(
                "AppleSeAssertionVerifyInput.last_known_counter must be int, "
                f"got {type(self.last_known_counter).__name__}"
            )
        if self.last_known_counter < 0:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="AppleSeAssertionVerifyInput.last_known_counter must be >=0",
            )
        # WebAuthn signCount field is a uint32 (4-byte big-endian); values
        # beyond 2^32-1 are never produced by a real authenticator.
        if self.last_known_counter > 0xFFFFFFFF:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="AppleSeAssertionVerifyInput.last_known_counter must be <=2^32-1 (WebAuthn signCount uint32 max)",
            )
        if len(self.authenticator_data) < 37:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="AppleSeAssertionVerifyInput.authenticator_data must be >=37B (WebAuthn: 32B rpIdHash + 1B flags + 4B counter minimum)",
            )
        # WebAuthn clientDataJSON must parse as a JSON object — heuristic
        # startswith('{') was too weak (passed '   {garbage'). Real parse here.
        try:
            _parsed = json.loads(self.client_data_json)
        except (json.JSONDecodeError, ValueError) as e:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail=f"AppleSeAssertionVerifyInput.client_data_json must be valid JSON ({type(e).__name__})",
            )
        if not isinstance(_parsed, dict):
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail=f"AppleSeAssertionVerifyInput.client_data_json must be a JSON object (got {type(_parsed).__name__})",
            )
        if len(self.expected_nonce) < 16:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="AppleSeAssertionVerifyInput.expected_nonce must be >=16B (anti-replay minimum)",
            )


@dataclass(frozen=True)
class AppleSeAssertionVerifyResult:
    """Verification outcome with field-level explanations."""

    valid: bool
    rp_id_hash_match: bool
    counter_monotonic: bool
    nonce_match: bool
    signature_valid: bool
    counter_value: int
    failure_reasons: tuple[str, ...]


def _parse_authenticator_data(auth_data: bytes) -> tuple[bytes, int, int]:
    """
    Parse authenticatorData per WebAuthn spec.

    Layout (37 bytes minimum):
      0..31  rp_id_hash (SHA-256 of RP ID)
      32     flags byte
      33..36 signCount (uint32 big-endian)
      37+    extensions / attestation data (varies)

    Returns (rp_id_hash, flags, sign_count).
    """
    if len(auth_data) < 37:
        raise SubstrateError(
            ErrorCode.SUBSTRATE_ATTESTATION_INVALID,
            detail=f"authenticatorData too short: {len(auth_data)} < 37 bytes",
        )
    rp_id_hash = auth_data[:32]
    flags = auth_data[32]
    sign_count = struct.unpack(">I", auth_data[33:37])[0]
    return rp_id_hash, flags, sign_count


def _extract_nonce_from_client_data(client_data_json: bytes) -> bytes:
    """
    Extract challenge field from client data JSON.

    Per WebAuthn, clientDataJSON has shape:
      { "type": "webauthn.get", "challenge": "<base64url-nonce>",
        "origin": "https://aiegis.ie" }

    Returns raw nonce bytes (base64url-decoded).
    """
    try:
        parsed = json.loads(client_data_json)
    except json.JSONDecodeError as e:
        raise SubstrateError(
            ErrorCode.SHAPE_INVALID,
            detail=f"client_data_json not valid JSON: {type(e).__name__}",
        ) from e
    challenge_b64url = parsed.get("challenge")
    if not isinstance(challenge_b64url, str):
        raise SubstrateError(
            ErrorCode.SHAPE_INVALID,
            detail="client_data_json missing 'challenge' field",
        )
    import base64

    padded = challenge_b64url + "=" * (4 - len(challenge_b64url) % 4)
    return base64.urlsafe_b64decode(padded)


def _verify_es256_signature(
    authenticator_data: bytes,
    client_data_json: bytes,
    signature: bytes,
    attested_pubkey_der: bytes,
) -> bool:
    """
    Verify ES256 signature per WebAuthn.

    Signature is over: authenticatorData || SHA256(clientDataJSON)
    Apple SE uses ES256 (ECDSA over P-256 + SHA-256).
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

    try:
        pubkey = serialization.load_der_public_key(attested_pubkey_der)
        if not isinstance(pubkey, ec.EllipticCurvePublicKey):
            return False
        signed_bytes = authenticator_data + hashlib.sha256(client_data_json).digest()
        pubkey.verify(signature, signed_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, UnsupportedAlgorithm, ValueError):
        # Specific catches only — programmer bugs bubble up.
        return False


def verify_apple_se_assertion(
    inputs: AppleSeAssertionVerifyInput,
) -> AppleSeAssertionVerifyResult:
    """
    Top-level operator-side App Attest assertion verifier.

    Order of checks (all must pass for valid=True):
      1. Parse authenticatorData (37+ byte WebAuthn shape)
      2. rp_id_hash == SHA-256(expected_rp_id)
      3. signCount > last_known_counter (replay defense)
      4. Nonce in clientDataJSON.challenge == expected_nonce (freshness)
      5. ES256 signature over (authenticatorData || sha256(clientDataJSON)) valid
    """
    reasons: list[str] = []

    try:
        rp_id_hash, _flags, sign_count = _parse_authenticator_data(
            inputs.authenticator_data
        )
    except ValueError as e:
        return AppleSeAssertionVerifyResult(
            valid=False,
            rp_id_hash_match=False,
            counter_monotonic=False,
            nonce_match=False,
            signature_valid=False,
            counter_value=-1,
            failure_reasons=(f"authenticator_data_parse_failure: {type(e).__name__}",),
        )

    expected_rp_id_hash = hashlib.sha256(inputs.expected_rp_id.encode("utf-8")).digest()
    rp_id_match = rp_id_hash == expected_rp_id_hash
    if not rp_id_match:
        reasons.append(
            f"rp_id_hash_mismatch (got {rp_id_hash.hex()[:16]}..., expected "
            f"{expected_rp_id_hash.hex()[:16]}...)"
        )

    counter_monotonic = sign_count > inputs.last_known_counter
    if not counter_monotonic:
        reasons.append(
            f"counter_not_monotonic (got {sign_count}, "
            f"last_known {inputs.last_known_counter})"
        )

    try:
        nonce_from_client_data = _extract_nonce_from_client_data(
            inputs.client_data_json
        )
        nonce_match = nonce_from_client_data == inputs.expected_nonce
        if not nonce_match:
            reasons.append("nonce_mismatch")
    except ValueError as e:
        nonce_match = False
        # Use class name only (e.g. "ValueError") — not str(e) which could
        # leak user input or file paths into regulator-facing audit trail.
        # Per Velo red-team 2026-05-10 20:43 IST details-field leak concern.
        reasons.append(f"nonce_extraction_failure: {type(e).__name__}")

    sig_valid = _verify_es256_signature(
        inputs.authenticator_data,
        inputs.client_data_json,
        inputs.signature,
        inputs.attested_pubkey_der,
    )
    if not sig_valid:
        reasons.append("es256_signature_invalid")

    valid = rp_id_match and counter_monotonic and nonce_match and sig_valid

    return AppleSeAssertionVerifyResult(
        valid=valid,
        rp_id_hash_match=rp_id_match,
        counter_monotonic=counter_monotonic,
        nonce_match=nonce_match,
        signature_valid=sig_valid,
        counter_value=sign_count,
        failure_reasons=tuple(reasons),
    )


__all__ = [
    "AppleSeAssertionVerifyInput",
    "AppleSeAssertionVerifyResult",
    "verify_apple_se_assertion",
    "AIEGIS_APP_ATTEST_RP_ID",
]
