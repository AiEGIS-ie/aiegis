"""
AiEGIS Article 50 Compliance Bundle generator — v0.1 working prototype.

Takes a sequence of BEACON verdict events + an operator Ed25519 keypair,
emits a JSON-LD Verifiable Credential bundle suitable for EU regulator submission.

Per spec: /Users/velo/Documents/VELO/aiegis-compliance-bundle-v0_7_spec_DRAFT.md
- JSON-LD primary (JSON-sort+UTF-8 canonicalization in v0.6.x; JCS RFC 8785 in v0.7; cryptosuite rename eddsa-rdfc-2022 → eddsa-jcs-2022 queued; v1.0 optional RDFC-1.0 via PyLD)
- Signature: Ed25519 (v0.7); hybrid Ed25519+ML-DSA-65 deferred to v0.8 when cryptography lib supports ML-DSA
- Operator-key custody (signer ≠ customer)
- policyBundle: 4 SHA-256 hashes (rules.rs + lib.rs + policy.json + binary)

v0.1 NOT included: cryptosuite alignment with W3C VC Data Integrity WG hybrid-PQC draft, status-list revocation.
(JSON-LD context URLs aiegis.ie/ns/compliance/v1 + /ns/substrate/v1 ARE deployed live as of 2026-05-10 — empirically HTTP 200, byte-pinned in spec table.)

Design-record (v0.7, V+N decision 2026-05-10):
  Considered: BundleVerificationError (raise-on-fail, EAFP idiom)
  Decided: VerificationResult dataclass returning result with __bool__ for
           backwards-compat. Reason: invalid signatures are EXPECTED operating
           condition for a regulator-grade verifier (audit log wants
           structured diagnosis, not stack traces). Composes with substrate
           verifier shape-parity (5-verifier uniform schema).
  Reserved: verify_bundle_strict() raise-on-fail variant for v0.8 if usage
           data shows safety-critical callers want EAFP. Deprecate one in v0.9
           if both stabilize.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple

# Reuse aiegis-agent-sdk crypto primitives
sys.path.insert(0, "/Users/velo/Documents/VELO/aiegis-agent-sdk-python")
from aiegis_agent import _crypto  # type: ignore
from aiegis_agent.errors import IdentityError  # type: ignore


VALID_DECISIONS = frozenset({"block", "warn", "allow"})


@dataclass(frozen=True)
class BeaconEvent:
    event_id: str
    decision: str  # "block" | "warn" | "allow"
    rule: str
    timestamp: str  # ISO 8601
    customer_did: str
    classifier_hits: list

    def __post_init__(self) -> None:
        # Non-empty event_id + rule (empty values would ship into the bundle
        # but provide no useful audit trail).
        if not self.event_id:
            raise ValueError("BeaconEvent.event_id must be non-empty")
        if not self.rule:
            raise ValueError("BeaconEvent.rule must be non-empty")
        # Bounded lengths per field (DoS guard + cap absurd inputs at
        # construction). Mirrors Nel's substrate-pack discipline 2026-05-10.
        if len(self.event_id) > MAX_EVENT_ID_LEN:
            raise ValueError(
                f"BeaconEvent.event_id too long: {len(self.event_id)} > "
                f"MAX_EVENT_ID_LEN={MAX_EVENT_ID_LEN}"
            )
        if len(self.rule) > MAX_RULE_LEN:
            raise ValueError(
                f"BeaconEvent.rule too long: {len(self.rule)} > "
                f"MAX_RULE_LEN={MAX_RULE_LEN}"
            )
        if len(self.customer_did) > MAX_DID_LEN:
            raise ValueError(
                f"BeaconEvent.customer_did too long: {len(self.customer_did)} > "
                f"MAX_DID_LEN={MAX_DID_LEN}"
            )
        # Control-character / NUL smuggling defense on event_id + rule +
        # customer_did (per Nel's rp_id NUL-smuggling pattern). Rejects
        # \x00-\x1F + \x7F. Nel-glass-house-catch 2026-05-10 lap2: I'd
        # initially missed customer_did — exact intra-class drift my own pin
        # feedback_audit_all_fields_when_refactoring_one was meant to prevent.
        for fname, fval in [("event_id", self.event_id), ("rule", self.rule),
                            ("customer_did", self.customer_did)]:
            if any(ord(c) < 0x20 or ord(c) == 0x7F for c in fval):
                raise ValueError(
                    f"BeaconEvent.{fname} contains control characters; "
                    f"NUL/CTL/DEL smuggling defense"
                )
        # customer_did must be a DID URI per W3C DID Core.
        if not self.customer_did.startswith("did:"):
            raise ValueError(
                f"BeaconEvent.customer_did must be a DID URI ('did:...'); "
                f"got {self.customer_did!r}"
            )
        # Validate decision at construction so a malformed event can't silently
        # ship in the bundle and corrupt the decisionBreakdown counts (any
        # value outside the set is neither block/warn/allow and counts zero).
        if self.decision not in VALID_DECISIONS:
            raise ValueError(
                f"BeaconEvent.decision must be one of {sorted(VALID_DECISIONS)}; "
                f"got {self.decision!r}"
            )
        # Validate timestamp parses as ISO 8601. Malformed timestamp would
        # ship into bundle.verdictEvents same silent-data-corruption class as
        # invalid decision. fromisoformat accepts both naive and tz-aware
        # forms; require tz-awareness (+offset or 'Z') so audit-trail entries
        # have unambiguous wall-clock semantics.
        # Python 3.9/3.10 fromisoformat doesn't accept the 'Z' suffix that
        # most RFC 3339 producers emit. Normalize 'Z' to '+00:00' before parse
        # so customers on 3.9/3.10 regulator-infrastructure hosts don't false-
        # fail on legitimate timestamps. (Nel customer-impact catch 21:00.)
        ts_for_parse = self.timestamp[:-1] + "+00:00" if self.timestamp.endswith("Z") else self.timestamp
        try:
            parsed = datetime.fromisoformat(ts_for_parse)
        except (TypeError, ValueError) as e:
            raise ValueError(
                f"BeaconEvent.timestamp must be ISO 8601 "
                f"(got {self.timestamp!r}): {type(e).__name__}"
            ) from e
        if parsed.tzinfo is None:
            raise ValueError(
                f"BeaconEvent.timestamp must include timezone offset or 'Z'; "
                f"got naive {self.timestamp!r}"
            )


# DoS guard: regulator-handed bundles document one operator's compliance
# window. A single window with >1M events is operationally absurd and would
# produce a multi-GB bundle the regulator can't reasonably process. Cap at
# 1M to prevent both memory exhaustion in build_bundle AND meaningless
# audit-trail outputs. (Mirrors Nel's DoS-cap discipline 2026-05-10 23:01.)
MAX_EVENTS_PER_BUNDLE = 1_000_000

# Classifier version follows semver-ish (e.g. "0.6.6", "1.0.0-rc.1"). Cap at
# 64 chars to reject pathological inputs without over-constraining the format.
MAX_CLASSIFIER_VERSION_LEN = 64

# BeaconEvent field caps. Operational sizes are tiny (UUIDs, short rule names,
# DID URIs ~100 chars). Caps reject pathological inputs without constraining
# normal use.
MAX_EVENT_ID_LEN = 128       # UUIDs are 36 chars; 128 is generous
MAX_RULE_LEN = 256           # rule names like "pi.ignore_previous" / "secret.openai_key"
MAX_DID_LEN = 512            # DID URIs are typically <100 chars; 512 generous for did:web with long FQDNs

# proofValue is hex-encoded signature bytes. Ed25519 = 128 hex chars, hybrid
# ML-DSA-65 = 6586 hex chars. Cap at 16KB hex = 8KB bytes, well above all
# v0.7+ cryptosuites. Prevents DoS via 100MB+ proofValue inputs that would
# allocate ~50MB before signature verification.
MAX_PROOF_VALUE_HEX_LEN = 16384


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _policy_bundle_shas(
    rules_rs: Path,
    lib_rs: Path,
    policy_json: Optional[Path] = None,
    binary: Optional[Path] = None,
) -> dict:
    out = {
        "rulesRsSha256": _sha256_file(rules_rs) if rules_rs.exists() else None,
        "libRsSha256": _sha256_file(lib_rs) if lib_rs.exists() else None,
    }
    if policy_json and policy_json.exists():
        out["policyJsonSha256"] = _sha256_file(policy_json)
    if binary and binary.exists():
        out["binarySha256"] = _sha256_file(binary)
    return out


def build_bundle(
    events: List[BeaconEvent],
    operator_priv: bytes,
    operator_did: str,
    customer_did: str,
    valid_from: datetime,
    valid_until: datetime,
    classifier_version: str,
    policy_bundle: dict,
    substrate_attestation: Optional[dict] = None,
) -> dict:
    # Per Nel audit (sha 43e84f51 demo had only 2/4): regulator-handed bundles
    # MUST have all 4 hashes — without binary sha, auditor can't prove which
    # classifier code was running; without policy.json sha, auditor can't see
    # the operator's runtime config. Strict enforcement at build time.
    # Size cap on events list (DoS guard). 1M events per window is the
    # operational ceiling; >1M produces multi-GB bundles regulators can't
    # process. Reject early.
    if len(events) > MAX_EVENTS_PER_BUNDLE:
        raise ValueError(
            f"events list too long: {len(events)} > "
            f"MAX_EVENTS_PER_BUNDLE={MAX_EVENTS_PER_BUNDLE}"
        )

    # classifier_version must be a non-empty bounded string. Pathological
    # 10KB version strings would bloat the bundle without audit value.
    if not isinstance(classifier_version, str) or not classifier_version:
        raise ValueError("classifier_version must be a non-empty string")
    if len(classifier_version) > MAX_CLASSIFIER_VERSION_LEN:
        raise ValueError(
            f"classifier_version too long: {len(classifier_version)} > "
            f"MAX_CLASSIFIER_VERSION_LEN={MAX_CLASSIFIER_VERSION_LEN}"
        )

    # substrate_attestation, when present, must be a dict (the shape is
    # opaque to the generator — the substrate verifier owns its schema —
    # but we reject non-dicts here so caller-side bugs surface loud).
    if substrate_attestation is not None and not isinstance(substrate_attestation, dict):
        raise ValueError(
            f"substrate_attestation must be a dict or None; "
            f"got {type(substrate_attestation).__name__}"
        )

    # event_id must be unique across the events list — duplicate IDs produce
    # an ambiguous audit trail where the regulator can't disambiguate two
    # entries with the same identifier.
    _seen: set = set()
    _dups: list = []
    for e in events:
        if e.event_id in _seen:
            _dups.append(e.event_id)
        _seen.add(e.event_id)
    if _dups:
        raise ValueError(f"duplicate event_id values: {sorted(set(_dups))}")

    # Top-level customer_did must be a DID URI — same contract as the
    # BeaconEvent.customer_did, enforced symmetrically.
    if not customer_did.startswith("did:"):
        raise ValueError(
            f"customer_did must be a DID URI ('did:...'); got {customer_did!r}"
        )
    if len(customer_did) > MAX_DID_LEN:
        raise ValueError(
            f"customer_did too long: {len(customer_did)} > MAX_DID_LEN={MAX_DID_LEN}"
        )
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in customer_did):
        raise ValueError(
            "customer_did contains control characters; NUL/CTL/DEL smuggling defense"
        )

    # operator_did MUST be the did:aiegis:operator: tier per spec. Regulator-
    # handed bundle issuer signals operator-key custody (FIPS 140-2 L3 +
    # multi-party ceremony); other DID tiers (did:web, did:aiegis:agent) would
    # silently downgrade the trust claim of the bundle.
    if not operator_did.startswith("did:aiegis:operator:"):
        raise ValueError(
            f"operator_did must be 'did:aiegis:operator:...' per spec; "
            f"got {operator_did!r}"
        )

    # Cryptographic linkage: the operator_did MUST match the public key
    # derivable from operator_priv. Otherwise a caller could pass A's
    # private key with B's did_string and produce a bundle signed by A
    # but claiming B as issuer — caught at verify (signature mismatch)
    # but silently misbuilt at construction. For regulator-handed bundles
    # build-time loud-fail beats verify-time silent-misbuild.
    try:
        derived_pub = _crypto.public_from_private(operator_priv)
    except IdentityError as e:
        raise ValueError(f"operator_priv invalid for linkage check: {e}") from e
    expected_did = _crypto.derive_did(derived_pub, namespace="operator")
    if expected_did != operator_did:
        raise ValueError(
            "operator_priv does not derive operator_did "
            "(cryptographic linkage check failed; priv key would sign as "
            f"{expected_did}, caller claimed {operator_did})"
        )

    # Compliance window sanity: valid_from must precede valid_until and the
    # window can't be zero-length. Without this a regulator-handed bundle
    # could claim a meaningless retroactive window (valid_from > valid_until)
    # and still sign cleanly — audit-trail semantics broken.
    if valid_from >= valid_until:
        raise ValueError(
            f"valid_from must be strictly before valid_until; "
            f"got valid_from={valid_from.isoformat()}, valid_until={valid_until.isoformat()}"
        )

    _required_hashes = {"rulesRsSha256", "libRsSha256", "policyJsonSha256", "binarySha256"}
    _missing = _required_hashes - set(policy_bundle.keys())
    if _missing:
        raise ValueError(f"policy_bundle missing required hashes: {sorted(_missing)}")
    # Tightening: key-present isn't enough — values must be 64-char lowercase
    # hex (sha-256 hexdigest). None / empty / wrong-length silently passing
    # the prior check would put a meaningless sha into the regulator-handed
    # bundle and make the audit trail unverifiable.
    _invalid = {
        k: policy_bundle[k]
        for k in _required_hashes
        if not (isinstance(policy_bundle[k], str)
                and len(policy_bundle[k]) == 64
                and all(c in "0123456789abcdef" for c in policy_bundle[k]))
    }
    if _invalid:
        raise ValueError(
            f"policy_bundle hashes must be 64-char lowercase hex; "
            f"invalid keys: {sorted(_invalid.keys())}"
        )
    """Build + sign a Compliance Bundle as JSON-LD VC.

    Signature is Ed25519 over the canonical-bytes-without-proof representation
    of the bundle (json.dumps(sort_keys=True, separators=(',',':')).encode()).
    Caller verifies by recomputing the canonical bytes minus 'proof' field +
    Ed25519.verify(operator_pubkey, signature, canonical_bytes).
    """
    issued_at = datetime.now(timezone.utc).isoformat()
    bundle_id = f"urn:uuid:{uuid.uuid4()}"

    context = [
        "https://www.w3.org/ns/credentials/v2",
        "https://aiegis.ie/ns/compliance/v1",
    ]
    # Per Nel audit-flag: when substrate_attestation present, also link the
    # substrate vocabulary so verifiers can semantically resolve
    # TpmSubstrate / AppleSeSubstrate / TeeSubstrate type URIs.
    if substrate_attestation is not None:
        context.append("https://aiegis.ie/ns/substrate/v1")
    payload = {
        "@context": context,
        "id": bundle_id,
        "type": ["VerifiableCredential", "AiEGISComplianceBundle"],
        "issuer": operator_did,
        "validFrom": valid_from.isoformat(),
        "validUntil": valid_until.isoformat(),
        "credentialSubject": {
            "id": customer_did,
            "complianceWindow": {
                "start": valid_from.isoformat(),
                "end": valid_until.isoformat(),
            },
            "verdictEvents": [
                {
                    "eventId": e.event_id,
                    "decision": e.decision,
                    "rule": e.rule,
                    "timestamp": e.timestamp,
                    "classifierHits": e.classifier_hits,
                }
                for e in events
            ],
            "policyBundle": policy_bundle,
            "classifierVersion": classifier_version,
            "eventCount": len(events),
            "decisionBreakdown": {
                "block": sum(1 for e in events if e.decision == "block"),
                "warn":  sum(1 for e in events if e.decision == "warn"),
                "allow": sum(1 for e in events if e.decision == "allow"),
            },
        },
    }

    # Sign: canonical-bytes of payload + Ed25519
    canonical = _crypto.canonicalize(payload)
    signature = _crypto.sign(operator_priv, canonical)

    proof = {
        "type": "DataIntegrityProof",
        # NOTE: cryptosuite name "eddsa-rdfc-2022" follows the W3C registry
        # convention but the underlying canonicalization in v0.6.x is
        # JSON-sort+UTF-8 (per aiegis_agent._crypto.canonicalize docstring),
        # not full RDFC-1.0 graph canonicalization. v0.7 migrates the SDK to
        # JCS (RFC 8785) + renames cryptosuite to "eddsa-jcs-2022". v1.0
        # optional ships PyLD + true RDFC-1.0. See whitepaper section "What
        # ships today" + spec table for the 3-stage migration narrative.
        "cryptosuite": "eddsa-rdfc-2022",
        "_cryptosuite_pinned_to": "PROVISIONAL — see v0.7 rename to eddsa-jcs-2022 + JCS canonicalization migration",
        "created": issued_at,
        "verificationMethod": f"{operator_did}#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": signature.hex(),
    }
    # Per Nel HOST_SUBSTRATE_FINGERPRINT_BINDING_SPEC_V01 (sha 150d03f0):
    # if operator's signing key is bound to a hardware substrate (TPM 2.0 /
    # Apple Secure Enclave / Intel TDX-AMD SEV-SNP-ARM CCA), attach the
    # signed BindingProof. Resolves to substrate-attested DID, closing
    # hyperscaler 3/4 → AiEGIS 4/4 on Trav's fingerprint invariants.
    if substrate_attestation is not None:
        proof["substrateAttestation"] = substrate_attestation
    payload["proof"] = proof
    return payload


class VerifyFailReason(str, Enum):
    OK = "ok"
    MISSING_PROOF = "missing_proof"
    MISSING_PROOF_VALUE = "missing_proof_value"
    INVALID_PROOF_HEX = "invalid_proof_hex"
    INVALID_KEY_FORMAT = "invalid_key_format"
    CANONICALIZATION_FAILED = "canonicalization_failed"
    SIGNATURE_INVALID = "signature_invalid"


@dataclass(frozen=True)
class VerificationResult:
    """Field-level diagnosis of a bundle verification.

    Shape parity with Nel's substrate verifiers (TpmQuote / AppleSeAssertion /
    TeeAttestation / BindingProof): per-check booleans + failure_reasons tuple.
    Regulator audit log gets identical field structure across all 5 verifiers.

    __bool__ preserves backwards-compat: `if verify_bundle(...)` still works
    against callers that expected a bare bool.
    """
    valid: bool
    proof_present: bool
    proof_value_present: bool
    proof_hex_valid: bool
    key_format_valid: bool
    canonicalization_ok: bool
    signature_valid: bool
    failure_reasons: Tuple[VerifyFailReason, ...] = field(default_factory=tuple)
    details: str = ""

    def __bool__(self) -> bool:
        return self.valid


def verify_bundle(bundle: dict, operator_pub: bytes) -> VerificationResult:
    """Verify a bundle's signature.

    Strips the 'proof' field, recomputes canonical bytes, verifies signature
    against the operator public key.

    Returns a VerificationResult dataclass; truthy iff signature valid. Caller
    can inspect failure_reasons + per-check booleans for audit-log diagnosis.
    Narrow exception catching: only InvalidKeyFormat (raised by cryptography
    on bad pubkey length) + ValueError (bad hex) are caught — unexpected
    exceptions bubble so callers see real bugs instead of masked-as-False.
    """
    reasons: list = []

    if "proof" not in bundle:
        reasons.append(VerifyFailReason.MISSING_PROOF)
        return VerificationResult(
            valid=False, proof_present=False, proof_value_present=False,
            proof_hex_valid=False, key_format_valid=False,
            canonicalization_ok=False, signature_valid=False,
            failure_reasons=tuple(reasons),
            details="bundle has no 'proof' field",
        )

    proof = bundle["proof"]
    sig_hex = proof.get("proofValue")
    if not sig_hex:
        reasons.append(VerifyFailReason.MISSING_PROOF_VALUE)
        return VerificationResult(
            valid=False, proof_present=True, proof_value_present=False,
            proof_hex_valid=False, key_format_valid=False,
            canonicalization_ok=False, signature_valid=False,
            failure_reasons=tuple(reasons),
            details="proof.proofValue missing or empty",
        )

    # details strings are customer-facing audit-log output. Never interpolate
    # raw exception messages — they can leak filesystem paths, hex of bad
    # input, library-internal pointer addresses, or stack traces. Use the
    # exception class name only — type-not-content. (Nel red-team HIGH 20:44)
    # DoS guard: cap proofValue hex length before parse. ml-dsa-65 hybrid
    # needs ~6586 hex chars; 16KB is generous.
    if len(sig_hex) > MAX_PROOF_VALUE_HEX_LEN:
        reasons.append(VerifyFailReason.INVALID_PROOF_HEX)
        return VerificationResult(
            valid=False, proof_present=True, proof_value_present=True,
            proof_hex_valid=False, key_format_valid=False,
            canonicalization_ok=False, signature_valid=False,
            failure_reasons=tuple(reasons),
            details=f"proofValue too long: {len(sig_hex)} > MAX_PROOF_VALUE_HEX_LEN={MAX_PROOF_VALUE_HEX_LEN}",
        )

    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError as e:
        reasons.append(VerifyFailReason.INVALID_PROOF_HEX)
        return VerificationResult(
            valid=False, proof_present=True, proof_value_present=True,
            proof_hex_valid=False, key_format_valid=False,
            canonicalization_ok=False, signature_valid=False,
            failure_reasons=tuple(reasons),
            details=f"proofValue not valid hex ({type(e).__name__})",
        )

    try:
        payload = {k: v for k, v in bundle.items() if k != "proof"}
        canonical = _crypto.canonicalize(payload)
    except (TypeError, ValueError) as e:
        reasons.append(VerifyFailReason.CANONICALIZATION_FAILED)
        return VerificationResult(
            valid=False, proof_present=True, proof_value_present=True,
            proof_hex_valid=True, key_format_valid=False,
            canonicalization_ok=False, signature_valid=False,
            failure_reasons=tuple(reasons),
            details=f"payload canonicalization failed ({type(e).__name__})",
        )

    # _crypto.verify catches InvalidSignature internally → returns bool.
    # ValueError is raised on wrong-length pubkey by ed25519 backend.
    try:
        sig_valid = _crypto.verify(operator_pub, sig_bytes, canonical)
    except (ValueError, TypeError, IdentityError) as e:
        reasons.append(VerifyFailReason.INVALID_KEY_FORMAT)
        return VerificationResult(
            valid=False, proof_present=True, proof_value_present=True,
            proof_hex_valid=True, key_format_valid=False,
            canonicalization_ok=True, signature_valid=False,
            failure_reasons=tuple(reasons),
            details=f"operator_pub key format invalid ({type(e).__name__})",
        )

    if not sig_valid:
        reasons.append(VerifyFailReason.SIGNATURE_INVALID)
        return VerificationResult(
            valid=False, proof_present=True, proof_value_present=True,
            proof_hex_valid=True, key_format_valid=True,
            canonicalization_ok=True, signature_valid=False,
            failure_reasons=tuple(reasons),
            details="Ed25519 signature did not verify against payload + operator_pub",
        )

    return VerificationResult(
        valid=True, proof_present=True, proof_value_present=True,
        proof_hex_valid=True, key_format_valid=True,
        canonicalization_ok=True, signature_valid=True,
        failure_reasons=(VerifyFailReason.OK,),
        details="",
    )


def demo() -> None:
    """End-to-end demo + roundtrip test."""
    # Generate a fake operator keypair
    operator_priv, operator_pub = _crypto.generate_keypair(seed=bytes(32))
    operator_did = _crypto.derive_did(operator_pub, namespace="operator")
    customer_did = "did:aiegis:customer:z6MkExample"

    # Mock 3 beacon events
    events = [
        BeaconEvent(
            event_id=f"evt-{i}",
            decision=["block", "warn", "block"][i],
            rule=["pi.ignore_previous", "pii.email", "secret.openai_key"][i],
            timestamp=datetime.now(timezone.utc).isoformat(),
            customer_did=customer_did,
            classifier_hits=[{"rule": "...", "score": 0.95, "snippet_offsets": None}],
        )
        for i in range(3)
    ]

    # Fake policy bundle hashes
    policy_bundle = {
        "rulesRsSha256": "a" * 64,
        "libRsSha256":   "b" * 64,
    }

    bundle = build_bundle(
        events=events,
        operator_priv=operator_priv,
        operator_did=operator_did,
        customer_did=customer_did,
        valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
        valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
        classifier_version="0.6.6",
        policy_bundle=policy_bundle,
    )

    assert verify_bundle(bundle, operator_pub), "verify failed"
    print(json.dumps(bundle, indent=2, sort_keys=True))
    print(f"\n# verified: True", file=sys.stderr)
    print(f"# operator: {operator_did}", file=sys.stderr)
    print(f"# events: {len(events)} ({bundle['credentialSubject']['decisionBreakdown']})", file=sys.stderr)


if __name__ == "__main__":
    demo()
