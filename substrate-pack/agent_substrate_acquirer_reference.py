"""
AiEGIS Agent-Side Substrate Acquirer — reference implementation.

Authored: 2026-05-10 ~19:54 IST per Trav cadence directive.
Composes with HOST_SUBSTRATE_FINGERPRINT_BINDING_SPEC_V01.md (sha aa2fd76c).

This is the AGENT-side counterpart to the operator-side verifiers
(tpm_quote_verifier_reference.py, apple_se_assertion_verifier_reference.py,
tee_attestation_verifier_reference.py).

Flow:
  1. Detect available substrate (TPM 2.0 | Apple SE | Intel TDX | AMD SEV-SNP).
  2. Acquire host attestation from that substrate (TPM quote, App Attest
     assertion, TD-Report, or SNP-Report).
  3. Build the substrateAttestation dict matching Velo's pass-through shape.
  4. Hand the dict to Velo's compliance-bundle generator (or compatible)
     for inclusion in the regulator-handed bundle.

Production: each Lane's _acquire_* function shells to the canonical user-space
tool (tpm2_quote, swiftpm App Attest, tdx-attest, snphost). This reference
documents the shape + provides a graceful "no substrate detected" fallback so
the agent stays operational on hosts without confidential-compute hardware
(e.g. nel-Air, dev laptops without TPM).

Non-goals:
  - PCR-policy enforcement (operator-side concern)
  - Cross-substrate migration (logical-agent stays consistent across hosts)
  - Substrate-attestation revocation (operator concern)
"""

from __future__ import annotations

import hashlib
import os
import platform
import struct
from dataclasses import dataclass
from typing import Literal

from substrate_errors import SubstrateError, ErrorCode


SubstrateKind = Literal[
    "TpmSubstrate",
    "AppleSeSubstrate",
    "TeeSubstrate",
    "None",
]


_VALID_SUBSTRATE_KINDS = frozenset({
    "TpmSubstrate", "AppleSeSubstrate", "TeeSubstrate", "None",
})


@dataclass(frozen=True)
class DetectedSubstrate:
    """Result of substrate detection on the current host."""

    kind: SubstrateKind
    vendor: str | None  # "intel-tdx" | "amd-sev-snp" | None for non-TEE substrates
    reason: str  # Human-readable explanation

    def __post_init__(self) -> None:
        if self.kind not in _VALID_SUBSTRATE_KINDS:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail=f"DetectedSubstrate.kind must be one of {sorted(_VALID_SUBSTRATE_KINDS)}, got {self.kind!r}",
            )
        # vendor is None for non-TEE substrates; for TeeSubstrate it must
        # be one of the supported vendors (mirror SUPPORTED_TEE_VENDORS).
        if self.kind == "TeeSubstrate":
            if self.vendor not in {"intel-tdx", "amd-sev-snp"}:
                raise SubstrateError(
                    ErrorCode.TEE_VENDOR_UNSUPPORTED,
                    detail=f"DetectedSubstrate.vendor must be 'intel-tdx' or 'amd-sev-snp' when kind=TeeSubstrate, got {self.vendor!r}",
                )
        elif self.vendor is not None:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail=f"DetectedSubstrate.vendor must be None when kind={self.kind!r}, got {self.vendor!r}",
            )


def detect_substrate() -> DetectedSubstrate:
    """
    Detect the host's available attestation substrate.

    Priority order: native hardware > confidential-VM > none.
    """
    system = platform.system()

    if system == "Darwin":
        # Apple Silicon has Secure Enclave on every M1+ chip. App Attest
        # requires being a registered app — agent code would need iOS/macOS
        # SDK access. This reference detects the substrate availability;
        # actual acquisition requires Swift/ObjC.
        if platform.machine().startswith(("arm64", "M1", "M2")):
            return DetectedSubstrate(
                kind="AppleSeSubstrate",
                vendor=None,
                reason="Apple Silicon detected; Secure Enclave available",
            )
        # Intel Macs 2017-2020 have T2 chip with SE-equivalent.
        return DetectedSubstrate(
            kind="None",
            vendor=None,
            reason=f"Darwin on {platform.machine()} — T2 path not implemented in reference",
        )

    if system == "Linux":
        # TPM 2.0 detection: /dev/tpm0 exists on most modern Linux hosts.
        if os.path.exists("/dev/tpm0") or os.path.exists("/dev/tpmrm0"):
            return DetectedSubstrate(
                kind="TpmSubstrate",
                vendor=None,
                reason="Linux /dev/tpm0 or /dev/tpmrm0 present",
            )
        # TEE detection: check for /sys/kernel/mm/tdx_guest (Intel TDX)
        # or /dev/sev-guest (AMD SEV-SNP).
        if os.path.exists("/sys/kernel/mm/tdx_guest"):
            return DetectedSubstrate(
                kind="TeeSubstrate",
                vendor="intel-tdx",
                reason="Intel TDX guest detected via /sys/kernel/mm/tdx_guest",
            )
        if os.path.exists("/dev/sev-guest"):
            return DetectedSubstrate(
                kind="TeeSubstrate",
                vendor="amd-sev-snp",
                reason="AMD SEV-SNP guest detected via /dev/sev-guest",
            )
        return DetectedSubstrate(
            kind="None",
            vendor=None,
            reason="Linux without TPM 2.0, Intel TDX, or AMD SEV-SNP",
        )

    if system == "Windows":
        # Windows 11 mandates TPM 2.0. Detection via TBS (TPM Base Services).
        # Reference doesn't shell to Windows API; flag as PROBABLY-TPM.
        return DetectedSubstrate(
            kind="TpmSubstrate",
            vendor=None,
            reason="Windows detected; assume TPM 2.0 (Win11 mandate). Verify via TBS API in prod.",
        )

    return DetectedSubstrate(
        kind="None",
        vendor=None,
        reason=f"Unsupported platform.system(): {system}",
    )


def _acquire_tpm_quote_stub(nonce: bytes, agent_pubkey: bytes) -> dict:
    """
    Produce a stub TPM substrate-attestation matching Velo's pass-through
    shape. Production swaps this for `tpm2_quote -c <aik> -l sha256:10 -q
    <nonce>` shelled via subprocess + parsing tpm2-pytss output.

    The stub emits well-formed-but-synthetic bytes; the operator-side
    verifier will FAIL hard-checks (signature, cert chain) which is
    correct behavior on a host without a real TPM.
    """
    pcr_digest = hashlib.sha256(b"aiegis-agent-binary-placeholder").digest()
    # Mirror the TPMS_ATTEST stub layout used in the verifier tests.
    magic = b"\xff\x54\x43\x47"
    body = b"\x80\x18" + b"\x00" * 6 + nonce
    middle = b"\x00" * 12
    tpms_attest = magic + body + middle + pcr_digest
    return {
        "substrate": "TpmSubstrate",
        "ekCertSha256": hashlib.sha256(b"stub-ek-cert").hexdigest(),
        "aikQuote": tpms_attest.hex(),
        "pcr0Sha256": pcr_digest.hex(),
        "bindingProofSig": "0" * 128,  # operator signs in real impl
    }


def _acquire_apple_se_assertion_stub(nonce: bytes, agent_pubkey: bytes) -> dict:
    """
    Stub Apple SE substrate-attestation. Production swaps for Swift code
    calling DCAppAttestService.generateAssertion(challenge:keyId:).
    """
    import base64
    import json

    rp_id_hash = hashlib.sha256(b"aiegis.ie").digest()
    flags = b"\x00"
    sign_count = struct.pack(">I", 1)
    auth_data = rp_id_hash + flags + sign_count
    challenge_b64 = base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
    client_data = json.dumps(
        {"type": "webauthn.get", "challenge": challenge_b64, "origin": "https://aiegis.ie"}
    ).encode("utf-8")
    return {
        "substrate": "AppleSeSubstrate",
        "attestedPubkeyDer": agent_pubkey.hex(),
        "authenticatorData": auth_data.hex(),
        "signature": "0" * 128,  # SE signs in real impl
        "clientDataJson": client_data.hex(),
    }


def _acquire_tee_report_stub(
    nonce: bytes, agent_pubkey: bytes, vendor: str
) -> dict:
    """
    Stub TEE substrate-attestation. Production swaps for tdx-attest CLI
    (Intel) or snphost (AMD).
    """
    measurement = hashlib.sha384(b"aiegis-confidential-vm-measurement").digest()
    if vendor == "intel-tdx":
        report = bytearray(1024)
        report[608:656] = measurement
        report[816:848] = nonce
        report[848:880] = hashlib.sha256(agent_pubkey).digest()
        return {
            "substrate": "TeeSubstrate",
            "vendor": "IntelTdx",
            "tdReport": bytes(report).hex(),
            "signatureChain": "30820010",
            "vmMeasurement": measurement.hex(),
        }
    if vendor == "amd-sev-snp":
        report = bytearray(1184)
        report[:4] = struct.pack("<I", 2)
        report[80:112] = nonce
        report[112:144] = hashlib.sha256(agent_pubkey).digest()
        report[144:192] = measurement
        return {
            "substrate": "TeeSubstrate",
            "vendor": "AmdSevSnp",
            "snpReport": bytes(report).hex(),
            "signatureChain": "30820020",
            "vmMeasurement": measurement.hex(),
        }
    raise SubstrateError(
        ErrorCode.TEE_VENDOR_UNSUPPORTED,
        detail=f"Unsupported TEE vendor: {vendor}",
    )


def acquire_substrate_attestation(
    nonce: bytes, agent_pubkey: bytes, *, allow_none: bool = False
) -> dict | None:
    """
    Top-level agent-side acquirer. Detects substrate + acquires attestation.

    Args:
        nonce: operator-provided 32-byte challenge.
        agent_pubkey: agent's pubkey (bytes; impl decides DER vs raw).
        allow_none: if True, return None instead of raising when no
            substrate detected. Default False — agent SHOULD fail-closed
            on hosts without attestation hardware (regulator-handed bundle
            without substrate is suspect).

    Returns:
        substrateAttestation dict matching Velo's pass-through shape, or
        None if substrate is "None" and allow_none=True.
    """
    # Boundary type checks — fail loud at the boundary instead of deep in
    # a substrate-specific stub. str-nonce previously slipped past the
    # len() check (str length == bytes length when ASCII) and only crashed
    # accidentally inside base64.urlsafe_b64encode in the Apple branch.
    if not isinstance(nonce, (bytes, bytearray)):
        raise TypeError(
            f"nonce must be bytes, got {type(nonce).__name__}"
        )
    if len(nonce) != 32:
        raise SubstrateError(
            ErrorCode.SHAPE_INVALID,
            detail=f"nonce must be 32 bytes, got {len(nonce)}",
        )
    if not isinstance(agent_pubkey, (bytes, bytearray)):
        raise TypeError(
            f"agent_pubkey must be bytes, got {type(agent_pubkey).__name__}"
        )
    if len(agent_pubkey) == 0:
        raise SubstrateError(
            ErrorCode.SHAPE_INVALID,
            detail="agent_pubkey must be non-empty",
        )
    # Cap pubkey size — Ed25519 raw=32B, X25519 raw=32B, RSA-4096 DER ~550B,
    # generous 4KB cap blocks DoS via 10MB pubkey blob in attestation dict.
    _MAX_PUBKEY_BYTES = 4 * 1024
    if len(agent_pubkey) > _MAX_PUBKEY_BYTES:
        raise SubstrateError(
            ErrorCode.LENGTH_CAP_EXCEEDED,
            detail=f"agent_pubkey must be <={_MAX_PUBKEY_BYTES}B (DoS guard; got {len(agent_pubkey)}B)",
        )
    detection = detect_substrate()
    if detection.kind == "TpmSubstrate":
        return _acquire_tpm_quote_stub(nonce, agent_pubkey)
    if detection.kind == "AppleSeSubstrate":
        return _acquire_apple_se_assertion_stub(nonce, agent_pubkey)
    if detection.kind == "TeeSubstrate":
        assert detection.vendor is not None
        return _acquire_tee_report_stub(nonce, agent_pubkey, detection.vendor)
    if detection.kind == "None":
        if allow_none:
            return None
        raise RuntimeError(
            f"No substrate detected ({detection.reason}). Agent must run on "
            "TPM 2.0 / Apple Secure Enclave / Intel TDX / AMD SEV-SNP host for "
            "regulator-grade compliance bundles. Use allow_none=True to bypass "
            "for dev/test ONLY."
        )
    raise RuntimeError(f"Unexpected detection kind: {detection.kind}")


__all__ = [
    "DetectedSubstrate",
    "detect_substrate",
    "acquire_substrate_attestation",
]
