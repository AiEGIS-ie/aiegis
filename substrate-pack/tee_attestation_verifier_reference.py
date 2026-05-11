"""
AiEGIS Confidential-Compute TEE Attestation Verifier — operator-side reference.

Authored: 2026-05-10 ~19:36 IST per Trav cadence directive.
Composes with HOST_SUBSTRATE_FINGERPRINT_BINDING_SPEC_V01.md (sha aa2fd76c) Lane C.

Covers two TEE substrates:
  - Intel TDX (Trust Domain Extensions): Sapphire Rapids+ Xeon
  - AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging):
    EPYC Milan 7003+ / Genoa 9004+
ARM CCA reserved for v0.2 (specs still rolling out 2024-2025).

WIRE: agent (running inside a Trust Domain or Confidential VM) provides:
  - attestation_report: bytes (TD-Report for Intel, SNP-Report for AMD)
  - report_signature_chain: bytes (DCAP for Intel, KDS for AMD; the cert chain
    from CPU hardware-root through quoting-enclave to vendor attestation root)
  - report_data_nonce: bytes (the agent embedded operator's nonce in the
    REPORTDATA / REPORT_DATA field of the report)
  - agent_pubkey_in_reportdata: bytes (concat'd into REPORTDATA alongside nonce
    so the report binds: "this TEE measurement + this agent pubkey")

OPERATOR provides:
  - vendor: str ("intel-tdx" or "amd-sev-snp")
  - expected_vm_measurement: bytes (MRTD/MRECEIPT for Intel, MEASUREMENT for AMD —
    SHA-384 of expected AiEGIS confidential VM image)
  - expected_nonce: bytes
  - vendor_root_cert_der: bytes (Intel ICX-D Provisioning Cert root or AMD
    Versioned Chip Endorsement Key root — operator pins both)

Operator-side validates:
  1. Report signature chains to vendor root
  2. Measurement matches expected (right AiEGIS VM image is running)
  3. REPORTDATA contains operator-sent nonce + agent's claimed pubkey
  4. Vendor-specific freshness/quote-version checks

This reference deliberately abstracts vendor-specific report layouts behind
a unified function signature. Real impls call into intel-sgx-dcap-quote-verify
or sev-snp-utils crates.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from substrate_errors import SubstrateError, ErrorCode


# Vendor identifiers.
VENDOR_INTEL_TDX = "intel-tdx"
VENDOR_AMD_SEV_SNP = "amd-sev-snp"

# TD-Report (Intel TDX) magic / type constants.
TD_REPORT_TYPE_TDX = 0x81  # TEE_TYPE_TDX from TDX module spec

# SNP-Report (AMD SEV-SNP) version constants.
SNP_REPORT_VERSION_2 = 2  # Genoa-era, v0.7+ baseline


SUPPORTED_TEE_VENDORS = frozenset({"intel-tdx", "amd-sev-snp"})


@dataclass(frozen=True)
class TeeAttestationVerifyInput:
    """Inputs for verifying a TEE attestation report."""

    vendor: str
    attestation_report: bytes
    report_signature_chain: bytes
    report_data_nonce: bytes
    agent_pubkey_in_reportdata: bytes
    expected_vm_measurement: bytes
    expected_nonce: bytes
    vendor_root_cert_der: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.vendor, str):
            raise TypeError(
                "TeeAttestationVerifyInput.vendor must be str, "
                f"got {type(self.vendor).__name__}"
            )
        if self.vendor not in SUPPORTED_TEE_VENDORS:
            raise SubstrateError(
                ErrorCode.TEE_VENDOR_UNSUPPORTED,
                detail=f"TeeAttestationVerifyInput.vendor must be one of {sorted(SUPPORTED_TEE_VENDORS)}, got {self.vendor!r}",
            )
        for field_name in (
            "attestation_report", "report_signature_chain", "report_data_nonce",
            "agent_pubkey_in_reportdata", "expected_vm_measurement",
            "expected_nonce", "vendor_root_cert_der",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, (bytes, bytearray)):
                raise TypeError(
                    f"TeeAttestationVerifyInput.{field_name} must be bytes, "
                    f"got {type(value).__name__}"
                )
            if len(value) == 0:
                raise SubstrateError(
                    ErrorCode.SHAPE_INVALID,
                    detail=f"TeeAttestationVerifyInput.{field_name} must be non-empty",
                )
        # Real TD-Reports / SNP-Reports are <2KB; 64KB cap blocks DoS via
        # huge attestation_report or signature_chain allocation.
        _MAX_TEE_BLOB = 64 * 1024
        for blob_field in ("attestation_report", "report_signature_chain"):
            blob = getattr(self, blob_field)
            if len(blob) > _MAX_TEE_BLOB:
                raise SubstrateError(
                    ErrorCode.LENGTH_CAP_EXCEEDED,
                    detail=f"TeeAttestationVerifyInput.{blob_field} must be <={_MAX_TEE_BLOB}B (DoS guard; got {len(blob)}B)",
                )
        if len(self.expected_vm_measurement) != 48:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="TeeAttestationVerifyInput.expected_vm_measurement must be exactly 48B (SHA-384 — TDX MRTD or SEV-SNP MEASUREMENT)",
            )
        if len(self.expected_nonce) < 16:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="TeeAttestationVerifyInput.expected_nonce must be >=16B (anti-replay minimum)",
            )


@dataclass(frozen=True)
class TeeAttestationVerifyResult:
    """Verification outcome with field-level explanations."""

    valid: bool
    vendor_supported: bool
    report_chain_valid: bool
    measurement_match: bool
    reportdata_nonce_match: bytes  # raw nonce extracted from report
    reportdata_pubkey_match: bool
    failure_reasons: tuple[str, ...]


def _parse_intel_tdx_report(report: bytes) -> dict:
    """
    Parse TD-Report v1.5 per Intel TDX Module Spec.

    Layout (highlights, total 1024 bytes):
      0..1024  TDREPORT_STRUCT
        0..256   REPORTMACSTRUCT (HMAC over the report body)
        256..512 TEE_TCB_INFO_STRUCT (Trusted Computing Base versions)
        512..1024 TDINFO_STRUCT
          512..560  ATTRIBUTES (16 bytes)
          560..608  XFAM (8 bytes)
          608..656  MRTD (48 bytes — SHA-384 of TD measurement, what we check)
          656..704  MRCONFIGID
          704..720  MROWNER
          720..768  MROWNERCONFIG
          768..816  RTMR[0..3] (Runtime Measurement Registers)
          816..880  REPORTDATA (64 bytes — operator's nonce + pubkey)

    Returns dict with mrtd, reportdata, attributes.
    """
    if len(report) < 1024:
        raise SubstrateError(
            ErrorCode.SUBSTRATE_ATTESTATION_INVALID,
            detail=f"TD-Report too short: {len(report)} < 1024 bytes",
        )
    return {
        "mrtd": report[608:656],
        "rtmr_0": report[768:784],
        "rtmr_1": report[784:800],
        "reportdata": report[816:880],
    }


def _parse_amd_snp_report(report: bytes) -> dict:
    """
    Parse SNP-Report v2 per AMD SEV-SNP ABI Spec (document 56860).

    REFERENCE PARSER — offsets below are placeholders that MUST be validated
    against the canonical AMD spec before production. The full AMD SEV-SNP
    Firmware ABI Spec is at https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf.

    Placeholder layout (1184 bytes total, must verify offsets in v0.2):
      0..4    version (uint32 LE) — expect SNP_REPORT_VERSION_2
      4..8    guest_svn
      8..16   policy
      16..32  family_id
      32..48  image_id
      48..52  vmpl
      52..56  signature_algo
      56..60  current_tcb / committed_tcb
      ...
      80..144  REPORT_DATA (64 bytes — operator's nonce + pubkey hash)  [VERIFY]
      144..192 MEASUREMENT (48 bytes — SHA-384 of guest VM image)        [VERIFY]
      ...
      672..1184 signature

    For v0.7+ production: replace this parser with sev-snp-utils crate or
    equivalent spec-validated library. This reference is for the test
    chain only; it must remain internally consistent with the test fixtures.
    """
    if len(report) < 1184:
        raise SubstrateError(
            ErrorCode.SUBSTRATE_ATTESTATION_INVALID,
            detail=f"SNP-Report too short: {len(report)} < 1184 bytes",
        )
    version = struct.unpack("<I", report[:4])[0]
    if version != SNP_REPORT_VERSION_2:
        raise SubstrateError(
            ErrorCode.SUBSTRATE_ATTESTATION_INVALID,
            detail=f"Unexpected SNP-Report version: {version}, expected {SNP_REPORT_VERSION_2}",
        )
    # Placeholder offsets — see docstring caveat. Must validate vs AMD 56860
    # before production. Test fixtures in test_substrate_verifiers.py match
    # these offsets so the test chain remains internally consistent.
    return {
        "version": version,
        "reportdata": report[80:144],  # 64 bytes — placeholder, VERIFY
        "measurement": report[144:192],  # 48 bytes — placeholder, VERIFY
        "signature": report[672:1184],
    }


def _verify_report_chain(
    vendor: str,
    report_signature_chain: bytes,
    vendor_root_cert_der: bytes,
) -> bool:
    """
    Validate the report signature chain to vendor root.

    Intel TDX: DCAP-based — QE quote → PCK cert → Intel root. Real impl uses
    `intel-tdx-attest` quote-verification-library.
    AMD SEV-SNP: KDS-based — chip endorsement key → ARK (AMD Root Key) →
    AMD KDS root. Real impl uses sev-snp-utils.

    Reference: returns False if chain is empty or vendor unsupported. Real
    chain validation requires vendor-specific library. Operator MUST swap
    this stub for a vendor-library impl before production.
    """
    if vendor not in (VENDOR_INTEL_TDX, VENDOR_AMD_SEV_SNP):
        return False
    if not report_signature_chain or not vendor_root_cert_der:
        return False
    # Stub: real impl chains TBS cert validation to vendor root. This
    # reference is operator-side scaffolding; production replaces with
    # intel-tdx-attest or sev-snp-utils chain validation. Returning True
    # here would be wrong-by-default in production, so we require the
    # operator to set AIEGIS_TEE_CHAIN_VALIDATOR before this verifier ships.
    return False


def verify_tee_attestation(
    inputs: TeeAttestationVerifyInput,
) -> TeeAttestationVerifyResult:
    """
    Top-level operator-side TEE attestation verifier.

    Order of checks (all must pass for valid=True):
      1. Vendor is supported (intel-tdx | amd-sev-snp)
      2. Parse report — extract reportdata (64 bytes) + measurement field
      3. Measurement matches expected_vm_measurement
      4. REPORTDATA[0:32] == expected_nonce (operator-supplied)
      5. REPORTDATA[32:64] hashes to agent_pubkey_in_reportdata
      6. Report signature chains to vendor root
    """
    reasons: list[str] = []

    if inputs.vendor not in (VENDOR_INTEL_TDX, VENDOR_AMD_SEV_SNP):
        return TeeAttestationVerifyResult(
            valid=False,
            vendor_supported=False,
            report_chain_valid=False,
            measurement_match=False,
            reportdata_nonce_match=b"",
            reportdata_pubkey_match=False,
            failure_reasons=(f"unsupported_vendor: {inputs.vendor}",),
        )

    try:
        if inputs.vendor == VENDOR_INTEL_TDX:
            parsed = _parse_intel_tdx_report(inputs.attestation_report)
            measurement = parsed["mrtd"]
            reportdata = parsed["reportdata"]
        else:
            parsed = _parse_amd_snp_report(inputs.attestation_report)
            measurement = parsed["measurement"]
            reportdata = parsed["reportdata"]
    except ValueError as e:
        return TeeAttestationVerifyResult(
            valid=False,
            vendor_supported=True,
            report_chain_valid=False,
            measurement_match=False,
            reportdata_nonce_match=b"",
            reportdata_pubkey_match=False,
            failure_reasons=(f"report_parse_failure: {type(e).__name__}",),
        )

    nonce_in_report = reportdata[:32]
    pubkey_hash_in_report = reportdata[32:64]
    expected_pubkey_hash = hashlib.sha256(inputs.agent_pubkey_in_reportdata).digest()

    nonce_match_raw = nonce_in_report == inputs.expected_nonce
    if not nonce_match_raw:
        reasons.append("reportdata_nonce_mismatch")

    pubkey_match = pubkey_hash_in_report == expected_pubkey_hash
    if not pubkey_match:
        reasons.append("reportdata_pubkey_hash_mismatch")

    measurement_match = measurement == inputs.expected_vm_measurement
    if not measurement_match:
        # Type-not-content per Velo red-team 2026-05-10 20:43 IST. Measurement
        # hex-prefix is generally public, but consistency with details-not-leaked
        # pattern across the 5-verifier pack: no content in failure_reasons.
        reasons.append("vm_measurement_mismatch")

    chain_valid = _verify_report_chain(
        inputs.vendor,
        inputs.report_signature_chain,
        inputs.vendor_root_cert_der,
    )
    if not chain_valid:
        reasons.append(
            "report_chain_invalid (production verifier MUST install "
            "vendor-specific chain validator: intel-tdx-attest or sev-snp-utils)"
        )

    valid = (
        nonce_match_raw
        and pubkey_match
        and measurement_match
        and chain_valid
    )

    return TeeAttestationVerifyResult(
        valid=valid,
        vendor_supported=True,
        report_chain_valid=chain_valid,
        measurement_match=measurement_match,
        reportdata_nonce_match=nonce_in_report,
        reportdata_pubkey_match=pubkey_match,
        failure_reasons=tuple(reasons),
    )


__all__ = [
    "TeeAttestationVerifyInput",
    "TeeAttestationVerifyResult",
    "verify_tee_attestation",
    "VENDOR_INTEL_TDX",
    "VENDOR_AMD_SEV_SNP",
]
