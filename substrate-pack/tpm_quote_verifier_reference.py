"""
AiEGIS TPM 2.0 Quote Verifier — operator-side reference implementation.

Authored: 2026-05-10 ~19:33 IST per Trav directive "no waiting for tomorrow keep going".
Composes with HOST_SUBSTRATE_FINGERPRINT_BINDING_SPEC_V01.md (sha aa2fd76c) Lane A.

This is the OPERATOR-side verifier. It consumes a TPM Quote produced by an
agent's TPM 2.0 chip and validates the chain:
  TPM_QUOTE_INFO (signed by AIK) → AIK cert (signed by EK) → EK cert (signed by TPM vendor root)

No actual TPM hardware needed to run this verifier — that's the whole point.
The agent has the TPM; the operator has cryptography + vendor root CAs.

WIRE: agent provides:
  - tpm_quote_info: bytes (TPMS_ATTEST struct per TCG spec, contains PCR digest + nonce)
  - signature: bytes (AIK signature over tpm_quote_info)
  - aik_cert: bytes (X.509 cert binding AIK pubkey to EK)
  - ek_cert: bytes (X.509 cert from TPM manufacturer, EK pubkey)

OPERATOR provides:
  - expected_nonce: bytes (the challenge the operator sent)
  - expected_pcr_digest: bytes (the policy-required PCR-10 value for aiegis-agent binary)
  - vendor_root_ca: bytes (Infineon / STMicro / Intel root cert, pinned)
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from substrate_errors import SubstrateError, ErrorCode


# TCG-allocated AiEGIS PCR slot — see open-q 1 in spec. PCR-10 is commonly
# free for application-specific measurements; TCG-allocated would be safer.
AIEGIS_PCR_SLOT = 10


@dataclass(frozen=True)
class TpmQuoteVerifyInput:
    """Bundle the inputs needed to verify a single TPM quote."""

    tpm_quote_info: bytes
    signature: bytes
    aik_cert_der: bytes
    ek_cert_der: bytes
    expected_nonce: bytes
    expected_pcr_digest: bytes
    vendor_root_ca_der: bytes

    def __post_init__(self) -> None:
        for field_name in (
            "tpm_quote_info", "signature", "aik_cert_der", "ek_cert_der",
            "expected_nonce", "expected_pcr_digest", "vendor_root_ca_der",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, (bytes, bytearray)):
                raise TypeError(
                    f"TpmQuoteVerifyInput.{field_name} must be bytes, "
                    f"got {type(value).__name__}"
                )
            if len(value) == 0:
                raise SubstrateError(
                    ErrorCode.SHAPE_INVALID,
                    detail=f"TpmQuoteVerifyInput.{field_name} must be non-empty",
                )
        if len(self.tpm_quote_info) < 32:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="TpmQuoteVerifyInput.tpm_quote_info must be >=32B (TPMS_ATTEST minimum per TCG spec)",
            )
        # Real TPMS_ATTEST is hundreds of bytes; 64KB cap blocks DoS via
        # huge-buffer allocation without hindering valid attestations.
        _MAX_TPMS_ATTEST = 64 * 1024
        if len(self.tpm_quote_info) > _MAX_TPMS_ATTEST:
            raise SubstrateError(
                ErrorCode.LENGTH_CAP_EXCEEDED,
                detail=f"TpmQuoteVerifyInput.tpm_quote_info must be <={_MAX_TPMS_ATTEST}B (DoS guard; got {len(self.tpm_quote_info)}B)",
            )
        if len(self.expected_pcr_digest) != 32:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="TpmQuoteVerifyInput.expected_pcr_digest must be exactly 32B (SHA-256 digest)",
            )
        if len(self.expected_nonce) < 16:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="TpmQuoteVerifyInput.expected_nonce must be >=16B (TCG anti-replay minimum)",
            )


@dataclass(frozen=True)
class TpmQuoteVerifyResult:
    """Verification outcome with field-level explanations."""

    valid: bool
    nonce_match: bool
    pcr_digest_match: bool
    aik_signature_valid: bool
    aik_cert_chains_to_ek: bool
    ek_cert_chains_to_vendor: bool
    failure_reasons: tuple[str, ...]


def _parse_tpms_attest(tpm_quote_info: bytes) -> tuple[bytes, bytes]:
    """
    Parse TPMS_ATTEST per TCG TPM 2.0 Structures spec §10.12.8.

    Returns (extra_data_nonce, pcr_digest). Real impl needs full TPMS_ATTEST
    parsing; this reference returns the two fields verifiers care about:
    extraData (nonce we sent) and pcr digest (over selected PCRs).

    Layout (simplified):
      4B  magic (0xFF544347 'TCG')
      2B  type (0x8018 for ATTEST_QUOTE)
      2B  qualifiedSigner.size + N bytes
      2B  extraData.size + N bytes nonce
      ... (clockInfo, firmwareVersion)
      ... TPMS_QUOTE_INFO with pcrSelect + pcrDigest

    For this reference: expect canonical-form bytes with extraData at known offset.
    Production impl: use python-tpm2-pytss or implement full BER-style walker.
    """
    if len(tpm_quote_info) < 32:
        raise SubstrateError(
            ErrorCode.SUBSTRATE_ATTESTATION_INVALID,
            detail="tpm_quote_info too short to be valid TPMS_ATTEST",
        )
    magic = tpm_quote_info[:4]
    if magic != b"\xff\x54\x43\x47":  # 0xFF544347
        raise SubstrateError(
            ErrorCode.SUBSTRATE_ATTESTATION_INVALID,
            detail=f"Invalid TPMS_ATTEST magic: {magic.hex()}",
        )

    # Reference impl: assume canonical 32-byte nonce at offset 12,
    # 32-byte SHA-256 pcr digest at offset 44 + structure overhead.
    # Real impl walks TLV per TCG spec. This is a placeholder for the
    # integration contract — Velo's generator will provide REAL fixtures
    # when it gets the substrate-extension treatment.
    extra_data_nonce = tpm_quote_info[12:44]
    pcr_digest = tpm_quote_info[-32:]
    return extra_data_nonce, pcr_digest


def _verify_aik_signature(
    tpm_quote_info: bytes,
    signature: bytes,
    aik_cert_der: bytes,
) -> bool:
    """
    Verify AIK signature over tpm_quote_info bytes.

    AIK is typically RSA-2048 or ECDSA-P256 per TCG TPM 2.0 EK Profile.
    Real impl: parse aik_cert via cryptography.x509, extract pubkey,
    verify with public_key.verify(signature, tpm_quote_info, padding, hash).

    Reference returns False on any error — operator-side fail-safe default.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

    try:
        aik_cert = x509.load_der_x509_certificate(aik_cert_der)
        pubkey = aik_cert.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey):
            pubkey.verify(
                signature,
                tpm_quote_info,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(signature, tpm_quote_info, ec.ECDSA(hashes.SHA256()))
            return True
        return False
    except (InvalidSignature, UnsupportedAlgorithm, ValueError):
        # InvalidSignature = sig mismatch, UnsupportedAlgorithm = unknown curve,
        # ValueError = malformed DER. Anything else (AttributeError, TypeError, etc.)
        # is a programmer bug — bubble up so caller sees the real issue, not False.
        return False


def _verify_cert_chain(child_cert_der: bytes, parent_cert_der: bytes) -> bool:
    """
    Verify child certificate is signed by parent.

    For AIK→EK: AIK cert's issuer must equal EK cert's subject, AIK cert
    must be signed by EK pubkey. (TPM vendors emit the EK cert; the
    operator-side ceremony binds AIK to EK at install time.)

    For EK→vendor: EK cert chains to TPM vendor root (Infineon/STMicro/Intel).
    Operator pins vendor root cert in config.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

    try:
        child = x509.load_der_x509_certificate(child_cert_der)
        parent = x509.load_der_x509_certificate(parent_cert_der)
        if child.issuer != parent.subject:
            return False
        parent_pubkey = parent.public_key()
        sig_algo = child.signature_hash_algorithm
        tbs_bytes = child.tbs_certificate_bytes
        child_sig = child.signature
        if isinstance(parent_pubkey, rsa.RSAPublicKey):
            parent_pubkey.verify(
                child_sig,
                tbs_bytes,
                padding.PKCS1v15(),
                sig_algo,
            )
            return True
        if isinstance(parent_pubkey, ec.EllipticCurvePublicKey):
            parent_pubkey.verify(child_sig, tbs_bytes, ec.ECDSA(sig_algo))
            return True
        return False
    except (InvalidSignature, UnsupportedAlgorithm, ValueError):
        # Specific catches only — programmer bugs bubble up.
        return False


def verify_tpm_quote(inputs: TpmQuoteVerifyInput) -> TpmQuoteVerifyResult:
    """
    Top-level operator-side TPM quote verifier.

    Order of checks (all must pass for valid=True):
      1. Parse TPMS_ATTEST — extract nonce + pcr digest
      2. Nonce matches what operator sent (freshness)
      3. PCR digest matches expected aiegis-agent binary measurement
      4. AIK signature over tpm_quote_info validates
      5. AIK cert chains to EK cert (binding ceremony at install time)
      6. EK cert chains to vendor root CA (manufacture-time trust)
    """
    reasons: list[str] = []

    try:
        nonce, pcr_digest = _parse_tpms_attest(inputs.tpm_quote_info)
    except ValueError as e:
        return TpmQuoteVerifyResult(
            valid=False,
            nonce_match=False,
            pcr_digest_match=False,
            aik_signature_valid=False,
            aik_cert_chains_to_ek=False,
            ek_cert_chains_to_vendor=False,
            failure_reasons=(f"parse_failure: {type(e).__name__}",),
        )

    nonce_match = nonce == inputs.expected_nonce
    if not nonce_match:
        reasons.append(
            f"nonce_mismatch (got {nonce.hex()[:16]}, expected "
            f"{inputs.expected_nonce.hex()[:16]})"
        )

    pcr_digest_match = pcr_digest == inputs.expected_pcr_digest
    if not pcr_digest_match:
        reasons.append("pcr_digest_mismatch")

    aik_sig_valid = _verify_aik_signature(
        inputs.tpm_quote_info, inputs.signature, inputs.aik_cert_der
    )
    if not aik_sig_valid:
        reasons.append("aik_signature_invalid")

    aik_to_ek = _verify_cert_chain(inputs.aik_cert_der, inputs.ek_cert_der)
    if not aik_to_ek:
        reasons.append("aik_cert_does_not_chain_to_ek")

    ek_to_vendor = _verify_cert_chain(inputs.ek_cert_der, inputs.vendor_root_ca_der)
    if not ek_to_vendor:
        reasons.append("ek_cert_does_not_chain_to_vendor_root")

    valid = (
        nonce_match
        and pcr_digest_match
        and aik_sig_valid
        and aik_to_ek
        and ek_to_vendor
    )

    return TpmQuoteVerifyResult(
        valid=valid,
        nonce_match=nonce_match,
        pcr_digest_match=pcr_digest_match,
        aik_signature_valid=aik_sig_valid,
        aik_cert_chains_to_ek=aik_to_ek,
        ek_cert_chains_to_vendor=ek_to_vendor,
        failure_reasons=tuple(reasons),
    )


def aiegis_agent_pcr_digest(binary_path: str) -> bytes:
    """
    Compute the expected PCR digest for an aiegis-agent binary.

    PCR-10 measurement is SHA-256 over the binary. Operator publishes
    this expected digest in a well-known location (e.g.
    /.well-known/aiegis-agent-pcr-policy.json) so verifiers can pin.
    """
    h = hashlib.sha256()
    with open(binary_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.digest()


__all__ = [
    "TpmQuoteVerifyInput",
    "TpmQuoteVerifyResult",
    "verify_tpm_quote",
    "aiegis_agent_pcr_digest",
    "AIEGIS_PCR_SLOT",
]
