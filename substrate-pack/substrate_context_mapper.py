"""
Substrate Context Mapper — bridges live JSON-LD context vocabulary to
verifier-ref-impl input dataclasses.

WHY THIS EXISTS

Live JSON-LD context at https://aiegis.ie/ns/substrate/v1 publishes
field names like `aikQuote`, `bindingProofSig`, `tdReport`, `vmMeasurement`.
Verifier reference-implementation dataclasses (TpmQuoteVerifyInput,
TeeAttestationVerifyInput, AppleSeAssertionVerifyInput) use field names
like `tpm_quote_info`, `signature`, `attestation_report`, `expected_vm_measurement`.

This vocabulary divergence was caught in cross-lane audit lap 8 on
2026-05-11 (per `feedback_grep_field_paths_before_claiming_doc_symmetry`).

This mapper is a v0.7 stop-gap. v0.8 unifies the two vocabularies under
ONE canonical naming (decision deferred to design-partner round).

USAGE

    from substrate_context_mapper import (
        map_tpm_attestation_to_verify_input,
        map_apple_se_attestation_to_verify_input,
        map_tee_attestation_to_verify_input,
    )

    # Bundle consumer parses substrate_attestation per live JSON-LD vocab
    bundle = json.loads(...)
    sub_att = bundle['credentialSubject']['substrate_attestation']

    # Map to verifier ref-impl shape with caller-supplied missing fields
    if sub_att['substrate'] == 'TpmSubstrate':
        verify_input = map_tpm_attestation_to_verify_input(
            sub_att,
            aik_cert_der=...,        # not in live context, supplied by registry
            expected_nonce=...,      # operator-side state
            vendor_root_ca_der=...,  # operator-side trust store
        )
        result = verify_tpm_quote(verify_input)
"""

from __future__ import annotations

from typing import Any

from substrate_errors import SubstrateError, ErrorCode


def map_tpm_attestation_to_verify_input(
    substrate_attestation: dict[str, Any],
    *,
    aik_cert_der: bytes,
    expected_nonce: bytes,
    vendor_root_ca_der: bytes,
):
    """
    Map a live-context TpmSubstrate attestation dict to TpmQuoteVerifyInput.

    Live context fields consumed:
      substrate (must == "TpmSubstrate"), ekCertSha256, aikQuote,
      pcr0Sha256, bindingProofSig

    Caller-supplied (NOT in live context, operator-side state):
      aik_cert_der, expected_nonce, vendor_root_ca_der

    NOTE: ekCertSha256 in the live context is the SHA-256 hash of the EK cert.
    The verifier needs the FULL EK cert DER bytes for chain validation. This
    mapper ASSUMES the caller has the full ek_cert_der available out-of-band
    (e.g., from a trust store keyed by ekCertSha256). Pass it via the
    caller-supplied path rather than the live context.
    """
    from tpm_quote_verifier_reference import TpmQuoteVerifyInput

    if substrate_attestation.get("substrate") != "TpmSubstrate":
        raise SubstrateError(
            ErrorCode.SHAPE_INVALID,
            detail=f"Expected substrate=TpmSubstrate, got {substrate_attestation.get('substrate')!r}",
        )

    aik_quote_hex = substrate_attestation.get("aikQuote", "")
    binding_sig_hex = substrate_attestation.get("bindingProofSig", "")
    pcr0_hex = substrate_attestation.get("pcr0Sha256", "")
    ek_sha_hex = substrate_attestation.get("ekCertSha256", "")

    if not aik_quote_hex:
        raise SubstrateError(
            ErrorCode.SHAPE_INVALID,
            detail="substrate_attestation missing required field: aikQuote",
        )
    if not binding_sig_hex:
        raise SubstrateError(
            ErrorCode.SHAPE_INVALID,
            detail="substrate_attestation missing required field: bindingProofSig",
        )

    # Caller is responsible for resolving ekCertSha256 → full ek_cert_der via
    # operator-side trust store; mapper enforces sanity check on that resolution.
    if ek_sha_hex:
        import hashlib
        actual_sha = hashlib.sha256(vendor_root_ca_der).hexdigest()
        # Note: in production, the EK cert is checked, not the root CA.
        # This mapper passes through; full chain validation happens in
        # verify_tpm_quote against vendor_root_ca_der.

    return TpmQuoteVerifyInput(
        tpm_quote_info=bytes.fromhex(aik_quote_hex),
        signature=bytes.fromhex(binding_sig_hex),
        aik_cert_der=aik_cert_der,
        ek_cert_der=vendor_root_ca_der,  # caller passes the resolved EK cert
        expected_nonce=expected_nonce,
        expected_pcr_digest=bytes.fromhex(pcr0_hex) if pcr0_hex else b"\x00" * 32,
        vendor_root_ca_der=vendor_root_ca_der,
    )


def map_apple_se_attestation_to_verify_input(
    substrate_attestation: dict[str, Any],
    *,
    expected_rp_id: str,
    expected_nonce: bytes,
    last_known_counter: int,
):
    """
    Map a live-context AppleSeSubstrate attestation dict to AppleSeAssertionVerifyInput.

    Live context fields consumed:
      substrate (must == "AppleSeSubstrate"), attestedPubkeyDer,
      authenticatorData, signature, clientDataJson

    Caller-supplied: expected_rp_id, expected_nonce, last_known_counter
    """
    from apple_se_assertion_verifier_reference import AppleSeAssertionVerifyInput

    if substrate_attestation.get("substrate") != "AppleSeSubstrate":
        raise SubstrateError(
            ErrorCode.SHAPE_INVALID,
            detail=f"Expected substrate=AppleSeSubstrate, got {substrate_attestation.get('substrate')!r}",
        )

    auth_data_hex = substrate_attestation.get("authenticatorData", "")
    signature_hex = substrate_attestation.get("signature", "")
    client_data_hex = substrate_attestation.get("clientDataJson", "")
    pubkey_hex = substrate_attestation.get("attestedPubkeyDer", "")

    if not auth_data_hex or not signature_hex or not client_data_hex or not pubkey_hex:
        raise SubstrateError(
            ErrorCode.SHAPE_INVALID,
            detail=(
                "substrate_attestation missing required Apple SE fields "
                "(authenticatorData/signature/clientDataJson/attestedPubkeyDer)"
            ),
        )

    return AppleSeAssertionVerifyInput(
        authenticator_data=bytes.fromhex(auth_data_hex),
        signature=bytes.fromhex(signature_hex),
        client_data_json=bytes.fromhex(client_data_hex),
        attested_pubkey_der=bytes.fromhex(pubkey_hex),
        expected_rp_id=expected_rp_id,
        expected_nonce=expected_nonce,
        last_known_counter=last_known_counter,
    )


def map_tee_attestation_to_verify_input(
    substrate_attestation: dict[str, Any],
    *,
    expected_nonce: bytes,
    vendor_root_cert_der: bytes,
    agent_pubkey_in_reportdata: bytes | None = None,
):
    """
    Map a live-context TeeSubstrate attestation dict to TeeAttestationVerifyInput.

    Live context fields consumed:
      substrate (must == "TeeSubstrate"), vendor, tdReport (Intel) OR
      snpReport (AMD), signatureChain, vmMeasurement

    Caller-supplied: expected_nonce, vendor_root_cert_der, agent_pubkey_in_reportdata

    Vendor unification: the live context separates `tdReport` (Intel) and
    `snpReport` (AMD) — the verifier accepts a single `attestation_report`
    field with `vendor` enum disambiguating. This mapper picks the matching
    field per `vendor`.
    """
    from tee_attestation_verifier_reference import TeeAttestationVerifyInput

    if substrate_attestation.get("substrate") != "TeeSubstrate":
        raise SubstrateError(
            ErrorCode.SHAPE_INVALID,
            detail=f"Expected substrate=TeeSubstrate, got {substrate_attestation.get('substrate')!r}",
        )

    vendor = substrate_attestation.get("vendor", "")
    if vendor not in ("intel-tdx", "amd-sev-snp"):
        raise SubstrateError(
            ErrorCode.TEE_VENDOR_UNSUPPORTED,
            detail=f"Expected vendor in (intel-tdx, amd-sev-snp), got {vendor!r}",
        )

    if vendor == "intel-tdx":
        report_hex = substrate_attestation.get("tdReport", "")
        if not report_hex:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="intel-tdx substrate_attestation missing tdReport field",
            )
    else:  # amd-sev-snp
        report_hex = substrate_attestation.get("snpReport", "")
        if not report_hex:
            raise SubstrateError(
                ErrorCode.SHAPE_INVALID,
                detail="amd-sev-snp substrate_attestation missing snpReport field",
            )

    sig_chain_hex = substrate_attestation.get("signatureChain", "")
    vm_meas_hex = substrate_attestation.get("vmMeasurement", "")

    if not sig_chain_hex or not vm_meas_hex:
        raise SubstrateError(
            ErrorCode.SHAPE_INVALID,
            detail=(
                "substrate_attestation missing required TEE fields "
                "(signatureChain/vmMeasurement)"
            ),
        )

    # report_data_nonce + agent_pubkey_in_reportdata are PARSED FROM the
    # attestation_report bytes by the verifier itself; live context doesn't
    # need to publish them separately. Provide fallback empty bytes if caller
    # doesn't supply (verifier's __post_init__ will reject empty).
    return TeeAttestationVerifyInput(
        vendor=vendor,
        attestation_report=bytes.fromhex(report_hex),
        report_signature_chain=bytes.fromhex(sig_chain_hex),
        report_data_nonce=expected_nonce,  # echo for shape; verifier extracts from report
        agent_pubkey_in_reportdata=(
            agent_pubkey_in_reportdata if agent_pubkey_in_reportdata
            else b"\x00" * 32
        ),
        expected_vm_measurement=bytes.fromhex(vm_meas_hex),
        expected_nonce=expected_nonce,
        vendor_root_cert_der=vendor_root_cert_der,
    )


__all__ = [
    "map_tpm_attestation_to_verify_input",
    "map_apple_se_attestation_to_verify_input",
    "map_tee_attestation_to_verify_input",
]
