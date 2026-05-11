"""Integration smoke-test: compliance-bundle generator ↔ Nel's TPM verifier.

Verifies the two modules compose at import + that the substrate_attestation
dict shape velo emits is consumable by Nel's verifier. Full end-to-end
verification needs real TPM materials (EK cert, AIK quote, PCR digest);
this smoke-test confirms the shape contract.
"""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, "/Users/velo/Documents/VELO/aiegis-agent-sdk-python")
sys.path.insert(0, "/Users/velo/Documents/VELO/aiegis-compliance-bundle")
sys.path.insert(0, "/Volumes/500GB/aegis-cross-lane")

from aiegis_agent import _crypto  # type: ignore
from generator import BeaconEvent, build_bundle, verify_bundle


class TestNelTpmIntegration(unittest.TestCase):
    """End-to-end smoke-test wiring velo's generator + nel's TPM verifier."""

    def test_import_composes(self) -> None:
        """Both modules import without conflict."""
        import tpm_quote_verifier_reference as nel_tpm  # noqa: F401
        from generator import build_bundle as _bb  # noqa: F401
        self.assertTrue(hasattr(nel_tpm, "verify_tpm_quote"))
        self.assertTrue(hasattr(nel_tpm, "TpmQuoteVerifyInput"))
        self.assertTrue(hasattr(nel_tpm, "TpmQuoteVerifyResult"))

    def test_substrate_attestation_shape_matches_nel_inputs(self) -> None:
        """Velo's substrate_attestation dict carries fields Nel's verifier needs.

        Nel's TpmQuoteVerifyInput consumes:
          - aik_quote (bytes)        ← velo emits aikQuote (hex)
          - aik_signature (bytes)    ← velo emits bindingProofSig (hex)
          - ek_cert (bytes)          ← velo emits ekCertSha256 (hex; full cert resolved via lookup)
          - expected_pcr_digest      ← velo emits pcr0Sha256 (hex)
          - nonce (bytes)            ← regulator-provided at verify time

        This test confirms field-name mapping; full byte-level conversion
        + verifier execution requires real TPM materials.
        """
        from generator import build_bundle
        priv, pub = _crypto.generate_keypair(seed=bytes(32))
        operator_did = _crypto.derive_did(pub, namespace="operator")

        substrate_attestation = {
            "substrate": "tpm-2.0",
            "ekCertSha256": "0" * 64,
            "aikQuote": "deadbeef" * 8,
            "pcr0Sha256": "1" * 64,
            "bindingProofSig": "abcd" * 16,
        }
        bundle = build_bundle(
            events=[BeaconEvent("e0", "block", "pi.ignore_previous", "2026-08-15T12:00:00+00:00", "did:aiegis:customer:x", [])],
            operator_priv=priv,
            operator_did=operator_did,
            customer_did="did:aiegis:customer:x",
            valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
            valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
            classifier_version="0.6.6",
            policy_bundle={"rulesRsSha256": "a" * 64, "libRsSha256": "b" * 64, "policyJsonSha256": "c" * 64, "binarySha256": "d" * 64},
            substrate_attestation=substrate_attestation,
        )
        self.assertEqual(bundle["proof"]["substrateAttestation"]["substrate"], "tpm-2.0")
        # The 4 fields Nel's verifier consumes are all present
        required = {"ekCertSha256", "aikQuote", "pcr0Sha256", "bindingProofSig"}
        self.assertTrue(required.issubset(bundle["proof"]["substrateAttestation"].keys()))
        # Bundle signature still verifies with substrate field attached
        self.assertTrue(verify_bundle(bundle, pub))


if __name__ == "__main__":
    unittest.main()
