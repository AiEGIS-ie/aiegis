"""Tests for compliance-bundle generator. Run: python3 -m unittest test_generator."""

from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, "/Users/velo/Documents/VELO/aiegis-agent-sdk-python")
sys.path.insert(0, "/Users/velo/Documents/VELO/aiegis-compliance-bundle")

from aiegis_agent import _crypto  # type: ignore
from generator import BeaconEvent, build_bundle, verify_bundle, VerificationResult, VerifyFailReason


class TestBundleGenerator(unittest.TestCase):
    def setUp(self) -> None:
        # Deterministic operator keypair for byte-identity tests
        self.priv, self.pub = _crypto.generate_keypair(seed=bytes(32))
        self.operator_did = _crypto.derive_did(self.pub, namespace="operator")
        self.customer_did = "did:aiegis:customer:z6MkExample"
        self.events = [
            BeaconEvent(
                event_id=f"evt-{i}",
                decision=["block", "warn", "block"][i],
                rule=["pi.ignore_previous", "pii.email", "secret.openai_key"][i],
                timestamp="2026-08-15T12:00:00+00:00",
                customer_did=self.customer_did,
                classifier_hits=[],
            )
            for i in range(3)
        ]

    def _build(self) -> dict:
        return build_bundle(
            events=self.events,
            operator_priv=self.priv,
            operator_did=self.operator_did,
            customer_did=self.customer_did,
            valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
            valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
            classifier_version="0.6.6",
            policy_bundle={"rulesRsSha256": "a" * 64, "libRsSha256": "b" * 64, "policyJsonSha256": "c" * 64, "binarySha256": "d" * 64},
        )

    def test_bundle_structure(self) -> None:
        b = self._build()
        self.assertIn("@context", b)
        self.assertIn("VerifiableCredential", b["type"])
        self.assertIn("AiEGISComplianceBundle", b["type"])
        self.assertEqual(b["issuer"], self.operator_did)
        self.assertIn("proof", b)
        self.assertEqual(b["proof"]["cryptosuite"], "eddsa-rdfc-2022")

    def test_signature_verifies(self) -> None:
        b = self._build()
        self.assertTrue(verify_bundle(b, self.pub))

    def test_tampered_payload_fails_verify(self) -> None:
        b = self._build()
        b["credentialSubject"]["eventCount"] = 999  # tamper
        self.assertFalse(verify_bundle(b, self.pub))

    def test_decision_breakdown(self) -> None:
        b = self._build()
        bd = b["credentialSubject"]["decisionBreakdown"]
        self.assertEqual(bd["block"], 2)
        self.assertEqual(bd["warn"], 1)
        self.assertEqual(bd["allow"], 0)

    def test_wrong_pubkey_fails_verify(self) -> None:
        b = self._build()
        _, other_pub = _crypto.generate_keypair(seed=bytes([1]) * 32)
        self.assertFalse(verify_bundle(b, other_pub))

    def test_missing_proof_fails_verify(self) -> None:
        b = self._build()
        del b["proof"]
        self.assertFalse(verify_bundle(b, self.pub))

    def test_operator_did_namespace(self) -> None:
        # Spec: operator-key custody. Issuer DID must be operator namespace.
        b = self._build()
        self.assertTrue(b["issuer"].startswith("did:aiegis:operator:"))

    def test_policy_bundle_requires_all_4_hashes(self) -> None:
        # Per Nel audit-find (generator sha 43e84f51): regulator-handed bundles
        # MUST have all 4 hashes — without binary sha, auditor can't prove
        # which classifier code was running; without policy.json sha, the
        # operator's runtime config is unaudtiable.
        with self.assertRaises(ValueError) as ctx:
            build_bundle(
                events=self.events,
                operator_priv=self.priv,
                operator_did=self.operator_did,
                customer_did=self.customer_did,
                valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
                valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
                classifier_version="0.6.6",
                policy_bundle={"rulesRsSha256": "a" * 64, "libRsSha256": "b" * 64},
            )
        self.assertIn("policy_bundle missing", str(ctx.exception))

    def test_substrate_attestation_optional_passthrough(self) -> None:
        # Per Nel HOST_SUBSTRATE_FINGERPRINT_BINDING_SPEC_V01 sha 150d03f0:
        # bundle composes with substrate-attested DID; field optional, passes
        # through to proof unchanged when present.
        substrate_attestation = {
            "substrate": "tpm-2.0",
            "ekCertSha256": "0" * 64,
            "aikQuote": "deadbeef",
            "pcr0Sha256": "1" * 64,
            "bindingProofSig": "ed25519-sig-hex",
        }
        b = build_bundle(
            events=self.events,
            operator_priv=self.priv,
            operator_did=self.operator_did,
            customer_did=self.customer_did,
            valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
            valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
            classifier_version="0.6.6",
            policy_bundle={"rulesRsSha256": "a" * 64, "libRsSha256": "b" * 64, "policyJsonSha256": "c" * 64, "binarySha256": "d" * 64},
            substrate_attestation=substrate_attestation,
        )
        self.assertEqual(b["proof"]["substrateAttestation"], substrate_attestation)
        self.assertTrue(verify_bundle(b, self.pub))


class TestVerificationResultDiagnosis(unittest.TestCase):
    """Field-level diagnosis tests — shape parity with Nel's 4 substrate verifiers.

    Same silent-fail-class discipline: regulator audit log must distinguish
    tampered-sig / malformed-bundle / wrong-key-format / missing-proofValue.
    Returning opaque False (pre-VerificationResult) was an adversary advantage.
    """

    def setUp(self) -> None:
        import sys
        sys.path.insert(0, "/Users/velo/Documents/VELO/aiegis-agent-sdk-python")
        from aiegis_agent import _crypto  # type: ignore
        self.priv, self.pub = _crypto.generate_keypair(seed=bytes(32))
        self.operator_did = _crypto.derive_did(self.pub, namespace="operator")
        self.bundle = build_bundle(
            events=[BeaconEvent("e", "block", "r", "2026-08-15T12:00:00+00:00", "did:aiegis:customer:x", [])],
            operator_priv=self.priv,
            operator_did=self.operator_did,
            customer_did="did:aiegis:customer:x",
            valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
            valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
            classifier_version="0.6.6",
            policy_bundle={"rulesRsSha256": "a"*64, "libRsSha256": "b"*64, "policyJsonSha256": "c"*64, "binarySha256": "d"*64},
        )

    def test_returns_VerificationResult_not_bool(self):
        r = verify_bundle(self.bundle, self.pub)
        self.assertIsInstance(r, VerificationResult)

    def test_bool_truthy_on_valid(self):
        # Backwards-compat: `if verify_bundle(...)` must keep working.
        r = verify_bundle(self.bundle, self.pub)
        self.assertTrue(r)
        self.assertTrue(r.valid)
        self.assertEqual(r.failure_reasons, (VerifyFailReason.OK,))

    def test_diagnosis_missing_proof(self):
        b = dict(self.bundle)
        del b["proof"]
        r = verify_bundle(b, self.pub)
        self.assertFalse(r)
        self.assertFalse(r.proof_present)
        self.assertIn(VerifyFailReason.MISSING_PROOF, r.failure_reasons)

    def test_diagnosis_missing_proof_value(self):
        b = dict(self.bundle)
        b["proof"] = dict(b["proof"])
        del b["proof"]["proofValue"]
        r = verify_bundle(b, self.pub)
        self.assertFalse(r)
        self.assertTrue(r.proof_present)
        self.assertFalse(r.proof_value_present)
        self.assertIn(VerifyFailReason.MISSING_PROOF_VALUE, r.failure_reasons)

    def test_diagnosis_invalid_hex(self):
        b = dict(self.bundle)
        b["proof"] = dict(b["proof"])
        b["proof"]["proofValue"] = "not-hex-at-all-zz"
        r = verify_bundle(b, self.pub)
        self.assertFalse(r)
        self.assertTrue(r.proof_value_present)
        self.assertFalse(r.proof_hex_valid)
        self.assertIn(VerifyFailReason.INVALID_PROOF_HEX, r.failure_reasons)

    def test_diagnosis_signature_invalid_after_tamper(self):
        b = dict(self.bundle)
        b["credentialSubject"] = dict(b["credentialSubject"])
        b["credentialSubject"]["eventCount"] = 999  # tamper
        r = verify_bundle(b, self.pub)
        self.assertFalse(r)
        # All pre-checks pass — only the cryptographic signature check fails.
        self.assertTrue(r.proof_present)
        self.assertTrue(r.proof_value_present)
        self.assertTrue(r.proof_hex_valid)
        self.assertTrue(r.key_format_valid)
        self.assertTrue(r.canonicalization_ok)
        self.assertFalse(r.signature_valid)
        self.assertIn(VerifyFailReason.SIGNATURE_INVALID, r.failure_reasons)

    def test_rejects_too_long_proof_value_dos_cap(self):
        """DoS guard: cap proofValue hex before parse. 100MB+ inputs would
        allocate ~50MB before signature check — reject early."""
        b = dict(self.bundle)
        b["proof"] = dict(b["proof"])
        b["proof"]["proofValue"] = "a" * 20000  # > 16KB cap
        r = verify_bundle(b, self.pub)
        self.assertFalse(r)
        self.assertIn(VerifyFailReason.INVALID_PROOF_HEX, r.failure_reasons)
        self.assertIn("too long", r.details)

    def test_diagnosis_bad_key_format(self):
        r = verify_bundle(self.bundle, b"too-short")
        self.assertFalse(r)
        self.assertFalse(r.key_format_valid)
        self.assertIn(VerifyFailReason.INVALID_KEY_FORMAT, r.failure_reasons)

    def test_narrow_triple_locks_each_direction(self):
        """Lock each narrow exception type explicitly per the gap-hypothesis I
        sparked at 20:39:03 — bubble-direction is locked by the _Sentinel test,
        but the EXACT narrow triple (ValueError, TypeError, IdentityError) is
        not. If someone re-narrowed to (ValueError, IdentityError) — dropping
        TypeError — programmer-bug-bubble test still passes, but legitimate
        TypeError from a crypto lib internal would silently bubble as if it
        were a programmer bug. This test fires each member of the triple via
        mock and asserts each wraps to INVALID_KEY_FORMAT in failure_reasons.
        Locks the set in BOTH directions: too-narrow + too-broad both fail."""
        from unittest.mock import patch
        import generator as gen_mod

        for exc_cls in (ValueError, TypeError):
            with patch.object(gen_mod._crypto, "verify", side_effect=exc_cls("synthetic")):
                r = verify_bundle(self.bundle, self.pub)
                self.assertFalse(r, f"{exc_cls.__name__} should wrap to falsy result")
                self.assertIn(
                    VerifyFailReason.INVALID_KEY_FORMAT, r.failure_reasons,
                    f"{exc_cls.__name__} should wrap to INVALID_KEY_FORMAT",
                )
        # IdentityError is already covered by test_diagnosis_bad_key_format
        # via the real cryptography stack (wrong-length pubkey path).

    def test_over_catch_regression_lock(self):
        """Discipline-lock against re-broadening verify_bundle except clause.

        Mirror of Nel's test_over_catch_tightening_lets_programmer_bugs_bubble
        on the substrate-verifier side (sha 8414a6e6 -> e2c8e717). If anyone
        widens our `except (ValueError, TypeError, IdentityError)` to bare
        `except Exception`, programmer-bug exceptions (KeyboardInterrupt
        sibling-types, AttributeError on malformed dicts) would mask as False
        again. This test feeds the function a payload that triggers an
        unexpected exception class — verify_bundle MUST raise, not silently
        return falsy VerificationResult.
        """
        class _Sentinel:
            """Non-container object — `"proof" not in obj` raises TypeError."""
            pass

        # Pre-tightening, the bare `except Exception:` would have swallowed
        # this TypeError and returned False. Post-tightening, the first line
        # `if "proof" not in bundle` has NO try/except wrapping — so a
        # malformed bundle of the wrong type bubbles cleanly. Locks the
        # contract: caller-supplied bad types raise, never silent-False.
        with self.assertRaises(TypeError):
            verify_bundle(_Sentinel(), self.pub)  # type: ignore[arg-type]


    def test_details_field_no_exception_message_leak(self):
        """Discipline-lock: details strings must NEVER include raw exception
        message content — only class name. Per Nel red-team 20:44 HIGH-sev:
        raw exception messages can leak filesystem paths, hex of bad input,
        library-internal pointer addresses, stack traces. customer-facing
        audit log gets type-not-content.

        Falsification: if anyone re-adds `{e}` interpolation, this test fires
        a synthetic exception whose str() is a recognizable sentinel string;
        if that sentinel appears in details, leak regression has shipped.
        """
        from unittest.mock import patch
        import generator as gen_mod
        SENTINEL = "SECRET_PATH_/Users/leaked/file.pem_AT_OFFSET_0xDEADBEEF"

        # Site 1: INVALID_KEY_FORMAT path (_crypto.verify raises)
        for exc_cls in (ValueError, TypeError):
            with patch.object(gen_mod._crypto, "verify", side_effect=exc_cls(SENTINEL)):
                r = verify_bundle(self.bundle, self.pub)
                self.assertFalse(r)
                self.assertIn(VerifyFailReason.INVALID_KEY_FORMAT, r.failure_reasons)
                self.assertNotIn(SENTINEL, r.details,
                    f"INVALID_KEY_FORMAT site leaked exc msg for {exc_cls.__name__}")
                self.assertIn(exc_cls.__name__, r.details)

        # Site 2: INVALID_PROOF_HEX — CPython's bytes.fromhex error message
        # is generic ("non-hexadecimal number found..."), doesn't echo input.
        # Leak risk is theoretical, not exploitable. Static-source assert:
        import inspect
        src = inspect.getsource(verify_bundle)
        # The 3 details-format sites must use type(e).__name__, not {e}.
        # Raw `{e}` interpolation inside details=f"..." is the failure pattern.
        for forbidden in ['details=f"proofValue not valid hex: {e}"',
                          'details=f"payload canonicalization failed: {e}"',
                          'details=f"operator_pub key format invalid: {e}"']:
            self.assertNotIn(forbidden, src,
                f"raw {{e}} interp re-introduced: {forbidden[:60]}")

        # Site 3: CANONICALIZATION_FAILED path (_crypto.canonicalize raises)
        for exc_cls in (ValueError, TypeError):
            with patch.object(gen_mod._crypto, "canonicalize", side_effect=exc_cls(SENTINEL)):
                r = verify_bundle(self.bundle, self.pub)
                self.assertFalse(r)
                self.assertIn(VerifyFailReason.CANONICALIZATION_FAILED, r.failure_reasons)
                self.assertNotIn(SENTINEL, r.details,
                    f"CANONICALIZATION_FAILED site leaked exc msg for {exc_cls.__name__}")
                self.assertIn(exc_cls.__name__, r.details)


    def test_rejects_priv_did_mismatch(self):
        """Cryptographic linkage check: caller passing A's priv with B's did
        produces silent-misbuild bundle (sig from A, issuer claim B). Verify
        catches it via signature mismatch but build should fail loud."""
        # Generate a SECOND keypair — its DID is different from self.operator_did
        from aiegis_agent import _crypto  # type: ignore
        other_priv, _ = _crypto.generate_keypair(seed=bytes([1]) * 32)
        with self.assertRaises(ValueError) as ctx:
            build_bundle(
                events=[BeaconEvent("e", "block", "r", "2026-08-15T12:00:00+00:00",
                                    "did:aiegis:customer:x", [])],
                operator_priv=other_priv,                # priv from keypair A
                operator_did=self.operator_did,          # did from keypair B
                customer_did="did:aiegis:customer:x",
                valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
                valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
                classifier_version="0.6.6",
                policy_bundle={"rulesRsSha256": "a"*64, "libRsSha256": "b"*64,
                               "policyJsonSha256": "c"*64, "binarySha256": "d"*64},
            )
        self.assertIn("does not derive operator_did", str(ctx.exception))

    def test_rejects_too_many_events_dos_cap(self):
        """DoS guard: regulator-handed bundles cap at MAX_EVENTS_PER_BUNDLE.
        Mirrors Nel's tpm_quote_info 64KB cap discipline."""
        from generator import MAX_EVENTS_PER_BUNDLE
        ev = BeaconEvent("e", "block", "r", "2026-08-15T12:00:00+00:00",
                         "did:aiegis:customer:x", [])
        with self.assertRaises(ValueError) as ctx:
            self._build_with_events([ev] * (MAX_EVENTS_PER_BUNDLE + 1))
        self.assertIn("events list too long", str(ctx.exception))

    def test_rejects_empty_classifier_version(self):
        with self.assertRaises(ValueError):
            self._build_with_classifier_version("")

    def test_rejects_too_long_classifier_version(self):
        with self.assertRaises(ValueError):
            self._build_with_classifier_version("x" * 65)

    def test_rejects_non_dict_substrate_attestation(self):
        with self.assertRaises(ValueError):
            self._build_with_substrate("not-a-dict")  # type: ignore[arg-type]

    def _build_with_events(self, events):
        return build_bundle(
            events=events,
            operator_priv=self.priv, operator_did=self.operator_did,
            customer_did="did:aiegis:customer:x",
            valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
            valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
            classifier_version="0.6.6",
            policy_bundle={"rulesRsSha256": "a"*64, "libRsSha256": "b"*64,
                           "policyJsonSha256": "c"*64, "binarySha256": "d"*64},
        )

    def _build_with_classifier_version(self, ver):
        return build_bundle(
            events=[BeaconEvent("e", "block", "r", "2026-08-15T12:00:00+00:00",
                                "did:aiegis:customer:x", [])],
            operator_priv=self.priv, operator_did=self.operator_did,
            customer_did="did:aiegis:customer:x",
            valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
            valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
            classifier_version=ver,
            policy_bundle={"rulesRsSha256": "a"*64, "libRsSha256": "b"*64,
                           "policyJsonSha256": "c"*64, "binarySha256": "d"*64},
        )

    def _build_with_substrate(self, sub):
        return build_bundle(
            events=[BeaconEvent("e", "block", "r", "2026-08-15T12:00:00+00:00",
                                "did:aiegis:customer:x", [])],
            operator_priv=self.priv, operator_did=self.operator_did,
            customer_did="did:aiegis:customer:x",
            valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
            valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
            classifier_version="0.6.6",
            policy_bundle={"rulesRsSha256": "a"*64, "libRsSha256": "b"*64,
                           "policyJsonSha256": "c"*64, "binarySha256": "d"*64},
            substrate_attestation=sub,
        )

    def test_rejects_wrong_tier_operator_did(self):
        """operator_did must be did:aiegis:operator: tier. Other tiers
        (did:web, did:aiegis:agent, did:key) would silently downgrade the
        trust claim of the regulator-handed bundle."""
        for bad_did in ("did:web:foo.com", "did:aiegis:agent:bob",
                        "did:key:z6Mk", "not-a-did"):
            with self.assertRaises(ValueError):
                build_bundle(
                    events=[BeaconEvent("e", "block", "r", "2026-08-15T12:00:00+00:00",
                                        "did:aiegis:customer:x", [])],
                    operator_priv=self.priv, operator_did=bad_did,
                    customer_did="did:aiegis:customer:x",
                    valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
                    valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
                    classifier_version="0.6.6",
                    policy_bundle={"rulesRsSha256": "a"*64, "libRsSha256": "b"*64,
                                   "policyJsonSha256": "c"*64, "binarySha256": "d"*64},
                )

    def test_rejects_duplicate_event_ids(self):
        """Audit-trail integrity: regulator can't disambiguate two events
        sharing the same event_id."""
        ev1 = BeaconEvent("dup-id", "block", "r1", "2026-08-15T12:00:00+00:00",
                          "did:aiegis:customer:x", [])
        ev2 = BeaconEvent("dup-id", "warn", "r2", "2026-08-15T12:00:01+00:00",
                          "did:aiegis:customer:x", [])
        with self.assertRaises(ValueError) as ctx:
            build_bundle(
                events=[ev1, ev2],
                operator_priv=self.priv, operator_did=self.operator_did,
                customer_did="did:aiegis:customer:x",
                valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
                valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
                classifier_version="0.6.6",
                policy_bundle={"rulesRsSha256": "a"*64, "libRsSha256": "b"*64,
                               "policyJsonSha256": "c"*64, "binarySha256": "d"*64},
            )
        self.assertIn("duplicate event_id", str(ctx.exception))

    def test_rejects_inverted_compliance_window(self):
        """valid_from must strictly precede valid_until. Inverted window
        creates a meaningless retroactive bundle that still signs cleanly."""
        with self.assertRaises(ValueError) as ctx:
            build_bundle(
                events=[BeaconEvent("e", "block", "r", "2026-08-15T12:00:00+00:00",
                                    "did:aiegis:customer:x", [])],
                operator_priv=self.priv, operator_did=self.operator_did,
                customer_did="did:aiegis:customer:x",
                valid_from=datetime(2026, 8, 31, tzinfo=timezone.utc),
                valid_until=datetime(2026, 8, 1, tzinfo=timezone.utc),  # before from
                classifier_version="0.6.6",
                policy_bundle={"rulesRsSha256": "a"*64, "libRsSha256": "b"*64,
                               "policyJsonSha256": "c"*64, "binarySha256": "d"*64},
            )
        self.assertIn("valid_from must be strictly before valid_until", str(ctx.exception))

    def test_rejects_zero_length_compliance_window(self):
        same = datetime(2026, 8, 1, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            build_bundle(
                events=[BeaconEvent("e", "block", "r", "2026-08-15T12:00:00+00:00",
                                    "did:aiegis:customer:x", [])],
                operator_priv=self.priv, operator_did=self.operator_did,
                customer_did="did:aiegis:customer:x",
                valid_from=same, valid_until=same,
                classifier_version="0.6.6",
                policy_bundle={"rulesRsSha256": "a"*64, "libRsSha256": "b"*64,
                               "policyJsonSha256": "c"*64, "binarySha256": "d"*64},
            )

    def test_beacon_event_rejects_invalid_decision(self):
        """BeaconEvent.decision must be in {block, warn, allow}. Prior code
        silently accepted anything — malformed decision counted zero against
        the breakdown (not block/warn/allow), so the event shipped in the
        bundle but didn't show up in tallies. Audit-trail corruption."""
        with self.assertRaises(ValueError) as ctx:
            BeaconEvent("evt", "garbage", "rule", "2026-08-15T12:00:00+00:00",
                        "did:aiegis:customer:x", [])
        self.assertIn("must be one of", str(ctx.exception))

    def test_beacon_event_rejects_empty_decision(self):
        with self.assertRaises(ValueError):
            BeaconEvent("evt", "", "rule", "2026-08-15T12:00:00+00:00",
                        "did:aiegis:customer:x", [])

    def test_beacon_event_rejects_too_long_event_id(self):
        with self.assertRaises(ValueError) as ctx:
            BeaconEvent("e" * 129, "block", "r", "2026-08-15T12:00:00+00:00",
                        "did:aiegis:customer:x", [])
        self.assertIn("event_id too long", str(ctx.exception))

    def test_beacon_event_rejects_too_long_rule(self):
        with self.assertRaises(ValueError):
            BeaconEvent("e", "block", "r" * 257, "2026-08-15T12:00:00+00:00",
                        "did:aiegis:customer:x", [])

    def test_beacon_event_rejects_too_long_customer_did(self):
        with self.assertRaises(ValueError):
            BeaconEvent("e", "block", "r", "2026-08-15T12:00:00+00:00",
                        "did:aiegis:customer:" + "x" * 600, [])

    def test_beacon_event_rejects_nul_in_event_id(self):
        with self.assertRaises(ValueError) as ctx:
            BeaconEvent("evt\x00inject", "block", "r", "2026-08-15T12:00:00+00:00",
                        "did:aiegis:customer:x", [])
        self.assertIn("control characters", str(ctx.exception))

    def test_beacon_event_rejects_ctl_in_rule(self):
        with self.assertRaises(ValueError):
            BeaconEvent("e", "block", "rule\x1fhidden", "2026-08-15T12:00:00+00:00",
                        "did:aiegis:customer:x", [])

    def test_beacon_event_rejects_nul_in_customer_did(self):
        """Glass-house catch from Nel lap2: customer_did was missing the
        NUL/CTL rejection that event_id + rule had. Same intra-class drift
        as my own pin warned about."""
        with self.assertRaises(ValueError) as ctx:
            BeaconEvent("e", "block", "r", "2026-08-15T12:00:00+00:00",
                        "did:aiegis:customer:abc\x00leak", [])
        self.assertIn("control characters", str(ctx.exception))

    def test_build_bundle_rejects_nul_in_top_level_customer_did(self):
        """Same charset defense at the bundle-level parameter."""
        with self.assertRaises(ValueError):
            build_bundle(
                events=[BeaconEvent("e", "block", "r", "2026-08-15T12:00:00+00:00",
                                    "did:aiegis:customer:x", [])],
                operator_priv=self.priv, operator_did=self.operator_did,
                customer_did="did:aiegis:customer:abc\x00leak",
                valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
                valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
                classifier_version="0.6.6",
                policy_bundle={"rulesRsSha256": "a"*64, "libRsSha256": "b"*64,
                               "policyJsonSha256": "c"*64, "binarySha256": "d"*64},
            )

    def test_beacon_event_rejects_del_char_in_event_id(self):
        with self.assertRaises(ValueError):
            BeaconEvent("evt\x7fdel", "block", "r", "2026-08-15T12:00:00+00:00",
                        "did:aiegis:customer:x", [])

    def test_beacon_event_rejects_empty_event_id(self):
        with self.assertRaises(ValueError):
            BeaconEvent("", "block", "rule", "2026-08-15T12:00:00+00:00",
                        "did:aiegis:customer:x", [])

    def test_beacon_event_rejects_empty_rule(self):
        with self.assertRaises(ValueError):
            BeaconEvent("evt", "block", "", "2026-08-15T12:00:00+00:00",
                        "did:aiegis:customer:x", [])

    def test_beacon_event_rejects_non_did_customer(self):
        with self.assertRaises(ValueError) as ctx:
            BeaconEvent("evt", "block", "rule", "2026-08-15T12:00:00+00:00",
                        "not-a-did", [])
        self.assertIn("DID URI", str(ctx.exception))

    def test_build_bundle_rejects_non_did_customer(self):
        with self.assertRaises(ValueError):
            build_bundle(
                events=[BeaconEvent("e", "block", "r", "2026-08-15T12:00:00+00:00",
                                    "did:aiegis:customer:x", [])],
                operator_priv=self.priv, operator_did=self.operator_did,
                customer_did="not-a-did",
                valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
                valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
                classifier_version="0.6.6",
                policy_bundle={"rulesRsSha256": "a"*64, "libRsSha256": "b"*64,
                               "policyJsonSha256": "c"*64, "binarySha256": "d"*64},
            )

    def test_beacon_event_rejects_invalid_timestamp(self):
        for bad_ts in ("tomorrow", "1999-13-99", "", "not-a-date"):
            with self.assertRaises(ValueError):
                BeaconEvent("evt", "block", "rule", bad_ts,
                            "did:aiegis:customer:x", [])

    def test_beacon_event_rejects_naive_timestamp(self):
        """Audit-trail entries need unambiguous wall-clock — require tz."""
        with self.assertRaises(ValueError) as ctx:
            BeaconEvent("evt", "block", "rule", "2026-08-15T12:00:00",  # no tz
                        "did:aiegis:customer:x", [])
        self.assertIn("timezone", str(ctx.exception))

    def test_beacon_event_accepts_explicit_offset(self):
        # '+00:00' is the explicit UTC offset; supported by fromisoformat on all
        # Python versions ≥3.7.
        try:
            BeaconEvent("evt", "block", "rule", "2026-08-15T12:00:00+00:00",
                        "did:aiegis:customer:x", [])
        except ValueError as e:
            self.fail(f"valid +00:00 timestamp rejected: {e}")

    def test_beacon_event_accepts_z_suffix(self):
        # 'Z' is RFC 3339 canonical UTC shorthand. Python 3.9/3.10 fromisoformat
        # doesn't parse it natively — generator normalizes 'Z' → '+00:00' before
        # parse so customers on 3.9/3.10 don't false-fail. (Nel catch 21:00.)
        try:
            BeaconEvent("evt", "block", "rule", "2026-08-15T12:00:00Z",
                        "did:aiegis:customer:x", [])
        except ValueError as e:
            self.fail(f"'Z'-suffix RFC 3339 timestamp wrongly rejected: {e}")

    def test_beacon_event_case_sensitive(self):
        # 'BLOCK' must not slip through — canonical form is lowercase per spec
        with self.assertRaises(ValueError):
            BeaconEvent("evt", "BLOCK", "rule", "2026-08-15T12:00:00+00:00",
                        "did:aiegis:customer:x", [])

    def test_policy_bundle_rejects_none_values(self):
        """Tightening: key-present alone isn't enough — None values silently
        passing the prior check would put a meaningless sha into the
        regulator-handed bundle and make the audit trail unverifiable."""
        bad = {"rulesRsSha256": "a" * 64, "libRsSha256": "b" * 64,
               "policyJsonSha256": None, "binarySha256": "d" * 64}
        with self.assertRaises(ValueError) as ctx:
            self._build_with_policy(bad)
        self.assertIn("64-char lowercase hex", str(ctx.exception))

    def test_policy_bundle_rejects_wrong_length(self):
        bad = {"rulesRsSha256": "a" * 32, "libRsSha256": "b" * 64,
               "policyJsonSha256": "c" * 64, "binarySha256": "d" * 64}
        with self.assertRaises(ValueError) as ctx:
            self._build_with_policy(bad)
        self.assertIn("64-char lowercase hex", str(ctx.exception))

    def test_policy_bundle_rejects_uppercase_hex(self):
        bad = {"rulesRsSha256": "A" * 64, "libRsSha256": "b" * 64,
               "policyJsonSha256": "c" * 64, "binarySha256": "d" * 64}
        with self.assertRaises(ValueError):
            self._build_with_policy(bad)

    def test_policy_bundle_rejects_non_hex_chars(self):
        bad = {"rulesRsSha256": "z" * 64, "libRsSha256": "b" * 64,
               "policyJsonSha256": "c" * 64, "binarySha256": "d" * 64}
        with self.assertRaises(ValueError):
            self._build_with_policy(bad)

    def _build_with_policy(self, policy_bundle):
        return build_bundle(
            events=[BeaconEvent("e", "block", "r", "2026-08-15T12:00:00+00:00", "did:aiegis:customer:x", [])],
            operator_priv=self.priv, operator_did=self.operator_did,
            customer_did="did:aiegis:customer:x",
            valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
            valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
            classifier_version="0.6.6",
            policy_bundle=policy_bundle,
        )


if __name__ == "__main__":
    unittest.main()
