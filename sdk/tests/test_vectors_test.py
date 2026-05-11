"""
Cross-SDK byte-equivalence test — Python side.

Loads the shared test-vector pack at /Users/velo/Documents/VELO/aiegis-sdk-test-vectors/
(or env AIEGIS_TEST_VECTORS_DIR) and asserts that this SDK's _crypto module
produces byte-identical output to the manifest. The TS SDK's
test/test_vectors.test.ts runs the same fixtures and must produce the same
bytes — that's the substrate-portability proof.
"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from aiegis_agent import _crypto


def _vectors_dir() -> Path | None:
    env = os.environ.get("AIEGIS_TEST_VECTORS_DIR")
    if env:
        p = Path(env)
        return p if p.exists() else None
    default = Path("/Users/velo/Documents/VELO/aiegis-sdk-test-vectors")
    return default if default.exists() else None


VECTORS = _vectors_dir()


@unittest.skipIf(VECTORS is None, "test-vectors pack not mounted; set AIEGIS_TEST_VECTORS_DIR")
class TestCrossSDKByteEquivalence(unittest.TestCase):

    def setUp(self) -> None:
        self.keypairs = json.loads((VECTORS / "keypairs.json").read_text())["keypairs"]
        self.passport_dir = VECTORS / "passport_fixtures"
        self.sig_dir = VECTORS / "signature_fixtures"

    def test_did_derivation(self) -> None:
        for kp in self.keypairs:
            pub = bytes.fromhex(kp["public_key_hex"])
            self.assertEqual(_crypto.derive_did(pub), kp["did"])

    def test_canonicalize_byte_length_and_sha(self) -> None:
        for fixture_path in self.passport_dir.glob("*.json"):
            passport = json.loads(fixture_path.read_text())
            canonical = _crypto.canonicalize(passport)
            # Pull expected from the first signature fixture — they all share
            # payload_canonical_sha256 + payload_canonical_bytes_len for this fixture.
            sig_files = list(self.sig_dir.glob(f"keypair*_{fixture_path.stem}.json"))
            self.assertTrue(sig_files, f"no signature fixture for {fixture_path.stem}")
            expected = json.loads(sig_files[0].read_text())
            self.assertEqual(len(canonical), expected["payload_canonical_bytes_len"])
            self.assertEqual(_crypto.sha256_hex(canonical), expected["payload_canonical_sha256"])

    def test_signature_byte_identity(self) -> None:
        passport_cache = {
            p.stem: json.loads(p.read_text())
            for p in self.passport_dir.glob("*.json")
        }
        for sig_path in self.sig_dir.glob("*.json"):
            data = json.loads(sig_path.read_text())
            kp = self.keypairs[data["keypair_index"]]
            priv = bytes.fromhex(kp["private_key_hex"])
            passport = passport_cache[data["passport_fixture"]]
            canonical = _crypto.canonicalize(passport)
            sig = _crypto.sign(priv, canonical)
            self.assertEqual(sig.hex(), data["signature_hex"], f"drift on {sig_path.name}")

    def test_verify_roundtrip(self) -> None:
        # Pick first keypair × first fixture
        kp = self.keypairs[0]
        priv = bytes.fromhex(kp["private_key_hex"])
        pub = bytes.fromhex(kp["public_key_hex"])
        passport = json.loads(next(self.passport_dir.glob("*.json")).read_text())
        canonical = _crypto.canonicalize(passport)
        sig = _crypto.sign(priv, canonical)
        self.assertTrue(_crypto.verify(pub, sig, canonical))
        # Tamper one byte → verify must fail
        bad = bytearray(canonical)
        bad[0] ^= 0x01
        self.assertFalse(_crypto.verify(pub, sig, bytes(bad)))


if __name__ == "__main__":
    unittest.main()
