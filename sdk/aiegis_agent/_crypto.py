"""
Ed25519 keypair + did:aiegis derivation. Internal module.

Mirrors the test-vector reference impl in /aiegis-sdk-test-vectors/generate.py —
both must produce byte-identical DIDs and signatures for the same (seed, payload).

Public functions:
  generate_keypair(seed=None) -> (priv_bytes, pub_bytes)
  derive_did(pub_bytes, namespace='agent') -> str
  sign(priv_bytes, payload) -> bytes
  verify(pub_bytes, signature, payload) -> bool
  canonicalize(obj) -> bytes
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.exceptions import InvalidSignature

from aiegis_agent.errors import IdentityError

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc_encode(payload: bytes) -> str:
    """Bitcoin-alphabet base58 encoder. No external dep — keeps SDK light."""
    n = int.from_bytes(payload, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58_ALPHABET[r] + out
    leading = sum(1 for b in payload if b == 0) if not payload or payload[0] != 0 else 0
    # Recompute leading correctly: count leading zero bytes in payload
    leading = 0
    for b in payload:
        if b == 0:
            leading += 1
        else:
            break
    return ("1" * leading) + out


def generate_keypair(seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Return (private_key_raw_32b, public_key_raw_32b).

    If seed is None, uses os.urandom(32). Otherwise seed must be exactly 32 bytes —
    enables deterministic test-vector generation.

    Raises IdentityError on bad seed.
    """
    if seed is None:
        seed = os.urandom(32)
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise IdentityError("seed must be exactly 32 bytes")
    try:
        sk = Ed25519PrivateKey.from_private_bytes(bytes(seed))
    except Exception as e:
        raise IdentityError(f"Ed25519 keypair generation failed: {e}") from e
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return priv, pub


def public_from_private(private_key_bytes: bytes) -> bytes:
    """Derive the raw 32-byte Ed25519 public key from a private key.

    Used by callers that hold only the private key but need to verify the
    public-key-derived DID matches a separately-passed operator_did
    parameter (cryptographic linkage check at build-time, preventing
    silent priv/did mismatch — see generator.py build_bundle).

    Raises IdentityError on bad private key bytes.
    """
    if not isinstance(private_key_bytes, (bytes, bytearray)) or len(private_key_bytes) != 32:
        raise IdentityError("private_key_bytes must be 32 bytes (Ed25519 raw)")
    try:
        sk = Ed25519PrivateKey.from_private_bytes(bytes(private_key_bytes))
    except Exception as e:
        raise IdentityError(f"Ed25519 private key derivation failed: {e}") from e
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def derive_did(public_key_bytes: bytes, namespace: str = "agent") -> str:
    """Per DID_AIEGIS_METHOD_SPEC_V01_NEL.md.

    did:aiegis:<namespace>:z<base58btc(0xed01 || ed25519-pubkey)>

    Multibase 'z' prefix + base58btc-encoded (multicodec 0xed01 ed25519-pub +
    32-byte raw pubkey). W3C DID Core conformant + did:key-compatible.

    namespace ∈ {agent, operator, registry}. SDK consumers use 'agent' by default.
    """
    if namespace not in {"agent", "operator", "registry"}:
        raise IdentityError(f"namespace must be agent|operator|registry, got {namespace!r}")
    if len(public_key_bytes) != 32:
        raise IdentityError("public_key_bytes must be 32 bytes (Ed25519 raw)")
    multicodec = b"\xed\x01"
    encoded = _base58btc_encode(multicodec + public_key_bytes)
    return f"did:aiegis:{namespace}:z{encoded}"


def sign(private_key_bytes: bytes, payload: bytes) -> bytes:
    """Ed25519 sign. Returns raw 64-byte signature.

    Deterministic per RFC 8032 § 5.1.6 — same (key, payload) always produces
    the same signature, which is what test-vector byte-equivalence depends on.
    """
    if len(private_key_bytes) != 32:
        raise IdentityError("private_key_bytes must be 32 bytes")
    try:
        sk = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    except Exception as e:
        raise IdentityError(f"private key load failed: {e}") from e
    return sk.sign(payload)


def verify(public_key_bytes: bytes, signature: bytes, payload: bytes) -> bool:
    """Ed25519 verify. Returns True iff signature is valid for (pubkey, payload).

    Returns False on InvalidSignature (does not raise — caller checks bool).
    Raises IdentityError on malformed key or signature length.
    """
    if len(public_key_bytes) != 32:
        raise IdentityError("public_key_bytes must be 32 bytes")
    if len(signature) != 64:
        raise IdentityError("signature must be 64 bytes")
    try:
        pk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except Exception as e:
        raise IdentityError(f"public key load failed: {e}") from e
    try:
        pk.verify(signature, payload)
        return True
    except InvalidSignature:
        return False


def canonicalize(obj: dict | list | str | int | float | bool | None) -> bytes:
    """Deterministic JSON serialization — sort_keys=True, separators=(',', ':').

    SDK-side spec for v0.6.x. v0.7.0 will migrate to JCS (RFC 8785) when the
    server side accepts it; until then, this is the byte-identity primitive.

    Both Python and TS SDKs MUST produce identical bytes for any (object).
    Test-vector pack at /aiegis-sdk-test-vectors enforces this in CI.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Convenience hex-SHA-256 — matches test-vector signature_fixtures format."""
    return hashlib.sha256(data).hexdigest()
