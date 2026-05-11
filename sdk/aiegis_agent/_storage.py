"""
Identity persistence — OS keyring + local agent metadata.

Private keys live in the OS keychain (macOS Keychain / Linux libsecret /
Windows DPAPI via the `keyring` package). Public metadata (DID, name,
operator_id, created_at) lives in a JSON sidecar at:

  $AIEGIS_HOME/agents/<name>.json     (default: ~/.aiegis/agents/)

The split exists because keyring backends differ in storage limits and
encoding rules — keep them holding ONLY the 32-byte raw private key.
Everything else is plain JSON next to the key reference.

Public functions:
  load_or_create(name, operator_id) -> Agent
  load(name) -> Agent | None
  delete(name) -> bool
  list_agents() -> list[Agent]

`Agent` is a public-surface dataclass from sdk.py; this module returns
ChallengeRecord-like internals and the SDK wraps them.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from aiegis_agent import _crypto
from aiegis_agent.errors import IdentityError


def _keyring():
    """Lazy import — keyring is only needed when persistence is actually used.
    Lets _crypto-only callers (test-vector verification, signing) import the
    package without forcing a keyring install."""
    import keyring  # type: ignore
    return keyring


def _keyring_error_class():
    """Lazy-resolve the REAL keyring.errors.KeyringError class.

    Prior code had `except KeyringError as e: raise IdentityError(...)` using
    a locally-defined stub class — but real backend errors raised by the
    keyring package inherit from `keyring.errors.KeyringError`, which is a
    separate class hierarchy. Dead-except: backend errors leaked as raw
    `keyring.errors.*` types instead of wrapping to clean IdentityError per
    function contracts. This helper returns the real class so except clauses
    actually match. Falls back to the local stub if keyring isn't installed
    (in that case the import itself raises, no need to catch).
    """
    try:
        import keyring.errors  # type: ignore
        return keyring.errors.KeyringError
    except ImportError:
        return KeyringError


class KeyringError(Exception):
    """Stub for use when keyring isn't installed (its absence makes the
    keyring backend raise ImportError before any KeyringError could fire)."""

KEYRING_SERVICE = "ie.aiegis.agent-sdk"


def _aiegis_home() -> Path:
    """Default $AIEGIS_HOME = ~/.aiegis. Override via env var."""
    home = os.environ.get("AIEGIS_HOME") or str(Path.home() / ".aiegis")
    return Path(home)


def _agents_dir() -> Path:
    d = _aiegis_home() / "agents"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _metadata_path(name: str) -> Path:
    safe = name.replace("/", "_").replace(os.sep, "_")
    if not safe or safe.startswith("."):
        raise IdentityError(f"invalid agent name: {name!r}")
    return _agents_dir() / f"{safe}.json"


@dataclass(frozen=True)
class StoredAgent:
    """Internal representation. SDK.create_agent() wraps this in public Agent."""
    name: str
    did: str
    public_key_hex: str
    operator_id: Optional[str]
    created_at: int
    keyring_user: str  # opaque key-id for keyring lookup


def _keyring_user(name: str) -> str:
    """Per-agent keyring user-id. Stable mapping name -> keyring slot."""
    return f"agent:{name}"


def load(name: str) -> Optional[StoredAgent]:
    """Return StoredAgent if name is known, else None.

    Verifies the keyring entry is still present — a missing keyring slot for
    a known metadata file means the keyring was wiped (user-rotated keychain,
    re-imaged machine). Caller's load_or_create() handles regeneration.
    """
    meta_path = _metadata_path(name)
    if not meta_path.exists():
        return None
    try:
        meta = json.loads(meta_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise IdentityError(f"corrupt metadata at {meta_path}: {e}") from e

    user = meta.get("keyring_user")
    if not user:
        raise IdentityError(f"metadata missing keyring_user: {meta_path}")
    try:
        priv_hex = _keyring().get_password(KEYRING_SERVICE, user)
    except _keyring_error_class() as e:
        raise IdentityError(f"keyring read failed: {e}") from e
    if priv_hex is None:
        return None  # keyring slot gone — let caller re-create

    return StoredAgent(
        name=meta["name"],
        did=meta["did"],
        public_key_hex=meta["public_key_hex"],
        operator_id=meta.get("operator_id"),
        created_at=int(meta["created_at"]),
        keyring_user=user,
    )


def load_private_key(name: str) -> bytes:
    """Read raw 32-byte private key from keyring. Raises IdentityError if missing."""
    user = _keyring_user(name)
    try:
        priv_hex = _keyring().get_password(KEYRING_SERVICE, user)
    except _keyring_error_class() as e:
        raise IdentityError(f"keyring read failed: {e}") from e
    if priv_hex is None:
        raise IdentityError(f"no keyring entry for agent {name!r}")
    try:
        return bytes.fromhex(priv_hex)
    except ValueError as e:
        raise IdentityError(f"keyring entry corrupt: {e}") from e


def create(name: str, operator_id: Optional[str] = None) -> StoredAgent:
    """Generate fresh keypair, store in keyring + write metadata sidecar.

    Raises IdentityError on duplicate name (use delete() first if rotating).
    """
    meta_path = _metadata_path(name)
    if meta_path.exists():
        raise IdentityError(f"agent {name!r} already exists at {meta_path}")

    priv, pub = _crypto.generate_keypair()
    did = _crypto.derive_did(pub)
    user = _keyring_user(name)
    try:
        _keyring().set_password(KEYRING_SERVICE, user, priv.hex())
    except _keyring_error_class() as e:
        raise IdentityError(f"keyring write failed: {e}") from e

    meta = {
        "name": name,
        "did": did,
        "public_key_hex": pub.hex(),
        "operator_id": operator_id,
        "created_at": int(time.time()),
        "keyring_user": user,
        "schema_version": "0.6.1",
    }
    # Write metadata atomically (write-tmp + rename) so a half-write doesn't
    # leave a corrupt JSON file on disk.
    tmp = meta_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(meta, indent=2, sort_keys=True))
    os.chmod(tmp, 0o600)  # metadata includes pubkey + DID — public, but tighten anyway
    tmp.replace(meta_path)

    return StoredAgent(
        name=name,
        did=did,
        public_key_hex=pub.hex(),
        operator_id=operator_id,
        created_at=meta["created_at"],
        keyring_user=user,
    )


def load_or_create(name: str, operator_id: Optional[str] = None) -> StoredAgent:
    """Idempotent — load existing agent or create fresh one."""
    existing = load(name)
    if existing is not None:
        if operator_id is not None and existing.operator_id != operator_id:
            raise IdentityError(
                f"agent {name!r} exists with operator_id={existing.operator_id!r}, "
                f"caller passed {operator_id!r}"
            )
        return existing
    return create(name, operator_id=operator_id)


def delete(name: str) -> bool:
    """Remove keyring entry + metadata file. Returns True if anything was deleted."""
    meta_path = _metadata_path(name)
    user = _keyring_user(name)
    deleted = False
    try:
        _keyring().delete_password(KEYRING_SERVICE, user)
        deleted = True
    except _keyring_error_class():
        pass  # entry may already be gone
    if meta_path.exists():
        meta_path.unlink()
        deleted = True
    return deleted


def list_agents() -> list[StoredAgent]:
    """Return all locally-known agents. Skips entries with missing keyring."""
    out: list[StoredAgent] = []
    for path in _agents_dir().glob("*.json"):
        try:
            agent = load(path.stem)
        except IdentityError:
            continue
        if agent is not None:
            out.append(agent)
    return out
