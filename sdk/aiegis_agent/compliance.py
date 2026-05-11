"""
Compliance bundle integration — re-export of the aiegis-compliance-bundle
generator + verifier, scoped to operate naturally from an Agent instance.

Lets SDK consumers do:

    import aiegis_agent
    agent = aiegis_agent.create_agent(name="audit-bot", operator_id="acme")
    bundle = agent.build_compliance_bundle(events=..., customer_did=..., ...)

without having to know the standalone compliance-bundle package exists.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# Resolve the compliance-bundle package path. Customer-onboarding contract:
# set AIEGIS_COMPLIANCE_PATH to point at the directory containing generator.py.
# Falls back to the local dev path (/Users/velo/...) only when env unset AND
# that path actually exists — otherwise fails loud at import-time with a
# clear error message instead of silent HAS_COMPLIANCE=False at call-time.
_DEV_FALLBACK_PATH = Path("/Users/velo/Documents/VELO/aiegis-compliance-bundle")


def _resolve_compliance_path() -> Optional[Path]:
    env_path = os.environ.get("AIEGIS_COMPLIANCE_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p
        # Loud fail: env was set but path doesn't resolve. Don't silently
        # downgrade to dev fallback — that masks a customer mis-config.
        raise ImportError(
            f"AIEGIS_COMPLIANCE_PATH={env_path!r} does not exist; "
            f"set it to the directory containing the aiegis-compliance-bundle "
            f"generator.py (see README onboarding)."
        )
    if _DEV_FALLBACK_PATH.exists():
        return _DEV_FALLBACK_PATH
    return None


_COMPLIANCE_PATH = _resolve_compliance_path()
if _COMPLIANCE_PATH is not None and str(_COMPLIANCE_PATH) not in sys.path:
    sys.path.insert(0, str(_COMPLIANCE_PATH))

try:
    from generator import (  # type: ignore
        BeaconEvent,
        build_bundle as _build_bundle,
        verify_bundle as _verify_bundle,
    )
    HAS_COMPLIANCE = True
except ImportError as _err:
    HAS_COMPLIANCE = False
    BeaconEvent = None  # type: ignore
    # Surface the missing-path case explicitly so first-5-min onboarding UX
    # tells the customer what to set. Otherwise a downstream call to
    # build_compliance_bundle gets a vague ImportError.
    if _COMPLIANCE_PATH is None:
        # Don't raise at module-import time (consumers may not use compliance
        # at all). Cache the error for build_compliance_bundle to surface.
        _IMPORT_ERROR = (
            "aiegis-compliance-bundle package not found. "
            "Set AIEGIS_COMPLIANCE_PATH=/path/to/aiegis-compliance-bundle "
            "(see README onboarding) before importing aiegis_agent.compliance."
        )
    else:
        _IMPORT_ERROR = (
            f"aiegis-compliance-bundle path resolved to {_COMPLIANCE_PATH} "
            f"but generator.py import failed: {_err}"
        )
else:
    _IMPORT_ERROR = None


def build_compliance_bundle(
    agent,
    events: List["BeaconEvent"],
    customer_did: str,
    valid_from: datetime,
    valid_until: datetime,
    policy_bundle: dict,
    substrate_attestation: Optional[dict] = None,
) -> dict:
    """Build a signed Article 50 Compliance Bundle on behalf of an Agent.

    The Agent's keypair is used to sign (operator-key custody per spec).
    Caller supplies customer_did + window + policy hashes.

    Raises ImportError if the compliance bundle package isn't on path.
    """
    if not HAS_COMPLIANCE:
        raise ImportError(_IMPORT_ERROR or
            "aiegis-compliance-bundle not on PYTHONPATH; install or set "
            "AIEGIS_COMPLIANCE_PATH to point at the package directory."
        )
    # Load private key for signing
    from aiegis_agent import _storage  # type: ignore
    priv = _storage.load_private_key(agent.name)
    return _build_bundle(
        events=events,
        operator_priv=priv,
        operator_did=agent.did,
        customer_did=customer_did,
        valid_from=valid_from,
        valid_until=valid_until,
        classifier_version="0.6.6",  # v0.8: read from agent metadata
        policy_bundle=policy_bundle,
        substrate_attestation=substrate_attestation,
    )


def verify_compliance_bundle(bundle: dict, operator_pub: bytes) -> bool:
    """Verify a compliance bundle against an operator public key."""
    if not HAS_COMPLIANCE:
        raise ImportError(_IMPORT_ERROR or
            "aiegis-compliance-bundle not on PYTHONPATH"
        )
    return _verify_bundle(bundle, operator_pub)


def _main_doctor() -> int:
    """CLI health-check: run `python -m aiegis_agent.compliance` to verify
    customer setup before calling build_compliance_bundle. Prints the
    resolved path + import status + actionable next-step. Returns 0 if OK,
    1 if compliance integration unavailable."""
    print("aiegis-compliance-bundle integration check")
    print("=" * 50)
    env_path = os.environ.get("AIEGIS_COMPLIANCE_PATH")
    print(f"AIEGIS_COMPLIANCE_PATH env var: {env_path or '(unset)'}")
    print(f"Resolved compliance path:        {_COMPLIANCE_PATH or '(not resolved)'}")
    print(f"HAS_COMPLIANCE:                  {HAS_COMPLIANCE}")
    if HAS_COMPLIANCE:
        print("\n✓ Integration ready. Imports working:")
        print(f"  - BeaconEvent:           {BeaconEvent}")
        print(f"  - build_compliance_bundle: available")
        print(f"  - verify_compliance_bundle: available")
        return 0
    else:
        print("\n✗ Integration NOT ready.")
        print(f"  Reason: {_IMPORT_ERROR or 'unknown'}")
        print("\nNext step:")
        print("  1. Clone aiegis-compliance-bundle to a directory you control")
        print("  2. export AIEGIS_COMPLIANCE_PATH=/that/directory")
        print("  3. Re-run: python -m aiegis_agent doctor")
        return 1


if __name__ == "__main__":
    sys.exit(_main_doctor())
