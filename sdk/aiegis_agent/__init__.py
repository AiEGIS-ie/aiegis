"""
AiEGIS Agent SDK — one-line did:aiegis identity for AI agents.

Quick start:

    import aiegis_agent

    agent = aiegis_agent.create_agent(name="MyBot")
    agent.did             # 'did:aiegis:abc...'
    agent.sign(payload)   # Ed25519 signature
    agent.passport()      # signed passport for /api/agent/issue
"""

__version__ = "0.6.3"

from aiegis_agent.sdk import create_agent, Agent
from aiegis_agent.errors import AiegisError, IdentityError, NetworkError

# Compliance integration is lazy-imported via PEP 562 __getattr__. The
# compliance module's import-time path-resolution can raise ImportError
# when AIEGIS_COMPLIANCE_PATH is mis-set; eager-importing here would make
# every aiegis_agent import crash on broken env (including unrelated CLI
# subcommands). Lazy-import keeps the package usable for callers that
# don't touch compliance, while build/verify_compliance_bundle still
# fail-loud at first access. (Nel regression-catch 2026-05-10 22:53.)
_LAZY_NAMES = {"build_compliance_bundle", "verify_compliance_bundle", "HAS_COMPLIANCE"}


def __getattr__(name):
    if name in _LAZY_NAMES:
        from aiegis_agent import compliance  # may raise ImportError on bad env
        return getattr(compliance, name)
    raise AttributeError(f"module 'aiegis_agent' has no attribute {name!r}")


__all__ = [
    "__version__",
    "create_agent",
    "Agent",
    "AiegisError",
    "IdentityError",
    "NetworkError",
    "build_compliance_bundle",
    "verify_compliance_bundle",
    "HAS_COMPLIANCE",
]
