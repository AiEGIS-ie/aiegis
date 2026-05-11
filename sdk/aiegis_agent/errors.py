"""Exception hierarchy for the AiEGIS Agent SDK."""


class AiegisError(Exception):
    """Base class for all SDK errors."""


class IdentityError(AiegisError):
    """Identity creation, key load/save, or DID resolution failed."""


class NetworkError(AiegisError):
    """Network call to /api/agent/* failed (unreachable, 5xx, malformed response)."""
