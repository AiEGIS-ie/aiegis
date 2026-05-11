"""Identity error with structured code + freeform detail (both-worlds pattern).

Closes the steelman-alternative gap: integrators get enum-stable .code for
branching AND human-readable .detail for debugging. The detail string MUST NOT
leak exception messages — only call-site-controlled context (offending field
name, length, etc.). Never embed user/customer values verbatim.

v0.8 prep. Pending Nel ratify + merge into generator.py raises.
"""

from typing import Optional

from error_codes import ErrorCode


MAX_DETAIL_LEN = 512
_TRUNC_MARKER = "... [truncated]"


def _sanitize_detail(raw: str) -> str:
    # Strip ASCII C0 controls + DEL (0x00-0x1F + 0x7F), preserve space.
    # Defends against log-forging via injected \n / \r and JSON-render breakage via NUL.
    cleaned = "".join(" " if (ord(c) < 0x20 or ord(c) == 0x7F) else c for c in raw)
    if len(cleaned) > MAX_DETAIL_LEN:
        keep = MAX_DETAIL_LEN - len(_TRUNC_MARKER)
        cleaned = cleaned[:keep] + _TRUNC_MARKER
    return cleaned


class IdentityError(ValueError):  # Option β — subclass ValueError so 53 existing test catches keep passing during incremental migration
    """Raised on compliance-bundle / passport verification failure.

    Attributes (.code, .detail) are frozen post-init. Mutation raises
    AttributeError — downstream consumers can rely on stable values.
    """

    _frozen = False
    # Exception parent provides __dict__ so __slots__=() is decorative here;
    # the freeze actually comes from the __setattr__ guard below. Kept as
    # signal-of-intent per Nel lap-127 doc-coherence note.
    __slots__ = ()

    def __init__(self, code: ErrorCode, detail: Optional[str] = None) -> None:
        if not isinstance(code, ErrorCode):
            raise TypeError(f"code must be ErrorCode, got {type(code).__name__}")
        # Bypass our own __setattr__ guard for these two writes.
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "detail", _sanitize_detail(detail) if detail else "")
        super().__init__(f"{code.value}: {self.detail}" if self.detail else code.value)
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_frozen", False):
            raise AttributeError(f"{type(self).__name__} is frozen post-init; cannot set {name!r}")
        object.__setattr__(self, name, value)

    def __repr__(self) -> str:
        # F19 — use type(self).__name__ so SubstrateError repr is correct.
        return f"{type(self).__name__}(code={self.code.value!r}, detail={self.detail!r})"

    def __reduce__(self):
        # F18 — pickle round-trip past __setattr__ freeze.
        # Default __reduce__ would call __setattr__ to restore state and hit the freeze guard.
        return (self.__class__, (self.code, self.detail))

    def to_dict(self) -> dict:
        """Serializable form for API responses / log records."""
        return {"error_code": self.code.value, "detail": self.detail}

    @classmethod
    def from_exception(cls, exc: BaseException, code: ErrorCode = ErrorCode.SHAPE_INVALID) -> "IdentityError":
        """Wrap an unexpected exception. Detail captures type-name only — never message.

        Use in generator.py call-sites:
            try:
                json.loads(...)
            except (ValueError, TypeError) as e:
                raise IdentityError.from_exception(e, ErrorCode.SHAPE_INVALID) from e
        """
        return cls(code, detail=type(exc).__name__)


class SubstrateError(IdentityError):
    """Raised by substrate verifiers (TPM / Apple SE / Intel TDX / AMD SEV-SNP / acquirer).

    Sibling-by-inheritance of IdentityError: integrators can catch SubstrateError
    specifically OR catch IdentityError to cover both. Same hardened detail
    contract (sanitize + cap) applies.
    """


__all__ = ["IdentityError", "SubstrateError", "MAX_DETAIL_LEN"]
