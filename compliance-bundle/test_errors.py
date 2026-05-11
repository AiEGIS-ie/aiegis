"""Regression-lock for IdentityError both-worlds contract."""

from errors import IdentityError
from error_codes import ErrorCode


def test_code_required_must_be_enum():
    try:
        IdentityError("LINKAGE_MISMATCH", "string-not-enum")
    except TypeError:
        return
    raise AssertionError("expected TypeError when code is str, not ErrorCode")


def test_code_rejects_int():
    try:
        IdentityError(42, "int-not-enum")
    except TypeError:
        return
    raise AssertionError("expected TypeError when code is int")


def test_code_rejects_none():
    try:
        IdentityError(None, "none-not-enum")
    except TypeError:
        return
    raise AssertionError("expected TypeError when code is None")


def test_code_rejects_errorcode_class_itself():
    # Passing the class instead of an instance is a common typo.
    try:
        IdentityError(ErrorCode, "class-not-instance")
    except TypeError:
        return
    raise AssertionError("expected TypeError when code is ErrorCode class (not instance)")


def test_detail_optional():
    e = IdentityError(ErrorCode.SHAPE_INVALID)
    assert e.code is ErrorCode.SHAPE_INVALID
    assert e.detail == ""
    assert str(e) == "SHAPE_INVALID"


def test_detail_renders_in_str():
    e = IdentityError(ErrorCode.LINKAGE_MISMATCH, "vm mismatch")
    assert str(e) == "LINKAGE_MISMATCH: vm mismatch"


def test_to_dict_shape():
    e = IdentityError(ErrorCode.WINDOW_EXPIRED, "issued 8d ago, max 7d")
    d = e.to_dict()
    assert d == {"error_code": "WINDOW_EXPIRED", "detail": "issued 8d ago, max 7d"}
    assert set(d.keys()) == {"error_code", "detail"}


def test_is_exception_subclass():
    assert issubclass(IdentityError, Exception)
    try:
        raise IdentityError(ErrorCode.PROOF_MISSING)
    except Exception:
        return
    raise AssertionError("should be catchable as Exception")


def test_detail_strips_control_chars():
    e = IdentityError(ErrorCode.SHAPE_INVALID, "line1\nline2\x00\x07tab\there space")
    assert "\n" not in e.detail
    assert "\x00" not in e.detail
    assert "\x07" not in e.detail
    assert "\t" not in e.detail  # 0x09 also stripped
    assert " " in e.detail  # space preserved


def test_detail_replaces_controls_with_space_not_underscore():
    # Regression-lock per Nel refine 2026-05-11 lap 108: underscore corrupts
    # semantic tokens (error_code → error_code). Must replace with space.
    e = IdentityError(ErrorCode.SHAPE_INVALID, "error\ncode")
    assert "_" not in e.detail, f"underscore leaked into sanitized detail: {e.detail!r}"
    assert e.detail == "error code"


def test_detail_truncates_at_cap():
    long = "A" * 1000
    e = IdentityError(ErrorCode.SHAPE_INVALID, long)
    assert len(e.detail) == 512
    assert e.detail.endswith("... [truncated]")


def test_from_exception_captures_type_name_only():
    try:
        raise ValueError("operator-secret-token-leak-12345")
    except ValueError as e:
        wrapped = IdentityError.from_exception(e, ErrorCode.SHAPE_INVALID)
    assert wrapped.code is ErrorCode.SHAPE_INVALID
    assert wrapped.detail == "ValueError"
    # The original exception message MUST NOT leak — pin discipline.
    assert "operator-secret-token-leak" not in wrapped.detail
    assert "operator-secret-token-leak" not in str(wrapped)


def test_attributes_frozen_post_init():
    e = IdentityError(ErrorCode.LINKAGE_MISMATCH, "x")
    try:
        e.code = ErrorCode.SHAPE_INVALID
    except AttributeError:
        pass
    else:
        raise AssertionError("expected AttributeError when mutating .code post-init")
    try:
        e.detail = "rewritten"
    except AttributeError:
        pass
    else:
        raise AssertionError("expected AttributeError when mutating .detail post-init")
    # Values must be unchanged after failed mutation attempts.
    assert e.code is ErrorCode.LINKAGE_MISMATCH
    assert e.detail == "x"


def test_no_arbitrary_attributes_post_init():
    e = IdentityError(ErrorCode.SHAPE_INVALID)
    try:
        e.sneaky = "value"
    except AttributeError:
        return
    raise AssertionError("expected AttributeError when adding arbitrary attribute post-init")


def test_from_exception_default_code():
    wrapped = IdentityError.from_exception(RuntimeError("x"))
    assert wrapped.code is ErrorCode.SHAPE_INVALID
    assert wrapped.detail == "RuntimeError"


def test_code_attribute_is_enum_not_string():
    # Integrator branching contract: e.code is the enum, e.code.value is the string.
    e = IdentityError(ErrorCode.SIGNATURE_INVALID, "ed25519 verify failed")
    assert isinstance(e.code, ErrorCode)
    assert e.code.value == "SIGNATURE_INVALID"


if __name__ == "__main__":
    test_code_required_must_be_enum()
    test_code_rejects_int()
    test_code_rejects_none()
    test_code_rejects_errorcode_class_itself()
    test_detail_optional()
    test_detail_renders_in_str()
    test_to_dict_shape()
    test_is_exception_subclass()
    test_detail_strips_control_chars()
    test_detail_replaces_controls_with_space_not_underscore()
    test_detail_truncates_at_cap()
    test_from_exception_captures_type_name_only()
    test_from_exception_default_code()
    test_attributes_frozen_post_init()
    test_no_arbitrary_attributes_post_init()
    test_code_attribute_is_enum_not_string()
    print("16/16 PASS — IdentityError both-worlds + hardened detail + from_exception + frozen-attrs + non-enum-rejection green")
