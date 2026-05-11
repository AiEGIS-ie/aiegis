"""Append-only stability contract regression-lock for error_codes.ErrorCode.

Post-v0.8 GA, codes are append-only. Renames/removals break external
integrator branching. This test fails loud if either happens.

To add a code: append to ErrorCode + append to EXPECTED below. Never reorder,
never remove, never rename.
"""

from error_codes import ErrorCode


EXPECTED_V08 = frozenset({
    "SHAPE_INVALID",
    "EVENT_ID_DUPLICATE",
    "DECISION_ENUM_INVALID",
    "POLICY_BUNDLE_HEX_INVALID",
    "CHARSET_VIOLATION",
    "LENGTH_CAP_EXCEEDED",
    "EVENT_COUNT_CAP_EXCEEDED",
    "TIMESTAMP_INVALID",
    "WINDOW_EXPIRED",
    "OPERATOR_DID_TIER_MISMATCH",
    "LINKAGE_MISMATCH",
    "SIGNATURE_INVALID",
    "KEY_FORMAT_INVALID",
    "PROOF_MISSING",
    "PROOFVALUE_EMPTY",
    "PROOFVALUE_TOO_LONG",
    "PROOFVALUE_HEX_INVALID",
    "CANONICALIZATION_FAILED",
    "SUBSTRATE_ATTESTATION_STALE",
    "SUBSTRATE_ATTESTATION_INVALID",
    "TPM_QUOTE_SIG_INVALID",
    "TPM_PCR_MISMATCH",
    "APPLE_SE_RP_ID_MISMATCH",
    "APPLE_SE_COUNTER_REPLAY",
    "TEE_VENDOR_UNSUPPORTED",
    "TEE_REPORT_HASH_INVALID",
    "NONCE_REPLAY",
    "OPERATOR_REGISTRY_LOOKUP_FAILED",
    "HOST_FINGERPRINT_BINDING_DRIFT",
})


V08_COUNT = 29  # bump deliberately when adding codes — forces PR-visible diff


def test_v08_codes_present():
    actual = {c.value for c in ErrorCode}
    missing = EXPECTED_V08 - actual
    assert not missing, f"v0.8 stability contract broken — codes removed/renamed: {missing}"


def test_count_matches_declared():
    # Closes silent-additive-drift gap: an APPEND that forgets EXPECTED_V08 + V08_COUNT
    # bump would otherwise pass the subset check. This forces explicit acknowledgement.
    actual_count = len(list(ErrorCode))
    expected_in_set = len(EXPECTED_V08)
    assert actual_count == V08_COUNT == expected_in_set, (
        f"count drift: ErrorCode has {actual_count}, V08_COUNT={V08_COUNT}, "
        f"EXPECTED_V08 has {expected_in_set}. Bump all three together when adding codes."
    )


def test_codes_are_string_enum():
    for c in ErrorCode:
        assert isinstance(c.value, str)
        assert c.value == c.name, f"{c.name} value drifted from name ({c.value})"


def test_codes_are_screaming_snake_case():
    import re
    for c in ErrorCode:
        assert re.fullmatch(r"[A-Z][A-Z0-9_]*", c.value), c.value


def test_no_duplicate_values():
    values = [c.value for c in ErrorCode]
    assert len(values) == len(set(values))


if __name__ == "__main__":
    test_v08_codes_present()
    test_count_matches_declared()
    test_codes_are_string_enum()
    test_codes_are_screaming_snake_case()
    test_no_duplicate_values()
    print(f"5/5 PASS — {len(list(ErrorCode))} codes, stability contract green")
