# Security Policy

## Reporting a vulnerability

If you find a vulnerability in AiEGIS — the spec, reference implementation, SDK, or compliance-bundle code — please disclose responsibly:

- **Email:** security@aiegis.ie
- **Response SLA:** initial acknowledgement within 72 hours, triage within 7 days

Please do **not** open a public issue for security reports. Use email first; we will coordinate public disclosure.

## Scope

In scope:

- Substrate-binding bypass (forge a signed action without the bound hardware key)
- Operator-key compromise paths in the reference custody design
- Replay / freshness-window attacks on attestation or BindingProof
- ReDoS / DoS in the parsing or canonicalization code paths
- Side-channel leaks in signature verification or detail-sanitization
- JSON-LD context-injection or RDFC/JCS canonicalization mismatches
- Pickle / deserialization issues in `IdentityError` or `SubstrateError`
- Smuggling attacks via control-character or quote-escape in JSON-LD bundles

Out of scope:

- Vulnerabilities in dependent libraries (report upstream; we will track)
- Issues requiring physical access to the host (substrate threat model documents this)
- Social engineering of operator-key custodians
- Hypervisor / firmware compromise on cloud TEEs (falls to vendor-attested tier)

## Hall of fame

Researchers who responsibly disclose receive credit here (with permission) and in the relevant release notes.

## Disclosure timeline

- Day 0 — researcher reports privately
- Day 1–7 — triage, internal fix, severity assessment
- Day 7–30 — patch landed in main, design-partner notification
- Day 30–90 — public advisory + CVE if applicable, coordinated release

## Crypto attestation

Our trust root is held in 2-of-3 Shamir + YubiHSM 2 (FIPS 140-2 L3 cert #3916 sunset 2026-05-02 per CMVP; FIPS 140-3 transition expected per Yubico Q2 2026). Key rotation requires multi-party ceremony. We do not single-handedly hold the ability to revoke or re-issue any identity.

## Standards

We track and contribute to:

- W3C DID Core 1.0
- W3C VC Data Model 2.0
- IETF RFC 8785 (JCS canonicalization)
- NIST FIPS 204 (ML-DSA) for hybrid PQC
- OWASP AIVSS — issues #31 / #32 / #33
