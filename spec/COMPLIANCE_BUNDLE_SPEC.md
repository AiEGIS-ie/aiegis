# AiEGIS v0.7 — Article 50 Compliance Bundle Spec (DRAFT)

**Authored:** 2026-05-10 19:21 IST by Velo. Anchor for tomorrow's full draft.
**Companion:** Nel's `2026-05-10_pqc_migration_did_aiegis_plan.md` (sha 63a93ba6) + BEACON_CONTRACT v1.1 (sha 86edd08b).

## Purpose

Given a sequence of BEACON verdict events from a customer's AiEGIS deployment,
emit a signed governance-report bundle that the customer hands to EU regulators
(or any third-party auditor) as proof-of-compliance with EU AI Act Article 50.

Hyperscaler-gap exploit per Nel competitor matrix (sha cb453ba7): MS Entra Agent
ID + Google Gemini Agent Identity + AWS Bedrock AgentCore Identity all provide
IAM-Principal cryptographic binding but NONE emit machine-readable signed-event
markers for governance verdicts. Article 50 compliance is the AiEGIS wedge.

## Wire format

Primary: **JSON-LD** per W3C Verifiable Credentials data model with Bitstring
Status List shape. Code of Practice June-2026 schema is expected to prescribe
JSON-LD; CBOR-only locks AiEGIS out of ecosystem-interop.

Optional: CBOR encoding for size-constrained transports (mobile, IoT) — must
be canonical-form (RFC 8949 §4.2) for byte-identity guarantees.

## Bundle shape (v0.1 draft)

```jsonld
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://aiegis.ie/ns/compliance/v1"
  ],
  "type": ["VerifiableCredential", "AiEGISComplianceBundle"],
  "issuer": "did:aiegis:operator:z6Mk...",
  "validFrom": "2026-08-01T00:00:00Z",
  "validUntil": "2026-08-31T23:59:59Z",
  "credentialSubject": {
    "id": "did:aiegis:customer:z6Mk...",
    "complianceWindow": {
      "start": "2026-08-01T00:00:00Z",
      "end": "2026-08-31T23:59:59Z"
    },
    "verdictEvents": [
      { "eventId": "...", "decision": "block", "rule": "pi.ignore_previous", "timestamp": "...", "signature": "..." }
    ],
    "policyBundle": {
      "rulesRsSha256": "<sha256 of classifier/src/rules.rs>",
      "libRsSha256": "<sha256 of classifier/src/lib.rs>",
      "policyJsonSha256": "<sha256 of operator policy.json>",
      "binarySha256": "<sha256 of compiled aiegis-host binary>"
    },
    "classifierVersion": "0.6.6"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ml-dsa-65+ed25519-hybrid",
    "_cryptosuite_pinned_to": "PROVISIONAL — align when W3C VC Data Integrity WG hybrid-PQC draft lands",
    "created": "2026-09-01T00:00:00Z",
    "verificationMethod": "did:aiegis:operator:z6Mk...#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "<hybrid-signature>"
  }
}
```

## Signature

Per Nel PQC migration plan (sha 63a93ba6): **hybrid Ed25519+ML-DSA-65** for
v0.7 — defends harvest-now-decrypt-later for the 10-15yr audit lifespan.
Pure Ed25519 fails by 2030 against quantum CRQC.

## Operator-key custody side

Per identity v0.1 spec, the signer is the operator key (`did:aiegis:operator:z6Mk...`)
not the customer key. Customer cannot forge a compliance bundle on their own behalf;
operator attests on customer's behalf. Matches Nel's higher-PQC-priority flag on
BSL-class credentials.

## What's NOT in this draft yet

- Status list (revocation of compliance claims)
- Multi-customer batch bundles (one regulator submission = N customers)
- Cross-DID resolution for non-AiEGIS issuers (W3C Verifiable Issuer Registry)
- Bundle size limits + paging (Article 50 spec may set ceilings)
- Test fixtures + cargo/python verifier impl

## Audit flags from Nel cross-review (queued for tomorrow)

- [ ] **@context URL 404 fix:** `https://aiegis.ie/ns/compliance/v1` returns 404 — entire `/ns/*` path 404. W3C verifiers will fail JSON-LD context dereference. Must publish context doc at that path OR change to a working URL before any real bundle ships.
- [ ] **Rate-limit key derivation host-attested:** api_v2.py:167 currently reads X-AiEGIS-Key / X-Agent-Id headers for rate-limit keying. Auth itself uses operator-signed passports (correct), but rate-limit dimension is spoofable per-request. When v0.7 fingerprint-architecture ships, rate-limit key MUST also consume host-attested binding — otherwise fingerprint-bound agent still games rate-limits via bearer-header lie.

## TBD tomorrow

- [ ] Full v0.7 spec authoring (sections 1-6 + open questions)
- [ ] Hybrid signature implementation sketch in `aiegis-agent-sdk-python`
- [ ] Bundle generator stub + 3-fixture test pack
- [ ] Cross-pin with Nel's PQC migration + AIVSS §3.2 + identity v0.1

## Open questions (parking)

1. Bundle-per-month vs bundle-per-incident? Article 50 unclear; lean monthly + on-demand-export.
2. Customer-controlled revocation (BSL bit) — who can revoke?
3. ~~JSON-LD canonicalization scheme: URDNA2015 (current W3C standard) or wait for RDFC-1.0 (2026-Q3)?~~ RESOLVED 2026-05-10 per Nel audit-flag-1: RDFC-1.0 already W3C-published Feb 2026 (URDNA2015 is deprecated alias). Use RDFC-1.0 from day one.
4. Compliance-bundle issuer key = operator-key (per identity v0.1) — OR new dedicated compliance-issuer key with different rotation policy?

— Velo, 2026-05-10 19:21 IST DRAFT
