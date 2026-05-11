# AiEGIS Passport → W3C VC Envelope Export Specification — v0.1

**Authored:** 2026-05-10 ~15:21 IST per Trav directive (4) Research mode + Identity priority
**Composes with:** DID_AIEGIS_METHOD_SPEC_V01.md (sha 62b228a0), v1.8 passport schema (/opt/aegis/specs/cross-lane/agent_passport_schema_v1_8.json)
**External standards:** W3C VC Data Model v2.0 (https://www.w3.org/TR/vc-data-model-2.0/), W3C Ed25519Signature2020 (https://w3c-ccg.github.io/lds-ed25519-2020/)

## Goal

Round-trip-lossless export of an AiEGIS v1.8 passport JSON object into a W3C VC v2.0 envelope, AND import back. Enables AiEGIS-issued passports to flow through any W3C VC verifier (including ones that have never heard of AiEGIS).

## Mapping table — v1.8 passport → VC envelope

| v1.8 passport field    | VC envelope location                        | Notes |
|------------------------|---------------------------------------------|-------|
| `agent_id`             | `credentialSubject.id`                      | Encoded as `did:aiegis:agent:<pubkey-base58btc>` |
| `operator_id`          | `issuer`                                    | Encoded as `did:aiegis:operator:<pubkey-base58btc>` |
| `issued_at`            | `validFrom`                                 | RFC 3339 |
| `expires_at`           | `validUntil`                                | RFC 3339, optional |
| `issuer_kid`           | `proof.verificationMethod`                  | `did:aiegis:operator:<pubkey>#<kid>` |
| `agent_pubkey_pem`     | `credentialSubject.publicKey`               | PEM string preserved verbatim |
| `credentials`          | `credentialSubject.capabilities`            | JSON array, schema-passthrough |
| `risk_classification`  | `credentialSubject.riskClassification`      | enum: low/medium/high/unknown |
| `classification_basis` | `credentialSubject.classificationBasis`     | string |
| `governance_payload`   | `credentialSubject.governancePayload`       | JSON object, schema-passthrough |
| `signature`            | `proof.proofValue`                          | Multibase-encoded Ed25519 sig |
| `proof_of_possession`  | `credentialSubject.proofOfPossession`       | optional |
| `bulk_issue_token`     | `credentialSubject.bulkIssueToken`          | optional |
| `permanent_id_registry_url` | `credentialSubject.permanentIdRegistryUrl` | optional |
| `capability_attestation`    | `credentialSubject.capabilityAttestation`  | optional |
| `classification_reviewed_at` | `credentialSubject.classificationReviewedAt` | optional, RFC 3339 |

## Worked example — v1.8 passport → VC

### Input (v1.8 passport)

```json
{
  "agent_id": "z6MkpzW1yPxQK4yRcS3vN8mF7t9LhJ2dXcEgU3aP4qZmA1bC",
  "operator_id": "z6MkrBdNdwUPnXDVD1DCxedzewNHsR1KpdoMyHHnB3aF9tEX",
  "issued_at": "2026-05-10T15:00:00Z",
  "expires_at": "2027-05-10T15:00:00Z",
  "issuer_kid": "key-1",
  "agent_pubkey_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----",
  "credentials": ["read:agents", "write:transactions"],
  "risk_classification": "low",
  "classification_basis": "auto-classified",
  "governance_payload": {
    "policies": ["EU_AI_ACT", "GDPR", "NIST_AI_RMF"],
    "jurisdiction": "EU"
  },
  "signature": "z3MwbeM..."
}
```

### Output (W3C VC v2.0 envelope)

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "type": ["VerifiableCredential", "AiEGISPassportCredential"],
  "issuer": "did:aiegis:operator:z6MkrBdNdwUPnXDVD1DCxedzewNHsR1KpdoMyHHnB3aF9tEX",
  "validFrom": "2026-05-10T15:00:00Z",
  "validUntil": "2027-05-10T15:00:00Z",
  "credentialSubject": {
    "id": "did:aiegis:agent:z6MkpzW1yPxQK4yRcS3vN8mF7t9LhJ2dXcEgU3aP4qZmA1bC",
    "publicKey": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----",
    "capabilities": ["read:agents", "write:transactions"],
    "riskClassification": "low",
    "classificationBasis": "auto-classified",
    "governancePayload": {
      "policies": ["EU_AI_ACT", "GDPR", "NIST_AI_RMF"],
      "jurisdiction": "EU"
    }
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:aiegis:operator:z6MkrBdNdwUPnXDVD1DCxedzewNHsR1KpdoMyHHnB3aF9tEX#key-1",
    "proofPurpose": "assertionMethod",
    "created": "2026-05-10T15:00:00Z",
    "proofValue": "z3MwbeM..."
  }
}
```

## Round-trip property

The export MUST be lossless: `import(export(passport)) == passport` byte-for-byte after JCS canonicalization (RFC 8785).

Test fixture suite to verify round-trip:
1. Minimal-required-only passport (10 required fields, no optionals)
2. Full-features passport (all 15 properties populated)
3. Edge: expires_at < issued_at (should fail validation in BOTH formats)
4. Edge: governance_payload with nested arrays + nulls
5. Edge: agent_id with non-Ed25519 pubkey (should fail did:aiegis:agent: encoding step)

## Signature handling

The Ed25519 signature MUST be preserved as-is. The VC envelope's `proof.proofValue` carries the same bytes as the v1.8 `signature` field. This means a verifier checking the VC envelope is checking the SAME signature as the AiEGIS dispatcher v1.8 governance-enforce mode.

This avoids re-canonicalizing + re-signing during export, which would double the trust-root surface.

## Implementation

```python
def passport_v1_8_to_vc_envelope(passport: dict) -> dict:
    return {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "type": ["VerifiableCredential", "AiEGISPassportCredential"],
        "issuer": f"did:aiegis:operator:{passport['operator_id']}",
        "validFrom": passport["issued_at"],
        "validUntil": passport.get("expires_at"),
        "credentialSubject": {
            "id": f"did:aiegis:agent:{passport['agent_id']}",
            "publicKey": passport["agent_pubkey_pem"],
            "capabilities": passport["credentials"],
            "riskClassification": passport["risk_classification"],
            "classificationBasis": passport["classification_basis"],
            "governancePayload": passport["governance_payload"],
            **{
                k: passport[v] for k, v in {
                    "proofOfPossession": "proof_of_possession",
                    "bulkIssueToken": "bulk_issue_token",
                    "permanentIdRegistryUrl": "permanent_id_registry_url",
                    "capabilityAttestation": "capability_attestation",
                    "classificationReviewedAt": "classification_reviewed_at",
                }.items() if v in passport
            }
        },
        "proof": {
            "type": "Ed25519Signature2020",
            "verificationMethod": f"did:aiegis:operator:{passport['operator_id']}#{passport['issuer_kid']}",
            "proofPurpose": "assertionMethod",
            "created": passport["issued_at"],
            "proofValue": passport["signature"]
        }
    }

def vc_envelope_to_passport_v1_8(vc: dict) -> dict:
    cs = vc["credentialSubject"]
    return {
        "agent_id": cs["id"].replace("did:aiegis:agent:", ""),
        "operator_id": vc["issuer"].replace("did:aiegis:operator:", ""),
        "issued_at": vc["validFrom"],
        "expires_at": vc.get("validUntil"),
        "issuer_kid": vc["proof"]["verificationMethod"].split("#", 1)[1],
        "agent_pubkey_pem": cs["publicKey"],
        "credentials": cs["capabilities"],
        "signature": vc["proof"]["proofValue"],
        "risk_classification": cs["riskClassification"],
        "classification_basis": cs["classificationBasis"],
        "governance_payload": cs["governancePayload"],
        **{
            k: cs[v] for k, v in {
                "proof_of_possession": "proofOfPossession",
                "bulk_issue_token": "bulkIssueToken",
                "permanent_id_registry_url": "permanentIdRegistryUrl",
                "capability_attestation": "capabilityAttestation",
                "classification_reviewed_at": "classificationReviewedAt",
            }.items() if v in cs
        }
    }
```

~50 lines of code, ~30 lines of test fixtures. Estimated 1 day to implement + test. Velo lane (alongside DID resolver).

## Open questions for v0.2

1. Should `governancePayload` be exported as a separate `credentialSubject` field, or as a `termsOfUse` attribute (W3C VC has dedicated semantics for terms-of-use)?
2. Round-trip-lossy edge: VC envelope's `@context` array order vs original passport's lack of context — JCS canonicalization treats array-order as semantic. Decision: import side strips `@context` before canonicalize-compare.
3. Should AiEGIS dispatcher v1.8 also accept VC envelope INPUT directly (currently only accepts native passport JSON)? Tradeoff: bigger attack surface, but interoperability win.

## Crypto-agility (forward-compat with v0.7+ PQC)

v0.1 envelope uses `Ed25519Signature2020` exclusively. v0.7+ will introduce `AiegisHybridSignature2026` which carries Ed25519 AND ML-DSA-65 in a single proof object. See `DID_AIEGIS_METHOD_SPEC_V01.md` Crypto-agility section + `research/2026-05-10_pqc_migration_for_did_aiegis.md` for the migration plan. Implementation guidance for envelope export tooling:

- `proof.type` MUST be parsed as a string and dispatched to the verifier matching that algorithm. Never assume Ed25519.
- Unknown `proof.type` MUST cause REJECT, not silent-accept. (Closes downgrade-attack window.)
- Round-trip identity: when a v0.7+ hybrid envelope is imported, the v0.1 import path MUST strip the `postQuantum` proof component before JCS canonicalization to preserve byte-identity with the original v1.8 passport. This is acceptable because v1.8 passports never carried PQC anyway.

## Compose with existing infra

- v1.8 dispatcher governance-enforce mode → reads `credentialSubject.governancePayload` exactly as it currently reads `governance_payload`
- v1.8 signature enforce → verifies `proof.proofValue` exactly as it currently verifies `signature` field
- Revocation registry at /registry/revocations → keyed on `agent_id` which maps directly to last segment of `credentialSubject.id` after `did:aiegis:agent:` prefix strip
