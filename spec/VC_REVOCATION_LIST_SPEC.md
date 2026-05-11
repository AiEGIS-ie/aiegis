# AiEGIS VC Revocation List Endpoint — v0.1

**Authored:** 2026-05-10 ~15:29 IST per directive-(4) Identity research-mode + did:aiegis v0.1 open question 4
**Composes with:** DID_AIEGIS_METHOD_SPEC_V01.md (sha 62b228a0), VC_ENVELOPE_EXPORT_SPEC_V01.md (sha 709af301), existing /registry/revocations endpoint
**External standards:** W3C VC Bitstring Status List v1.0 (https://www.w3.org/TR/vc-bitstring-status-list/ verified 200), W3C VC Data Model v2.0

## Question (from did:aiegis v0.1 open Q4)

Verifiable Credentials revocation list endpoint shape — bitstring-list (W3C standard) vs custom registry-pull endpoint?

## Decision: dual-shape, bitstring-list as W3C-interop layer over native registry

**Native endpoint (already shipping):** `GET /registry/revocations` returns JSON array of revoked agent_ids. Custom shape, used by AiEGIS dispatcher v1.8 governance-enforce.

**New W3C-interop endpoint (v0.2 TO-BUILD):** `GET /registry/status-list/v1` returns W3C VC Bitstring Status List Credential. Same revocation data, different envelope.

Rationale: native endpoint is already operationally proven (v1.8 dispatcher reads it daily). BSL endpoint is a translation layer — it does NOT replace the native endpoint, it ADDS a W3C-compatible view. Dual-shape lets us serve both AiEGIS-native verifiers + W3C VC ecosystem verifiers without forking the data model.

## W3C Bitstring Status List shape

Per W3C VC BSL v1.0:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "https://aiegis.ie/registry/status-list/v1",
  "type": ["VerifiableCredential", "BitstringStatusListCredential"],
  "issuer": "did:aiegis:operator:<aiegis-root-pubkey>",
  "validFrom": "2026-05-10T15:00:00Z",
  "credentialSubject": {
    "id": "https://aiegis.ie/registry/status-list/v1#list",
    "type": "BitstringStatusList",
    "statusPurpose": "revocation",
    "encodedList": "<base64url-encoded-gzipped-bitstring>"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:aiegis:operator:<pubkey>#status-list-key",
    "proofPurpose": "assertionMethod",
    "created": "2026-05-10T15:00:00Z",
    "proofValue": "z3..."
  }
}
```

The `encodedList` is a gzip-compressed bitstring where bit-N is set if the credential at index N is revoked. Default minimum: 16KB uncompressed (131,072 bits → can index 131K credentials).

## Mapping native → BSL

To map AiEGIS's native revocation list to BSL, each revoked passport needs a stable index. Two strategies:

### Strategy A: index = hash of agent_id

```python
def credential_index(agent_id: str, list_size: int = 131072) -> int:
    import hashlib
    h = hashlib.sha256(agent_id.encode()).digest()
    return int.from_bytes(h[:4], "big") % list_size
```

Pros: deterministic, no central-counter coordination. Cons: collisions (~50% probability at 64K credentials per birthday-paradox). Recommendation: use SHA-256 truncated to 64 bits + pre-allocated size of 2M+ credentials to keep collision probability < 0.01%.

### Strategy B: index = monotonic counter

Each issued passport gets a counter-incremented index stored in DB. Pros: zero collisions. Cons: requires central counter, makes offline issuance harder.

**Recommendation: Strategy A** — collision-tolerant + offline-issuable. Add `statusListIndex` to v1.8 passport schema (optional field, deterministic from agent_id).

## VC envelope reference to status list

When AiEGIS issues a VC envelope per `VC_ENVELOPE_EXPORT_SPEC_V01.md`, it adds a `credentialStatus` reference:

```json
"credentialStatus": {
  "id": "https://aiegis.ie/registry/status-list/v1#<index>",
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": "<index>",
  "statusListCredential": "https://aiegis.ie/registry/status-list/v1"
}
```

W3C VC verifiers see this, fetch the BSL endpoint, decode the bitstring, check bit at `statusListIndex`. Standard W3C flow.

## Implementation

```python
import gzip, base64, hashlib

LIST_SIZE = 131072  # 16KB / 8 bits

def credential_index(agent_id: str) -> int:
    h = hashlib.sha256(agent_id.encode()).digest()
    return int.from_bytes(h[:4], "big") % LIST_SIZE

def build_bitstring_status_list(revoked_agent_ids: list[str]) -> str:
    bits = bytearray(LIST_SIZE // 8)
    for aid in revoked_agent_ids:
        idx = credential_index(aid)
        byte_idx = idx // 8
        bit_idx = idx % 8
        bits[byte_idx] |= (1 << bit_idx)
    compressed = gzip.compress(bytes(bits))
    return base64.urlsafe_b64encode(compressed).decode().rstrip("=")
```

~30 lines impl, ~20 lines test. Estimated 1 day Velo lane.

## Endpoint contract

```
GET /registry/status-list/v1
Accept: application/vc+ld+json
→ 200 with BSL credential JSON
→ Cache-Control: max-age=300 (5min freshness for revocation propagation)
```

Sign the BSL credential with operator-root key on each generation. Publish refresh on every revocation event.

## Open questions for v0.2

1. Should we publish multiple status-list credentials (one per `statusPurpose`: revocation / suspension / message)? W3C BSL allows this; AiEGIS only has revocation today.
2. Should historical BSL versions be addressable (e.g. `/registry/status-list/v1?at=2026-05-10T15:00:00Z`)? Useful for forensic verification.
3. Is the 16KB / 131K-credential default sufficient, or should we ship a larger list-size from day one? 1M credentials = 128KB uncompressed.

## Empirical verify of plumbing

```
=== Existing /registry/revocations endpoint ===
GET https://aiegis.ie/registry/revocations → 200, {"revocations":[...], "count":N}
```

Verified 2026-05-10 ~15:29 IST. Native endpoint operational. BSL endpoint TO-BUILD; reads same source data via Strategy A indexing.

## Crypto-agility (forward-compat with v0.7+ PQC)

The BSL credential's `proof.type` is `Ed25519Signature2020` in v0.1. v0.7+ MUST upgrade BSL credentials to hybrid (`AiegisHybridSignature2026`) per `DID_AIEGIS_METHOD_SPEC_V01.md` Crypto-agility section. Revocation lists outlive the credentials they revoke (10-15 yr regulator audit lifespan), so they are HIGHER PRIORITY for PQC than per-agent VCs. Operator-key custody (per `OPERATOR_KEY_CUSTODY_SPEC_V01.md`) must reach a PQC-capable HSM substrate BEFORE v0.9 default-PQC issuance ramps.

## Composes with

- did:aiegis spec v0.1 — `did:aiegis:operator:<pubkey>` is BSL credential issuer
- VC envelope export spec v0.1 — issued VCs carry `credentialStatus` reference to this BSL endpoint
- v1.8 passport schema — add optional `statusListIndex` field (deterministic from agent_id, not enforced if missing for legacy)
- Revocation registry pipeline — native /registry/revocations remains canonical write-path; BSL endpoint is read-only translation
