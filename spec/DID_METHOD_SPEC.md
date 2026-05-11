# `did:aiegis` Method Specification — v0.1 Draft

**Authored:** 2026-05-10 ~15:18 IST per Trav directive (4) Research mode + autonomy greenlight + Identity priority (priority order: Identity > Eye > Grid)
**Source research:** /Users/nel/Documents/NEL/research/2026-05-10_identity_competitive_landscape.md (action #1)
**Existing infra:** Ed25519 passport + operator-key trust-root + v1.8 governance signature enforce shipped 2026-05-10 ~07:18 IST (parser sha 1d3d6325)
**Composes with:** W3C DID 1.0 (canonical URL https://www.w3.org/TR/did-1.0/ — final 200 after 301 redirect from legacy /TR/did-core/, verified 2026-05-11 02:46 IST); W3C DID Extensions (canonical URL https://www.w3.org/TR/did-extensions/ — final 200 after 301 redirect from legacy /TR/did-spec-registries/, verified same time). Per W3C 2025+ rename of "DID Core" → "DID 1.0" and "DID Spec Registries" → "DID Extensions".

## Status

v0.1 draft. NOT yet submitted to W3C DID Extensions registry (formerly DID Spec Registries; W3C 2025+ rename verified 2026-05-11 02:51 IST). Internal alignment doc + roadmap for resolver implementation.

## Why a new DID method (positioning)

W3C DID 1.0 (REC at https://www.w3.org/TR/did-1.0/ verified 2026-05-11 03:14 IST) is **deliberately technology-neutral on substrate**. Verbatim: *"This specification does not presuppose any particular technology or cryptography to underpin the generation, persistence, resolution, or interpretation of DIDs."* Per §5.1.2: *"the process of authorizing a DID controller is defined by the DID method."*

W3C DID 1.0 §9 Security Considerations contains **zero references to hardware-rooted keys, TPM, Secure Enclave, TEE, or substrate-binding** (verified by direct WebFetch 2026-05-11 03:14 IST). Key custody is explicitly a **DID-method-specific concern**, not a core-spec issue.

**`did:aiegis` fills the substrate-binding design space W3C deliberately left to DID methods.** This is not a contradiction of W3C — it is the exact extension surface W3C designed in.

Competing DID method substrate-stance (probed 2026-05-11 03:18 IST):
- **`did:key`** (w3c-ccg.github.io/did-key-spec/) — RECOMMENDS hardware security modules for long-lived use cases. Verbatim: *"Use of `did:key` for long-lived use cases is only recommended when accompanied with high confidence in hardware isolation."* Software-optional / hardware-preferred for persistence. Does not name TPM/SE/TEE.
- **`did:web`** (w3c-ccg.github.io/did-method-web/) — ZERO hardware mentions. Silent/neutral. Software-only model relying on TLS/DNS as trust anchor.
- **`did:wba`** (agentnetworkprotocol.com/en/specs/03-did-wba-method-specification/) — ZERO hardware mentions. Silent/neutral. Software-only model relying on HTTPS + standard algos.

**did:aiegis differentiation:** unlike did:key (recommends HSM generically), did:aiegis names specific substrate lanes (TPM 2.0, Apple Secure Enclave, Intel TDX/AMD SEV-SNP) and ships substrate-attestation verifiers per lane. Unlike did:web/did:wba (silent), did:aiegis MANDATES hardware-rooted identity for substrate-namespaced DIDs (did:aiegis:tpm:, did:aiegis:apple-se:, did:aiegis:tee:).

## Regulatory anchor: NIST SP 800-63B-4

did:aiegis substrate-binding directly satisfies NIST SP 800-63B Revision 4 (published 2025-08-26, current; supersedes -3) §3.1.6.1 verbatim:

> *"Non-exportable authentication keys (usable at AAL3 or below) SHALL be stored in an isolated execution environment that is protected by hardware or in a separate processor with a controlled interface to the central processing unit of the user endpoint."*

NIST SP 800-63B-4 §3.1.1.2 (verifier-side secret-storage guidance) names the canonical hardware substrate vocabulary verbatim:

> *"It SHOULD be stored and used within a hardware-protected area, such as a hardware security module or trusted execution environment (TEE), such as a trusted platform module (TPM)"*

did:aiegis substrate lanes map 1:1 to §3.1.1.2's enumerated substrate types:
- Lane A (TPM 2.0) → "trusted platform module (TPM)"
- Lane B (Apple Secure Enclave) → "hardware security module" (Apple SE is HSM-class per FIPS 140-3)
- Lane C (Intel TDX / AMD SEV-SNP) → "trusted execution environment (TEE)"

Per `research/2026-05-11_nist_sp_800_63b_4_aal3_alignment.md` for full positioning + pitch language (verified 2026-05-11 03:19 IST).

## Cross-jurisdiction anchor chain

did:aiegis substrate-binding is anchored across 6 standards/regulatory layers (all verified 2026-05-11):

| Layer | Anchor | Verbatim probe receipt | Substrate-binding relationship |
|-------|--------|------------------------|-------------------------------|
| 1. US federal authentication | **NIST SP 800-63B-4 §3.1.6.1 + §3.1.1.2** (published 2025-08-26 supersedes -3) | pages.nist.gov/800-63-4/sp800-63b.html | §3.1.6.1: non-exportable authentication keys (usable at AAL3 or below) SHALL be stored in an isolated execution environment protected by hardware OR in a separate processor with controlled CPU interface → MANDATES substrate-binding for non-exportable keys |
| 2. US federal cryptographic modules | **FIPS 140-3** "Security Requirements for Cryptographic Modules" (published 2019-03-22, supersedes FIPS 140-2) | csrc.nist.gov/pubs/fips/140-3/final | Azure Key Vault Managed HSM verified at FIPS 140-3 Level 3 with Marvell LiquidSecurity hardware (lap 50.3 audit log receipt) |
| 3. International standards | **ISO/IEC 19790:2012 + ISO/IEC 24759:2017** | cited via FIPS 140-3 published reference (ISO direct paywall 403); FIPS 140-3 abstract / keywords reference ISO/IEC 19790:2012 + ISO/IEC 24759 with SP 800-140x documents identified as those that modify ISO requirements (paraphrase pending direct PDF read of body text) | International cryptographic-module standard that FIPS 140-3 modifies — anchors did:aiegis substrate-binding into ISO standards via FIPS bridge |
| 4. EU regulatory | **EU AI Act Article 50** disclosure obligation (enforcement 2 August 2026 per Article 113) | artificialintelligenceact.eu/article/50/ | Art 50(1) verbatim: *"Providers shall ensure that AI systems intended to interact directly with natural persons are designed and developed in such a way that the natural persons concerned are informed that they are interacting with an AI system, unless this is obvious from the point of view of a natural person who is reasonably well-informed, observant and circumspect, taking into account the circumstances and the context of use."* COMPLEMENT to substrate-binding (Art 50 is disclosure-mandate with reasonable-person exemption; substrate-binding is key-custody-mandate). BEACON_CONTRACT v1.1 serves Art 50 transparency audit-trail. |
| 5. W3C standards | **W3C DID 1.0** deliberate substrate-neutrality + **W3C VC Data Integrity 1.0 / EdDSA Cryptosuites v1.0** (REC 2025-05-15) | w3.org/TR/did-1.0/ + w3.org/TR/vc-data-integrity/ + w3.org/TR/vc-di-eddsa/ | DID 1.0 spec verbatim: *"This specification does not presuppose any particular technology or cryptography to underpin the generation, persistence, resolution, or interpretation of DIDs"* — leaves substrate choice to DID methods; did:aiegis fills the gap. VC-DI + EdDSA define `eddsa-jcs-2022` cryptosuite which **v0.8** did:aiegis VCs migrate to (current v0.7 uses `eddsa-rdfc-2022` per binding_proof_reference.py; v0.8 cryptosuite rename per spec § Crypto-agility line 347 and matches code lap-75 corrected state). |
| 6. Industry / Top 10 | **OWASP Agentic AI Security Initiative** (gap in current OWASP Top 10 for LLM 2025) | genai.owasp.org/initiatives/agentic-security-initiative/ + genai.owasp.org/llm-top-10/ | OWASP Top 10 for LLM (2025) has ZERO identity/attestation/substrate-binding categories. AiEGIS substrate-binding fills the future-Agentic-Top-10 identity-attestation gap. First-mover positioning before OWASP publishes ranked Agentic Top 10. |

**Cross-layer pitch hook:** *"AiEGIS substrate-binding is anchored across all 6 layers: US federal authentication (NIST SP 800-63B-4 §3.1.6.1), US federal cryptographic modules (FIPS 140-3), international standards (ISO/IEC 19790 via FIPS reference), EU regulatory (AI Act Art 50 disclosure complement), W3C identity (DID 1.0 + VC-DI), and industry (OWASP Agentic AI Security Initiative gap-filler). Per primary-source competitor audit (lap-204/205 2026-05-11): Cisco Duo Agentic Identity emphasizes OAuth 2.1 + MCP gateway + agent discovery (no substrate-binding advertised per duo.com/blog/introducing-duo-agentic-identity); Salt Agentic Security Platform provides AG-SPM discovery + AG-DR detection (no substrate-binding advertised per salt.security press release 2026-03-18); Anjuna AI Overwatch advertises TEE-based hardware-rooted attestation overlapping Layer 1 substrate-binding but not formally anchored in the W3C DID / NIST / EU AI Act / OWASP regulatory chain (per anjuna.io/solution/agentic-ai). did:aiegis differentiates from Anjuna on multi-substrate scope (TPM + Apple SE + TEE + acquirer, not TEE-only) plus explicit 6-layer regulatory anchoring."*

Per `research/2026-05-11_owasp_agentic_initiative_positioning.md` for full 6-layer synthesis + pitch language (verified 2026-05-11 03:23 IST).

## Method name

The method name to identify this DID method is: **`aiegis`**

A DID that uses this method MUST begin with: `did:aiegis:`

## Method-specific identifier

The `did:aiegis` method-specific-id syntax is defined per RFC 5234 ABNF, conforming to W3C DID 1.0 (formerly DID Core, W3C 2025+ rename) §3.1 generic-id ABNF rules:

```abnf
; did:aiegis Method-Specific Identifier (RFC 5234 ABNF)
;
; Conforms to W3C DID 1.0 (formerly DID Core, W3C 2025+ rename) §3.1: method-specific-id = *( *idchar ":" ) 1*idchar
; idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded

aiegis-did             = "did:aiegis:" namespace ":" namespace-specific-id

namespace              = logical-namespace / substrate-namespace / role-namespace

logical-namespace      = "agent"
substrate-namespace    = "tpm" / "apple-se" / "tee"
role-namespace         = "operator" / "customer" / "registry"

namespace-specific-id  = ed25519-pubkey-multibase
                       / passport-id
                       / opaque-id

ed25519-pubkey-multibase = "z" 46*48( base58btc-char )      ; Multibase z-prefix + base58btc encoding
                                                            ; of (0xed 0x01 multicodec prefix || 32-byte
                                                            ; Ed25519 pubkey) = 34 bytes total → 46-48
                                                            ; base58btc chars depending on leading-zero
                                                            ; bytes. Canonical did:key examples = 47
                                                            ; base58btc chars (48 total with z prefix).

passport-id            = "passport_" 4DIGIT "_" 8HEXDIG     ; e.g., "passport_2026_a1b2c3d4"

opaque-id              = 1*256idchar                        ; arbitrary registry-managed identifier
                                                            ; (256-char max per substrate body charset)

base58btc-char         = %x31-39 / %x41-48 / %x4A-4E / %x50-5A / %x61-6B / %x6D-7A
                       ; 0-9 except 0,O / A-Z except I,l / a-z (Bitcoin base58 alphabet)
                       ; 58 distinct chars, no 0/O/I/l ambiguity

idchar                 = ALPHA / DIGIT / "." / "-" / "_"   ; Per W3C DID 1.0 §3.1
                                                            ; (no pct-encoded in did:aiegis v0.1)
```

### Namespace semantics

| Namespace | Role | Identifier source | Resolution |
|-----------|------|-------------------|------------|
| `agent` | Logical AI agent identity | Ed25519 pubkey (multibase) | Deterministic (no network) |
| `operator` | Trust-root signing authority | Ed25519 pubkey (multibase) | Deterministic + service endpoint |
| `customer` | Customer org identifier | Ed25519 pubkey (multibase) OR opaque-id | Deterministic OR registry-resolved |
| `tpm` | Substrate-attested TPM 2.0 host | Ed25519 pubkey (multibase) | Deterministic + Lane A verifier validates |
| `apple-se` | Substrate-attested Apple Secure Enclave host | Ed25519 pubkey (multibase) | Deterministic + Lane B verifier validates |
| `tee` | Substrate-attested Intel TDX or AMD SEV-SNP host | Ed25519 pubkey (multibase) | Deterministic + Lane C verifier validates |
| `registry` | Opaque passport identifier (privacy-preserving) | Passport-id pattern | Network-resolved via AiEGIS registry |

### Examples

```
did:aiegis:agent:z6MktFoNMC8d8vS723uEEuQ5Mq8H2a592EQFByazqaZRH86L
did:aiegis:operator:z6MkjQuVAhM6BRs6L4MiYtdzezqwP3vWhmmUjwWGxF2t6e2m
did:aiegis:customer:z6Mkr3tt3iGk4bLmf8MH8jfhdjDA8EPSLJebEDthUu53kXok
did:aiegis:tpm:z6Mkot7D4MvBKMe73jueAaMmzGjpDcjg9nQw8CBfiPd7mmqa
did:aiegis:apple-se:z6Mkn7mGCCU9Jjg34iKzbUBbuAKqs1Ku98ni5NfcQvYNYHKt
did:aiegis:tee:z6MkoQvjLDEmUjnJhVzpCS4wdXRu2Fmz3gEdN4pp5qTA5skX
did:aiegis:registry:passport_2026_a1b2c3d4
```

### Identifier-source semantics

The `agent`, `operator`, `customer`, and substrate (`tpm`, `apple-se`, `tee`) namespaces use **`z` + base58btc multibase encoding** of the raw 32-byte Ed25519 public key (W3C `did:key`-compatible). This makes resolution deterministic and offline-verifiable. A relying party can verify the namespace-specific-id by base58btc-decoding to recover the 32-byte pubkey and validating Ed25519 signatures against it.

The `registry` namespace uses an opaque passport-id (network-resolved), enabling privacy use cases where the identifier should not leak the underlying pubkey at the DID-string layer.

### v0.7+ ABNF additions

Substrate-attested namespaces (`tpm`, `apple-se`, `tee`) are added in v0.7 alongside the substrate-binding spec (`HOST_SUBSTRATE_FINGERPRINT_BINDING_SPEC_V01`). Their identifier-source is the same multibase Ed25519 pubkey as `agent`, but resolution requires successful Lane A/B/C verifier validation against the substrate's attestation evidence (substrate proof binds the logical agent DID to the substrate-attested host).

Substrate namespaces are intentionally **NOT** sub-namespaces of `agent` (e.g. `did:aiegis:agent:tpm:...`) because they identify the SUBSTRATE not the agent — a single logical agent (`did:aiegis:agent:<pubkey>`) can be bound to multiple substrate identities (`did:aiegis:tpm:<pubkey>`, `did:aiegis:apple-se:<pubkey>`) via BindingProof.

## DID Document resolution

### Resolver: `did:aiegis:agent:<pubkey>`

The resolver MUST construct the DID Document deterministically from the Ed25519 public key without network round-trip:

> **Display-truncation note (added 2026-05-11 03:40 IST):** `z6MktFoN...` (and similar prefix-elide forms throughout this spec) is DISPLAY-ONLY shorthand for the canonical full 48-char Ed25519 multibase identifier `z6MktFoNMC8d8vS723uEEuQ5Mq8H2a592EQFByazqaZRH86L` (or equivalent canonical 47-base58btc-char body for other example identifiers — see § "Method-specific identifier" for full set). For conformance testing (per § "Conformance testing"), examples MUST be expanded to canonical full form before parsing.

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
  "id": "did:aiegis:agent:z6MktFoN...",
  "verificationMethod": [{
    "id": "did:aiegis:agent:z6MktFoN...#key-1",
    "type": "Multikey",
    "controller": "did:aiegis:agent:z6MktFoN...",
    "publicKeyMultibase": "z6MktFoN..."
  }],
  "authentication": ["did:aiegis:agent:z6MktFoN...#key-1"],
  "assertionMethod": ["did:aiegis:agent:z6MktFoN...#key-1"]
}
```

Identical resolution shape to `did:key` for Ed25519 — interop with existing `did:key` resolvers is the design goal. Canonical `did:key` spec at https://w3c-ccg.github.io/did-key-spec/ (200 verified 2026-05-11 02:46 IST). Note: W3C TR/did-key/ URL is 404; the spec is hosted by the Credentials Community Group at the GitHub Pages URL above. Verification method type `Multikey` (W3C VC-DI EdDSA Cryptosuites v1.0 §2.1.1, REC 2025-05-15) supersedes the legacy `Ed25519VerificationKey2020` per VC-DI EdDSA §A.1.1.1 ("New applications are strongly urged to use the newer key format"). Legacy `Ed25519VerificationKey2020` MAY be accepted by verifiers for backward-compat with deployed v0.x-pre-2025 systems but MUST NOT be emitted by new did:aiegis issuers.

### Resolver: `did:aiegis:operator:<pubkey>`

Same as `agent` resolution, except `service` array adds:

```json
{
  "service": [{
    "id": "did:aiegis:operator:z6MkjQuV...#trust-root",
    "type": "AiEGISTrustRoot",
    "serviceEndpoint": "https://aiegis.ie/api/trust-root/{pubkey}"
  }]
}
```

The endpoint returns the operator's signing-history + revocation status. AiEGIS Identity v1.8 governance enforce-mode reads this endpoint at passport-verify time.

### Resolver: `did:aiegis:registry:<passport-id>`

Network-resolved via:
```
GET https://aiegis.ie/api/registry/passports/{passport-id}/.did
Accept: application/did+json
```

Returns full DID Document including any operator-issued attestations as VerifiableCredentials.

This namespace is for opaque passport identifiers where the holder doesn't want pubkey-leakage at the DID-string layer. (Privacy use case: corporate agents that want a stable identifier without exposing rotation key.)

## Operations

| Operation | Supported | Notes |
|-----------|-----------|-------|
| Create    | ✓         | `agent` + `operator`: deterministic from Ed25519 keygen. `registry`: requires AiEGIS account + passport issuance. |
| Read      | ✓         | Deterministic for `agent`/`operator`, network for `registry`. |
| Update    | △ partial | `agent` deterministic — to update, generate new keypair = new DID. `operator` + `registry` support service-endpoint update via signed mutation request. |
| Deactivate | ✓        | All namespaces support deactivation via signed AiEGISRevocationCredential + W3C Bitstring Status List 2021 (see § "Deactivate operation — cryptographic operations" below). Per W3C DID Core v1.0 §8.2 Method Operations: cryptographic operations specified. |

### Update operation — cryptographic authorization

Per W3C DID Core v1.0 §8.2 Method Operations, this section specifies the cryptographic authorization required for each Update operation:

**`did:aiegis:agent:<pubkey>` (deterministic):** No update operation is supported on an existing agent DID. The DID Document is fully derived from the pubkey at the DID-string level. To "update" an agent identity, the controller MUST generate a new Ed25519 keypair and publish the new DID. The old DID remains resolvable but SHOULD be deactivated by the operator.

**`did:aiegis:operator:<pubkey>` (deterministic + service):** The verificationMethod array is fixed by the pubkey. Service endpoints (e.g., the `AiEGISTrustRoot` URL) MAY be updated via:
- A signed mutation request to `https://aiegis.ie/api/operator/{pubkey}/services` containing:
  - `mutation`: the new service endpoint object (per W3C DID Core v1.0 §5.4 Services)
  - `nonce`: 32-byte random anti-replay value
  - `timestamp`: RFC 3339 UTC, must be within 60 seconds of receipt
  - `signature`: Ed25519 signature over canonical(mutation + nonce + timestamp + operator_did) using the operator's pubkey
- The AiEGIS registry MUST verify the signature against the operator's pubkey before accepting the mutation.

**`did:aiegis:customer:<pubkey>` (deterministic OR opaque):** Same authorization model as operator namespace. Customer signs mutation request with the pubkey embedded in the DID.

**`did:aiegis:registry:<passport-id>` (network-resolved):** Update authorization requires the passport's CURRENT controller key (which may have rotated). The mutation request signature is verified against the controller key listed in the latest registry-published DID Document, NOT the passport-id itself. This enables controller-key rotation without DID rotation.

**Substrate namespaces (`tpm`/`apple-se`/`tee`):** Substrate-namespace DIDs are NOT updatable. They identify a specific hardware substrate; if the substrate changes (TPM swap, device replacement), a new substrate DID MUST be issued + a new BindingProof MUST be created linking the logical agent DID to the new substrate DID.

### Deactivate operation — cryptographic operations

Per W3C DID Core v1.0 §8.2 Method Operations: this section specifies the cryptographic operations necessary to establish proof of deactivation for `did:aiegis` DIDs. Cross-lane decision 2026-05-11: ship two complementary primitives — (a) **signed revocation Verifiable Credential** for individual deactivation events + (c) **W3C Bitstring Status List 2021** for scalable batch verifier polling. (Tombstone DID document — covered conceptually in W3C DID Core v1.0 §8.2 Method Operations under "Deactivate" — is optional v1.0+ implementation work for did:aiegis.)

#### Primitive (a): Signed Revocation Verifiable Credential

The operator (or designated revocation authority) MUST issue a signed Verifiable Credential of type `AiEGISRevocationCredential` per W3C VC Data Model v2.0. (Note: the JSON-LD context `https://aiegis.ie/ns/revocation/v1` defines the `AiEGISRevocationCredential` vocabulary; live deploy queued for v0.8 alongside revocation registry endpoints — endpoint returns 404 today, spec defines wire format at v0.7.):

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://aiegis.ie/ns/revocation/v1"
  ],
  "type": ["VerifiableCredential", "AiEGISRevocationCredential"],
  "issuer": "did:aiegis:operator:z6MkjQuV...",
  "validFrom": "2026-05-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:aiegis:agent:z6MktFoN...",
    "deactivated": true,
    "deactivationReason": "key_rotation" | "compromise_suspected" | "lifecycle_end" | "operator_decision",
    "deactivationTimestamp": "2026-05-11T00:00:00Z",
    "nonce": "<32-byte hex anti-replay value>"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "created": "2026-05-11T00:00:00Z",
    "verificationMethod": "did:aiegis:operator:z6MkjQuV...#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "<base58btc-encoded Ed25519 signature; v0.8+ migrates to eddsa-jcs-2022 cryptosuite + hybrid Ed25519+ML-DSA-65>"
  }
}
```

**Cryptographic operations:**
1. The revocation authority canonicalizes the credentialSubject + nonce + deactivationTimestamp + issuer using JCS (RFC 8785) per the active cryptosuite.
2. The revocation authority signs the canonical bytes with its operator key (per `OPERATOR_KEY_CUSTODY_SPEC_V01` HSM-bound signing).
3. The signature is encoded as the `proofValue` of the AiEGISRevocationCredential.
4. The credential is published to the AiEGIS revocation registry at `https://aiegis.ie/api/registry/revocations/{agent-did}` (endpoint deploy in v0.8 alongside spec adoption; v0.7 specifies wire format only — endpoint returns 404 today).

**Verifier check:**
1. Fetch the AiEGISRevocationCredential from the registry endpoint (TLS 1.3+ with root cert pin).
2. Verify the `issuer` matches the expected operator DID (operator authorization check).
3. Verify the `proof.verificationMethod` resolves to the operator's pubkey via deterministic `did:aiegis:operator:` resolution.
4. Reconstruct the canonical bytes per JCS and verify the Ed25519 (or hybrid) signature against the operator's pubkey.
5. If signature verifies AND `credentialSubject.deactivated == true`, the DID is conclusively deactivated.

#### Primitive (c): W3C Bitstring Status List 2021

For scalable batch verifier polling (e.g., relying parties verifying thousands of agent identities per second), the operator MUST also publish a W3C Bitstring Status List 2021 credential at `https://aiegis.ie/api/registry/status-list/v1` (endpoint deploy in v0.8 alongside spec adoption; v0.7 specifies wire format only — endpoint returns 404 today):

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/security/data-integrity/v2"
  ],
  "id": "https://aiegis.ie/api/registry/status-list/v1",
  "type": ["VerifiableCredential", "BitstringStatusListCredential"],
  "issuer": "did:aiegis:operator:z6MkjQuV...",
  "validFrom": "2026-05-11T00:00:00Z",
  "credentialSubject": {
    "id": "https://aiegis.ie/api/registry/status-list/v1#list",
    "type": "BitstringStatusList",
    "statusPurpose": "revocation",
    "encodedList": "<base64url-encoded gzip-compressed bitstring>"
  },
  "proof": { ... same DataIntegrityProof shape ... }
}
```

Each AiEGIS agent passport MUST include a `credentialStatus` field referencing the status list:

```json
"credentialStatus": {
  "id": "https://aiegis.ie/api/registry/status-list/v1#42",
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": "42",
  "statusListCredential": "https://aiegis.ie/api/registry/status-list/v1"
}
```

**Verifier check (batch-friendly):**
1. Fetch the status list credential ONCE (cached for the operator-configured TTL, default 1 hour).
2. Verify the status list signature against the operator's pubkey.
3. For each agent DID being verified, look up the `statusListIndex` from the agent's passport `credentialStatus.statusListIndex`.
4. Decode bit at that index from `encodedList` (base64url → gzip → bitstring).
5. Bit value 1 = revoked; bit value 0 = active.

**Composition:** primitive (a) provides per-event deactivation evidence with operator signature; primitive (c) provides O(1) batch lookup at scale. Verifier MAY use either; high-stakes verifications SHOULD check both.

**Stale revocation handling:** the status list credential's `validFrom` MUST be within the operator-configured freshness window (default 1 hour for status lists, distinct from BindingProof's 7-day default). Verifiers SHOULD reject status lists older than the freshness window and re-fetch.

## Security considerations

This section addresses W3C DID 1.0 (formerly DID Core, W3C 2025+ rename) §8.3 MUST requirements: key material protection, authorization and access control, attack mitigation, and cryptographic strength.

### Key material protection

- **Operator root key:** held in 2-of-3 Shamir custody + YubiHSM 2 FIPS (NIST CMVP cert #3916, FIPS 140-2 Overall Level 3 — original certification sunset date 2026-05-02 per CMVP; Yubico FIPS 140-3 transition expected Q2 2026 per yubico.com/product/yubihsm-2-fips/). Spec MUST update to FIPS 140-3 cert reference when Q2 2026 transition completes. Per `OPERATOR_KEY_CUSTODY_SPEC_V01`. Multi-party ceremony required for rotation. Single-party access cannot extract or use the key.
- **Agent signing keys:** generated by the operator at issuance time + delivered to the customer environment via TLS 1.3+ pinned channel. The customer is responsible for at-rest protection (recommended: OS keystore — macOS Keychain / Windows DPAPI / Linux libsecret per `aiegis-agent-sdk-python`).
- **Substrate-attested keys:** for `did:aiegis:tpm:`, `did:aiegis:apple-se:`, `did:aiegis:tee:` namespaces, the signing key is generated INSIDE the substrate (TPM 2.0 / Apple SE / Intel TDX / AMD SEV-SNP) and is non-exportable by hardware policy. The substrate's attestation chain proves to verifiers that the key resides in attested hardware.

### Authorization and access control

- DID Document mutation (Update operation) requires Ed25519 signature by the controller key embedded in the DID (or current controller per registry resolution for `registry:` namespace).
- Substrate-namespace verification requires successful Lane A/B/C verifier validation against the substrate's attestation evidence + matching expected substrate-tier root CA.
- Operator-namespace registration requires offline-signed AiEGIS root key approval (trust establishment is out-of-band; in-band registration is rejected).

### Attack mitigation

- **Replay attacks:** all mutation requests carry a nonce + timestamp; the registry MUST reject requests with reused nonces or timestamps outside a 60-second window.
- **MitM attacks:** all network resolution endpoints MUST require TLS 1.3+ with AiEGIS root certificate pinning at the resolver. Bare HTTP resolution is rejected.
- **Substrate-key cloning:** non-exportable substrate keys cannot be cloned by software-only attacks. Physical motherboard swap (TPM chip replacement) breaks the binding intentionally; recovery requires explicit operator re-enrollment.
- **Operator-key compromise:** bounded by 2-of-3 Shamir custody + multi-party rotation ceremony. Single insider with HSM access cannot issue rogue identities.
- **Stale BindingProof replay:** verifiers MUST reject BindingProof beyond the operator-configured freshness window (default 7 days per W3C VC issuance pattern; per-action substrate attestation verified fresh via nonce at verify time).
- **Cross-namespace identity confusion:** the namespace allowlist (per ABNF + Conformance test TV-008) MUST reject DIDs with unknown namespaces; resolvers MUST NOT silently fall back to a default namespace.

### Cryptographic strength

- **v0.7 baseline:** Ed25519 (128-bit classical security per RFC 8032).
- **v0.8 hybrid:** Ed25519 + ML-DSA-65 (NIST FIPS 204 Final, published August 13, 2024 per https://csrc.nist.gov/pubs/fips/204/final verified 2026-05-11; specific NIST PQC category mapping + bit-security level details in source PDF — not verbatim-cited here pending direct PDF read).
- **v1.0 PQC-required:** ML-DSA-65 only for new agents; legacy hybrid agents continue verification via cross-suite acceptance.
- **Hash:** SHA-256 (NIST FIPS 180-4) for all DID-document content hashing + BindingProof attestation-blob digests.
- **Canonicalization:** v0.7 uses JSON-sort+UTF-8 with `eddsa-rdfc-2022` cryptosuite tag (transitional rdfc-style — NOT full JCS RFC 8785). v0.8 migrates to true JCS RFC 8785 canonicalization AND cryptosuite rename to `eddsa-jcs-2022` (both bundled in single version bump per W3C VC-DI EdDSA Cryptosuites v1.0, W3C Recommendation May 15, 2025, REC-vc-di-eddsa-20250515). The v0.8 migration includes label-driven canonicalization branching in `_canonical_message()` — accepting the label without the branch would silently mis-verify v0.7-canonical bundles (V red-team lap-388, 2026-05-11).

### Side-channel and timing considerations

- v0.7 verifier endpoint does NOT enforce constant-time fail paths; v0.8 adds constant-time fail-path equalization for the BindingProof signature verify step (per NIST FIPS 140-3 §6.4 timing-side-channel guidance).
- Resolver endpoints MUST NOT leak operator-side internal state via timing differences between valid + invalid DID lookups.

### Out-of-scope (acknowledged)

- Physical TPM chip replacement (intentional re-enrollment trigger)
- Operator-side insider with physical access to YubiHSM + Shamir quorum (defense = multi-party ceremony)
- Side-channel attacks on the substrate hardware itself (covered by substrate vendor's own attestation + threat model)
- Hypervisor compromise on cloud TEEs (covered by vendor TEE threat model; AiEGIS attestation records the substrate's stated security level)

## Privacy considerations

This section addresses the W3C DID 1.0 (formerly DID Core, W3C 2025+ rename) §10 MUST requirement that DID method specifications discuss correlation, herd privacy, exposure minimization, and personal data handling.

### Correlation risks

The `did:aiegis:agent:<pubkey>` and `did:aiegis:operator:<pubkey>` namespaces expose the raw Ed25519 public key in the DID string itself (multibase-encoded). This is inherent to deterministic resolution and matches `did:key` behavior.

**Correlation surface:**
- A pubkey-based DID is trivially linkable across all contexts where it appears. Two parties seeing `did:aiegis:agent:z6Mk...` can correlate that the same agent acted in both contexts.
- Substrate-namespace DIDs (`did:aiegis:tpm:<pubkey>`, `did:aiegis:apple-se:<pubkey>`, `did:aiegis:tee:<pubkey>`) similarly expose substrate-specific pubkeys, enabling correlation of which substrate hosted which agent across deployments.

**Mitigation:** the `did:aiegis:registry:<passport-id>` namespace exists specifically for high-correlation-sensitivity deployments. It uses opaque registry-issued identifiers that do NOT expose the underlying signing pubkey at the DID-string layer. Registry resolution returns the current pubkey via TLS-pinned endpoint, but the DID itself does not leak it.

### Herd privacy

Substrate attestation inherently reduces herd privacy: a substrate-attested agent is identified as running on specific hardware (TPM EK or Apple SE attestation key) which is in turn linkable to a specific physical device. This trade-off is intentional — substrate binding is the security primitive — but deployments with high herd-privacy requirements should consider:

- Using `registry:` namespace at the DID layer (opaque ID) while substrate attestation lives in a separate verifiable credential that is selectively disclosed
- BBS+ selective-disclosure proofs over the BindingProof for verifier presentation (v0.9 roadmap)

### Personal data handling

`did:aiegis` DIDs do NOT contain PII at the DID-string layer. The agent/operator/customer pubkeys are cryptographic identifiers, not personal data. However, deployments must consider:

- **Operator DID exposure:** identifies the issuing AiEGIS operator (an organization). Per GDPR, organization identifiers are not personal data.
- **Customer DID exposure:** if `did:aiegis:customer:<pubkey>` represents an individual sole-trader, the pubkey may indirectly identify a natural person. Recommend `registry:` namespace for individual customers.
- **Substrate DID + BindingProof exposure:** binding an agent to a specific employee laptop's TPM creates a record linking agent action → employee device. Workplace deployments require DPIA per GDPR Art. 35 and employee notice per Art. 13/14 (see workplace-monitoring privacy-by-design addendum + AiEGIS Eye DPIA template, v1.0 deliverable).

### Exposure minimization

Issuers SHOULD minimize DID-document field exposure:

- DID documents resolved via `agent:` and `operator:` namespaces are deterministic and contain ONLY: `@context`, `id`, `verificationMethod` (1 entry), `authentication`, `assertionMethod`. No PII, no service endpoints (except operator-namespace `AiEGISTrustRoot` service endpoint which exposes only the public registry URL).
- `registry:` namespace DID documents MAY include service endpoints; issuers SHOULD scope endpoint URLs to non-PII paths.
- `customer:` namespace DID documents SHOULD use opaque pubkey identifiers when the customer is an individual.

### Recommendations for high-privacy deployments

1. Default to `registry:` namespace for individual-natural-person customers.
2. Default to `agent:` namespace (deterministic + no service endpoints) for agent identity.
3. Consider BBS+ selective-disclosure proofs over BindingProof when v0.9 ships.
4. For workplace deployments, follow the DPIA template + employee-notice requirements per workplace-monitoring privacy-by-design addendum.
5. Substrate-namespace DIDs (`tpm:`, `apple-se:`, `tee:`) SHOULD NOT be exposed in customer-facing surfaces; they are operator-side trust-binding primitives, not user-facing identifiers.

## Conformance testing

This section addresses the W3C DID 1.0 (formerly DID Core, W3C 2025+ rename) §8 MUST requirement that DID method specifications define conformance testing mechanisms.

### Conformance criteria

A `did:aiegis` implementation conforms to this spec if and only if:

1. **Method-name conformance:** the implementation accepts and produces DIDs with the exact prefix `did:aiegis:` and rejects any other prefix.
2. **ABNF conformance:** the implementation accepts only DIDs matching the `aiegis-did` ABNF grammar in §"Method-specific identifier", and rejects DIDs with malformed `namespace`, `namespace-specific-id`, or character sets outside the defined allowlist (per substrate body charset: alphanumeric + `:-_.`, no `/` `\` whitespace control chars).
3. **Resolution conformance:**
   - For `agent` / `operator` / `customer` / substrate (`tpm`/`apple-se`/`tee`) namespaces, the resolver MUST construct the DID Document deterministically from the multibase-decoded Ed25519 public key, with no network round-trip.
   - For `registry:` namespace, the resolver MUST fetch from `https://aiegis.ie/api/registry/passports/{passport-id}/.did` over TLS 1.3+ with AiEGIS root cert pinning.
4. **Operations conformance:** the implementation supports Create / Read / Update (per partial-update rules in operations table) / Deactivate per the cryptographic-operations specifications in § "Deactivate operation".
5. **VC envelope conformance:** issued Verifiable Credentials use W3C VC Data Model v2.0 envelope with proof `type: DataIntegrityProof` and `cryptosuite: eddsa-rdfc-2022` (v0.7 baseline). v0.7 verifiers REJECT bundles labeled `eddsa-jcs-2022` until v0.8 implements proper JCS RFC 8785 canonicalization branched on the cryptosuite label — accepting the label without that branch would silently mis-verify v0.6-canonical bundles labeled jcs (V red-team lap-388, 2026-05-11). Hybrid Ed25519+ML-DSA-65 proof type is introduced in v0.7+ as `AiegisHybridSignature2026` (see § Crypto-agility). Legacy `Ed25519Signature2020` proof type is deprecated per W3C VC-DI EdDSA appendix and MUST NOT be used by new did:aiegis issuers.

### Reference test vectors

Conforming implementations MUST pass the test-vector pack at `https://aiegis.ie/conformance/did-aiegis-test-vectors-v01.json` (deferred to v0.2 publication; pack scaffold below).

**Required test fixtures:**

| Test ID | Input | Expected behavior |
|---------|-------|-------------------|
| TV-001 | `did:aiegis:agent:z6MktFoNMC8d8vS723uEEuQ5Mq8H2a592EQFByazqaZRH86L` | Resolves to deterministic DID Document with single `Multikey` verificationMethod (publicKeyMultibase z-prefixed Ed25519), agent namespace |
| TV-002 | `did:aiegis:operator:z6MkjQuVAhM6BRs6L4MiYtdzezqwP3vWhmmUjwWGxF2t6e2m` | Resolves with `AiEGISTrustRoot` service endpoint included |
| TV-003 | `did:aiegis:tpm:z6Mkot7D4MvBKMe73jueAaMmzGjpDcjg9nQw8CBfiPd7mmqa` | Resolves; substrate-namespace flag set; Lane A verifier validation REQUIRED |
| TV-004 | `did:aiegis:apple-se:z6Mkn7mGCCU9Jjg34iKzbUBbuAKqs1Ku98ni5NfcQvYNYHKt` | Same as TV-003 with Lane B verifier |
| TV-005 | `did:aiegis:tee:z6MkoQvjLDEmUjnJhVzpCS4wdXRu2Fmz3gEdN4pp5qTA5skX` | Same as TV-003 with Lane C verifier (vendor enum: `intel-tdx` or `amd-sev-snp`) |
| TV-006 | `did:aiegis:registry:passport_2026_a1b2c3d4` | Network resolution to `aiegis.ie/api/registry/passports/passport_2026_a1b2c3d4/.did` |
| TV-007 | `did:web:example.com` | REJECTED — wrong method prefix |
| TV-008 | `did:aiegis:novel-tier:abc` | REJECTED — namespace not in allowlist (per ABNF) |
| TV-009 | `did:aiegis:agent:..//../etc/passwd` | REJECTED — path-traversal characters in namespace-specific-id |
| TV-010 | `did:aiegis:agent:abc\x00null` | REJECTED — NUL byte in namespace-specific-id |
| TV-011 | Deactivated agent DID | Resolution returns AiEGISRevocationCredential with credentialSubject.deactivated == true per § "Deactivate operation"; corresponding Bitstring Status List bit set to 1 at the agent passport credentialStatus.statusListIndex |
| TV-012 | Stale BindingProof (>operator-configured freshness window) | Substrate-namespace verification fails with `binding_proof_stale` reason |

### Reference implementation

The substrate-binding reference implementation at `https://github.com/[REPO]/substrate-identity/` includes:

- `tpm_quote_verifier_reference.py` — Lane A (TPM 2.0) verifier, 91 unit tests
- `apple_se_assertion_verifier_reference.py` — Lane B (Apple SE) verifier
- `tee_attestation_verifier_reference.py` — Lane C (Intel TDX + AMD SEV-SNP) verifier
- `agent_substrate_acquirer_reference.py` — substrate detection + acquisition
- `binding_proof_reference.py` — operator-signed BindingProof generator + verifier
- `substrate_context_mapper.py` — live JSON-LD vocab → ref-impl input shape mapper
- `test_substrate_verifiers.py` + `test_e2e_substrate_attested_bundle.py` — 110 tests total, all green

Conforming implementations MAY swap any reference component for a vendor-equivalent (e.g., `tpm2-pytss` for production TPM verification), provided the outputs (verification result + failure_reasons) match the reference behavior on the test-vector pack.

### Interoperability profile

`did:aiegis` is intentionally `did:key`-compatible for the agent/operator/customer/substrate namespaces: the namespace-specific-id is the same multibase Ed25519 public key encoding as `did:key`. A `did:key` resolver SHOULD be able to extract the pubkey from a `did:aiegis:agent:z6Mk...` DID by stripping the `did:aiegis:agent:` prefix and treating the remainder as a `did:key` body. This enables ecosystem interop without separate `did:aiegis` resolver software for read-only verification scenarios (e.g., signature validation against the pubkey embedded in the DID).

## Verifiable Credentials envelope

`did:aiegis` issuers MUST emit VCs in W3C VC Data Model v2.0 envelope (REC 2025-05-15) using `DataIntegrityProof` with `cryptosuite` per W3C VC-DI EdDSA Cryptosuites v1.0 (REC 2025-05-15) — v0.7 accepted value is `eddsa-rdfc-2022`. v0.7 verifiers REJECT `eddsa-jcs-2022` until v0.8 implements label-driven JCS RFC 8785 canonicalization (V red-team lap-388, 2026-05-11). The legacy `Ed25519Signature2020` proof type is deprecated per W3C VC-DI EdDSA appendix ("new implementations should instead use `eddsa-rdfc-2022`") and MUST NOT be used by new did:aiegis VCs:

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "AiEGISPassportCredential"],
  "issuer": "did:aiegis:operator:z6MkjQuV...",
  "credentialSubject": {
    "id": "did:aiegis:agent:z6MktFoN...",
    "passportId": "passport_2026_a1b2c3d4",
    "governancePolicies": ["EU_AI_ACT", "GDPR", "NIST_AI_RMF"]
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "verificationMethod": "did:aiegis:operator:z6MkjQuV...#key-1",
    "proofValue": "z3MwbeM..."
  }
}
```

This envelope is what the AiEGIS dispatcher v1.8 governance-enforce mode validates at request-verify time.

## Open questions for v0.2

1. Should `did:aiegis:agent` resolution be PURELY deterministic, or include an optional network call to fetch the latest service-endpoint set? (Tradeoff: offline-resolvable vs current-endpoints.)
2. Should we support did-doc rotation history for `operator:` namespace, or treat each rotation as DID-deactivate + new-DID? (DID-Core allows both.)
3. Cross-method resolution: should `did:aiegis:agent:<pubkey>` ALSO be resolvable as `did:key:<pubkey>` for ecosystem interop? (Pure-base58btc-pubkey makes this trivial.)
4. Verifiable Credentials revocation list endpoint shape — bitstring-list (W3C standard) vs custom registry-pull endpoint?

## Implementation status

**Existing infrastructure:**
- ✓ Ed25519 keypair primitives (already shipping, in nel-Air keychain + Velo monorepo)
- ✓ Operator trust-root (already shipping as v1.8 governance signature enforce)
- ✓ Revocation registry SCAFFOLD at `/registry/revocations` (404 on specific resources today; v0.8 deploys per-DID resource pattern)
- ✓ Live JSON-LD contexts at `/ns/compliance/v1` + `/ns/substrate/v1` (HTTP 200 byte-verified 2026-05-10)

**Spec-defined endpoints — v0.7 wire format only, v0.8 live deploy:**

| Endpoint | Status | Spec § | Deploy target |
|----------|--------|--------|---------------|
| `https://aiegis.ie/api/did/resolve?did=...` | TO BUILD | DID Document resolution | v0.8 |
| `https://aiegis.ie/api/operator/{pubkey}/services` | TO BUILD (404 today) | Update operation | v0.8 |
| `https://aiegis.ie/api/registry/passports/{passport-id}/.did` | 403 today (auth-gated, deploy in progress) | Resolver: registry namespace | v0.7 partial / v0.8 full |
| `https://aiegis.ie/api/registry/revocations/{agent-did}` | TO BUILD (404 today) | Deactivate primitive (a) | v0.8 |
| `https://aiegis.ie/api/registry/status-list/v1` | TO BUILD (404 today) | Deactivate primitive (c) | v0.8 |
| `https://aiegis.ie/api/trust-root/{pubkey}` | TO BUILD (404 today) | Resolver: operator namespace | v0.8 |
| `https://aiegis.ie/ns/revocation/v1` | TO BUILD (404 today) | AiEGISRevocationCredential context | v0.8 |
| `https://aiegis.ie/conformance/did-aiegis-test-vectors-v01.json` | TO BUILD | Conformance testing | v0.2 publication of test-vector pack |

**TO BUILD (v0.7 → v0.8 migration):**
- ✗ DID resolver endpoint
- ✗ DID Document materializer (deterministic agent/operator + network registry)
- ✗ VC envelope export from existing passports
- ✗ Operator service-mutation endpoint
- ✗ AiEGISRevocationCredential issuer
- ✗ Bitstring Status List v1 publisher
- ✗ Trust-root service endpoint
- ✗ JSON-LD context for revocation vocabulary
- ✗ Conformance test-vector pack publication

**Empirical 2026-05-11:** all spec-cited endpoints listed as "TO BUILD" return HTTP 404 anonymous (verified via curl). Spec defines wire-format + cryptographic operations at v0.7; live deployment scheduled v0.8 alongside W3C registry submission.

Estimated engineering: ~2-3 weeks for all v0.8 endpoint deploys + W3C registry submission prep. Velo lane (resolver + materializer + revocation registry + status list) + Nel lane (VC envelope export + did-method-registries submission + JSON-LD context deploy + conformance pack publish).

## Crypto-agility — forward-compat for post-quantum migration

v0.1 of this spec is Ed25519-only. v0.7+ will add hybrid post-quantum signatures (see `research/2026-05-10_pqc_migration_for_did_aiegis.md` for full plan). To make that migration non-breaking:

**Verification methods** — the `verificationMethod` array in the DID Document is plural by design. v0.7+ MUST add a second entry alongside the existing Ed25519 entry without removing it:

```json
"verificationMethod": [
  {"id": "...#key-1", "type": "Multikey", "publicKeyMultibase": "z6Mk...", ...},
  {"id": "...#pqc-1", "type": "Multikey", "publicKeyMultibase": "z<mldsa-65-prefix>...", ...}
]
```

(Both entries use `Multikey` per W3C VC-DI EdDSA §2.1.1; the multicodec prefix in `publicKeyMultibase` disambiguates Ed25519 `0xed01` vs ML-DSA-65 `0x1211` per § Crypto-agility multicodec table.)

**Proof types** — `proof.type` is a string. v0.7+ introduces `AiegisHybridSignature2026` as a new proof type that contains BOTH Ed25519 and ML-DSA-65 signatures in a single proof object. v0.1 verifiers seeing the new type MUST reject (unknown algorithm) — they will not silently accept unsigned credentials. v0.7 verifiers REJECT `eddsa-jcs-2022` (loud "must be one of [...]" via `_VALID_CRYPTOSUITES`) because v0.7 `_canonical_message()` does not branch on the cryptosuite label, so accepting jcs without implementing JCS canonicalization would silently mis-verify (V red-team lap-388, 2026-05-11). v0.8 adds `eddsa-jcs-2022` with label-driven JCS RFC 8785 canonicalization. The deprecated `Ed25519Signature2020` proof type is NOT emitted by canonical v0.1 issuers (per § Verifiable Credentials envelope) but legacy non-canonical issuers may exist; verifiers SHOULD accept it for backward-compat with appropriate warning logging.

**Multicodec extensions** — v0.7 hybrid PQC adds ML-DSA-65 keys to the multicodec table. ML-DSA-65 public key codec is **`0x1211`** (already draft-registered in the canonical multicodec table at github.com/multiformats/multicodec/master/table.csv as of 2026-05-11 02:55 IST verify; "as specified by FIPS 204"). NOT `0x9301` as earlier draft of this spec claimed — that was a defect. Companion ML-DSA-65 private key codec is `0x1318`. v0.1 multicodec table (only Ed25519 public key, varint codec `0xed01` derived from canonical `0xed`) is forward-compat: parsers extract the codec prefix and route accordingly; unknown codec = parse-error, not silent fallthrough. v0.7 adds parser support for the FIPS-204 codec range (`0x1210` mldsa-44-pub through `0x1212` mldsa-87-pub).

**Non-goals for v0.1:** PQC implementation. v0.1 ships pure Ed25519 to match shipping infrastructure. PQC is research-tracked, not in the v0.1 scope.

## Submission to W3C DID Spec Registries

After v0.1 internal review + 1-2 design partners use the spec, submit PR to https://github.com/w3c/did-extensions (canonical 200; legacy /w3c/did-spec-registries 301 redirects here, verified 2026-05-11 02:49 IST) adding `aiegis` method per https://www.w3.org/TR/did-extensions/ format guidelines (W3C 2025+ rename of did-spec-registries). Target: v0.2 publication.
