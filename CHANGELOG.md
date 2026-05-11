# Changelog

All notable changes to AiEGIS (spec + substrate-pack + compliance-bundle + SDK) are recorded here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The spec wire format moves independently from the SDK and reference-impl release numbers — see the README "Spec conformance" stanza for the current mapping.

## [0.7.0] — 2026-05-11

First public preview. Apache 2.0. Spec stable enough for design-partner integration; SDK and reference-impl ship together under one monorepo.

### Spec

- `did:aiegis` DID method spec, v0.7
- Substrate-binding spec, v0.7, covering TPM 2.0 / Apple Secure Enclave / Intel TDX / AMD SEV-SNP
- Compliance-bundle spec, v0.7, Ed25519 signatures + JSON-sort canonicalization (JCS RFC 8785 lands in v0.8)
- Cryptosuite + canonicalization wire format:

  | spec version  | accepted cryptosuites                          | canonicalization                          | verifier behavior                                                                                                  |
  | ------------- | ---------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
  | v0.7 (this)   | `eddsa-rdfc-2022`, `hybrid-ed25519-mldsa65`    | JSON-sort + UTF-8                         | accepts the two listed suites; rejects `eddsa-jcs-2022` via `_VALID_CRYPTOSUITES` with a loud must-be-one-of error |
  | v0.8 (planned)| above **+** `eddsa-jcs-2022`                   | above **+** JCS (RFC 8785)                | label-driven canonicalization branching in `_canonical_message()` — the label↔canonicalization binding is verifier-enforced, mislabeled bundles fail sig-verify |
- `grid.json` v0.1 wholesale-catalog manifest at `/.well-known/grid.json`

### Substrate-pack (reference verifiers)

- 214 tests, regression-locked
- `_VALID_CRYPTOSUITES` frozen at `{eddsa-rdfc-2022, hybrid-ed25519-mldsa65}` for v0.7; `eddsa-jcs-2022` ships in v0.8 alongside actual JCS canonicalization
- Per-substrate verifier modules with shared `BindingProof` envelope

### Compliance-bundle

- 75 tests, regression-locked
- `IdentityError(code, detail)` with append-only stability contract (`V08_COUNT = 29`)
- `SubstrateError(IdentityError)` sibling for substrate-class failures
- Detail-sanitization (strips control chars + 512-char cap)
- JSON-LD `@context` byte-stable at `https://aiegis.ie/ns/compliance/v1` and `https://aiegis.ie/ns/substrate/v1`

### SDK (`aiegis-agent-sdk`)

- Python SDK 0.6.3 — one-line `create_agent()` for did:aiegis identity
- Ed25519 signing, keyring-backed private-key storage (macOS Keychain / Windows DPAPI / Linux libsecret)
- LangChain / OpenAI / Anthropic / CrewAI / Vercel AI SDK wrappers ship starting SDK 0.7.0

### AIVSS

- [#31 — Runtime Enforcement](https://github.com/OWASP/www-project-artificial-intelligence-vulnerability-scoring-system/issues/31), [#32 — Multi-Agent Governance](https://github.com/OWASP/www-project-artificial-intelligence-vulnerability-scoring-system/issues/32), [#33 — Mutation Testing](https://github.com/OWASP/www-project-artificial-intelligence-vulnerability-scoring-system/issues/33)

### Tooling

- `scripts/pre_push_gate.sh` — 8-gate pre-push verifier (error-codes stability, IdentityError contract, pytest full suite, JSON-LD `@context` body, VPS reachability, VPS `/api/health` 200, compliance + substrate context byte-stability)
- `scripts/post_push_verify.sh` — post-push smoke (clone + re-run gate + raw-sha compare + pytest + stale-URL grep) with CDN-lag-aware retry on the raw fetch step

### Not yet shipping

- ARM CCA verifier (production attestation flow pending vendor traces)
- Federated multi-operator registry
- Self-serve SMB checkout
- `/.well-known/security.txt` (RFC 9116) — deferred to v0.8 until `security@aiegis.ie` inbox is empirically verified; SECURITY.md remains the disclosure surface
- Dogfooded `/.well-known/grid.json` on `aiegis.ie` — deferred to v0.8 once an AiEGIS operator DID is issued and a live binding-proof is published; the SMB onboarding guide currently points readers at `spec/grid_example_smb.json` for the reference manifest shape
- Canonical JSON Schemas for `aiegis_binding_example.json`, `grid_catalog_example.json`, and `grid_signed_catalog_envelope.json` — v0.7 ships `grid.schema.json` for the manifest only; pre-push gate (x) validates the manifest example today and will fan out to the other three once their schemas are authored in v0.8
- `aiegis-compliance-bundle` PyPI package — v0.7 ships the compliance bundle as a flat-file Python module imported directly from the cloned tree; pip-packaged distribution lands alongside SDK v1.0 (first paying customer milestone)
- Formal `THREAT_MODEL.md` — v0.7 documents threat scope inside `SECURITY.md` (in-scope vs out-of-scope sections); a dedicated threat-model document with substrate-binding attack-tree analysis lands in v0.8 alongside the design-partner security review

[0.7.0]: https://github.com/AiEGIS-ie/aiegis/releases/tag/v0.7.0
