# PoP × did:aiegis Composition — v0.1

**Authored:** 2026-05-10 ~15:50 IST per directive-(4) Identity research-mode
**Composes with:** DID_AIEGIS_METHOD_SPEC_V01.md (sha 62b228a0), VC_ENVELOPE_EXPORT_SPEC_V01.md (sha 709af301), aegis_agent_passport_verify.py check_proof_of_possession, /opt/aegis/core/pop_challenge_storage.py (deployed 2026-05-10 14:48)
**Question:** When a verifier resolves `did:aiegis:agent:<pubkey>`, is the original passport's PoP signature sufficient, or does the verifier need to re-issue a fresh PoP challenge?

## TL;DR

**Original passport's PoP signature is sufficient for did:aiegis:agent: resolution; verifiers do NOT need to re-issue PoP challenges.** PoP proves possession at issuance time; subsequent verifications only need the passport signature, not re-proof of key control.

## Threat model split

PoP and signature verification defend against DIFFERENT attacks:

### Attack 1: Compromised customer API key + agent without private key

Attacker has stolen customer admin Bearer token. Attempts to issue passports for keypairs they don't actually control.

**Defense:** PoP at issuance. Forces requester to sign a fresh challenge (`/api/agent/issue/challenge` → /api/agent/issue) with the agent_priv_key. Stolen API key alone doesn't grant key-control.

**Where it runs:** /api/agent/issue handler. Per-issuance, one-time. Succeeded → passport issued. Failed → 400.

### Attack 2: Stolen passport at verification time

Attacker has a valid passport JSON (perhaps from a leak). Attempts to use it to authenticate as the agent at some other verifier.

**Defense:** Passport `signature` field (operator-key signature over canonical bytes). Attacker has the signed bytes but cannot forge a NEW passport for a different agent_id without the operator key.

**Where it runs:** every passport-verify call. Continuous. Succeeded → passport-bound claim accepted. Failed → reject.

### Attack 3: Compromised passport + replay at verification

Attacker has a valid passport AND wants to use it across multiple sessions / multiple verifiers. They don't need to forge anything; they just re-present the same valid passport to many verifiers.

**Defense:** challenge-response at the SESSION layer (NOT the passport layer). Verifiers run their own session-bind challenge separately from passport verification.

**Where it runs:** session establishment (e.g. TLS client cert exchange, or application-layer challenge-response). NOT inside passport-verify.

## did:aiegis:agent: resolution flow

When a W3C VC verifier (Sovrin, Trinsic, etc.) resolves `did:aiegis:agent:z6Mkpz...`:

1. **Deterministic resolution** (no network call): construct DID Document from the base58btc-encoded Ed25519 pubkey embedded in the DID string. Per `DID_AIEGIS_METHOD_SPEC_V01.md` §"DID Document resolution".
2. **Look up Verifiable Credential**: verifier fetches the VC envelope (per `VC_ENVELOPE_EXPORT_SPEC_V01.md`) — typically presented by the agent, not pull-fetched.
3. **Verify VC proof**: cryptographic check that `proof.proofValue` is a valid signature over canonical bytes of the VC claims, using the operator's verificationMethod pubkey. v0.1 uses Ed25519; v0.7+ adds hybrid Ed25519+ML-DSA-65 — verifier MUST dispatch on `proof.type` not assume Ed25519. See `DID_AIEGIS_METHOD_SPEC_V01.md` §Crypto-agility.
4. **Check revocation status**: pull BSL credential from `/registry/status-list/v1`, decode bitstring, check bit at `statusListIndex`.
5. **(Optional) Session challenge**: if verifier wants session-binding (Attack 3 defense), issues their OWN challenge; agent signs with agent_priv_key; verifier checks against agent_pubkey embedded in did:aiegis or VC subject.

**PoP from issuance is NOT re-checked.** It was a one-time proof-of-possession at the moment of issuance. The current verifier doesn't need to re-prove that the issuance was legitimate; that's the operator's job (and the operator already enforced it before signing the passport).

## When verifiers SHOULD do session-bound challenge

If the verifier is operating in:
- High-value transaction context (financial transfer > €1000)
- High-trust delegation context (agent acting on user's behalf for irreversible action)
- Long-lived session (> 24hr from passport issuance)

Then verifier should add session-bound challenge-response on TOP of passport verification. Pseudocode:

```python
def verify_with_session_bind(passport, agent_pubkey):
    # Layer 1: passport check (PoP-at-issuance was already done, just verify signature)
    if not verify_operator_signature(passport):
        return REJECT
    if is_revoked(passport.agent_id):
        return REJECT

    # Layer 2: session-bound challenge (defends Attack 3)
    nonce = secrets.token_bytes(32)
    sig = ask_agent_to_sign(nonce)
    if not ed25519_verify(agent_pubkey, nonce, sig):
        return REJECT  # agent doesn't control private key right now

    return ACCEPT
```

The Layer-2 challenge is verifier-side, not AiEGIS-side. It's the same mechanism as `/api/agent/issue/challenge` but at the verification-time boundary.

## Operational implication for AiEGIS

We don't need to add anything to did:aiegis spec to support PoP-at-verification. It's a verifier-side optional extension.

What we COULD add as a v0.2 enhancement: a standardized "session-bound challenge" flow for `did:aiegis` that gives verifiers a cookbook recipe for Layer-2 challenge-response. Compose with `/api/agent/session-challenge` endpoint similar to `/api/agent/issue/challenge`.

**Recommendation:** defer to v0.2. Current did:aiegis v0.1 spec is sufficient for the standard case (passport sig + revocation check). Document Layer-2 as RECOMMENDED for high-value contexts.

## Add to did:aiegis spec v0.2 open questions

5. Should AiEGIS provide a standardized session-bound challenge endpoint (`/api/agent/session-challenge`) for verifiers to use as Layer-2 defense, or leave session-binding entirely to verifier's own implementation?

## Composes with

- DID_AIEGIS_METHOD_SPEC_V01.md — defines resolution shape; this doc defines what verifiers MUST/SHOULD do at resolve time.
- VC_ENVELOPE_EXPORT_SPEC_V01.md — VC envelope carries the passport; same proof-verification logic applies.
- VC_REVOCATION_LIST_SPEC_V01.md — Layer-1 revocation check.
- pop_challenge_storage.py — production module shipped 2026-05-10 14:48; same atomic-CAS pattern would apply if /api/agent/session-challenge added at v0.2.
- aegis_agent_passport_verify.py check_proof_of_possession — already a no-op for absent PoP; current behavior aligns with this spec (PoP is issuance-time, not verification-time).

## Empirical receipt

- ✓ check_proof_of_possession returns "no PoP declared — backward-compat with v1.0/v1.1" when field absent (verified by reading impl /opt/aegis/specs/cross-lane/aegis_agent_passport_verify.py)
- ✓ pop_challenge_storage.py + integration deployed 14:48; PoP-at-issuance now multi-worker-coherent
- ✓ All did:aiegis-cited W3C URLs verified 200 against EXACT shipped strings (per URL-verify pin)
