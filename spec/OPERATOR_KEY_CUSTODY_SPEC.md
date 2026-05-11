# AiEGIS Operator Key Custody — Cold-Storage Spec v0.1

**Authored:** 2026-05-10 ~15:33 IST per directive-(4) Identity research-mode
**Composes with:** DID_AIEGIS_METHOD_SPEC_V01.md (sha 62b228a0), VC_REVOCATION_LIST_SPEC_V01.md (sha dbceebcc), 2026-04-25_phase2_5_identity_model.md
**Threat being defended:** AiEGIS operator root key compromise — the load-bearing trust anchor of the entire did:aiegis identity ecosystem

## Why this spec matters

Per `DID_AIEGIS_VS_DID_WEB_TRADEOFF.md`: did:aiegis trust-root is "operator-issued Ed25519 keypair." The whole identity thesis collapses if this key leaks. Existing identity model (2026-04-25) cites "offline cold-storage Ed25519 keypair" but doesn't specify:
- What hardware?
- Where is it stored?
- Who can access it?
- How often is it used?
- What's the rotation schedule?
- What's the recovery procedure if lost?

These questions need answers BEFORE we register did:aiegis with W3C and onboard regulated-customer design partners.

## Hardware recommendation

**Operator root key MUST be generated + stored on FIPS 140-2 Level 3+ HSM.** Concrete options:

| Option | Vendor | Cost | Compliance |
|--------|--------|------|------------|
| YubiHSM 2 | Yubico | ~$650 | FIPS 140-2 Level 3 |
| AWS CloudHSM | AWS | ~$1.50/hr | FIPS 140-2 Level 3 |
| Thales Luna Network | Thales | ~$10K+ | FIPS 140-2 Level 3, eIDAS |
| Hardware token (YubiKey 5 FIPS) | Yubico | ~$80 | FIPS 140-2 Level 2 — NOT sufficient for root key |

**Recommendation: YubiHSM 2 for v0.1 (cost-appropriate for current scale), migrate to AWS CloudHSM or Thales Luna at first design-partner ramp.**

Reasoning: YubiHSM 2 is FIPS 140-2 L3, supports Ed25519 natively, ~$650 unit cost makes 2-of-3 multi-sig setup affordable ($1,950 total).

## Key generation ceremony

The operator root keypair generation MUST be a multi-party ceremony with:

1. **3 trusted operators present in person.** For v0.1 (Trav as sole operator): Trav + 1 hired witness + 1 signed-attestation observer (e.g. notary).
2. **Air-gapped laptop.** Booted from read-only USB Tails or NixOS ISO. Never connects to network.
3. **YubiHSM 2 initialized via `yubihsm-shell`.** Genkey command produces Ed25519 keypair. Pubkey is exported for publication; privkey never leaves the HSM.
4. **Pubkey published.** Written to AiEGIS root cert at `https://aiegis.ie/.well-known/operator-pubkey.pem`. Hash of pubkey embedded in code as the `AIEGIS_ROOT_PUBKEY` constant.
5. **Backup HSM(s) initialized.** 2-of-3 multi-sig: 2 backup YubiHSM 2 units initialized with shamir-shared key custody.
6. **Ceremony attestation signed.** Notary signs document attesting: time, place, parties, hardware serial numbers, pubkey fingerprint. Published with the pubkey.

## Custody procedure

- **Primary HSM:** locked safe at AiEGIS Ltd registered office (Ireland).
- **Backup HSM 1:** sealed envelope at Trav's residence safe.
- **Backup HSM 2:** sealed envelope at law firm of record (escrow).
- **HSM access PIN:** split via Shamir Secret Sharing 2-of-3, distributed to: Trav, one trusted operator (TBD), notarized escrow.

For v0.1 sole-operator phase: Trav holds primary HSM PIN. Backup PINs in Shamir 2-of-3 with escrow + 1 trusted person. Failure tolerance: any 2 of 3 can recover.

## Signing operations

The operator root key signs ONLY:
1. **AiEGIS sub-operator keys** (1-2x per year, low frequency). Sub-operator keys do the day-to-day passport issuance.
2. **Revocation list signing key** (1x at initialization, rotate annually).
3. **W3C BSL credential issuer key** (1x at initialization, rotate annually).
4. **Emergency key-rotation announcements** (only if root key suspected compromised).

The root key is NOT used for routine passport issuance. That's done by online sub-operator keys (different HSM, online, FIPS 140-2 Level 2 acceptable).

## Rotation schedule

- **Sub-operator keys:** rotate every 12 months.
- **Operator root key:** rotate every 5 years OR on suspected compromise.
- **BSL signing key:** rotate every 12 months.

Each rotation = signed announcement published at `https://aiegis.ie/.well-known/key-rotations.json` with old-pubkey + new-pubkey + cross-signature (old key signs new, new key signs old).

## Compromise response

If operator root key is suspected compromised:

1. **Within 1 hour:** broadcast revocation announcement signed by 2-of-3 Shamir-recovered backup keys.
2. **Within 24 hours:** publish new operator root pubkey via emergency rotation (cross-signed by 2-of-3 backup keys).
3. **All sub-operator keys signed by old root:** revoked immediately. Re-issued under new root.
4. **All passports issued by sub-operators:** valid until expiry (Ed25519 signatures still verify against archived sub-operator pubkeys).
5. **Customer dashboards:** notification banner "AiEGIS operator key rotated [timestamp]. No passport action required for already-issued credentials. New passport issuance restored within 24h."
6. **Public incident postmortem:** within 30 days, RFC-style writeup published.

## v0.2 enhancements

Open questions for v0.2:

1. **Multi-sig at root:** should operator-root-key be 2-of-3 multi-sig from day one (3 separate HSMs each holding a partial key, joint signatures required)? Tradeoff: stronger compromise resistance, slower ceremony.
2. **Threshold Ed25519:** FROST-Ed25519 (https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/) enables n-of-m threshold signing on Ed25519 — would replace Shamir-PIN-sharing with cryptographic threshold scheme.
3. **Hardware attestation:** require HSM remote-attestation as part of every signing operation, log attestation chain in revocation registry.
4. **Geographic distribution:** for EU jurisdiction (EU AI Act enforcement Aug 2026), require backup HSM in 2+ EU member states.

## Empirical verify

Cannot empirically test the ceremony spec yet (Trav has not yet executed the ceremony). v0.2 deliverable: ceremony rehearsal (without committing the actual root key) to validate procedure documentation + identify gaps.

Today's empirical: existing /.well-known/{agent,mcp}.json pattern works (verified earlier this session), so /.well-known/operator-pubkey.pem + /.well-known/key-rotations.json compose with existing nginx infra without new patterns.

## Composes with

- DID_AIEGIS_METHOD_SPEC_V01.md — operator-trust-root is the differentiator vs did:web; this spec defines how that trust-root is operationally protected.
- VC_REVOCATION_LIST_SPEC_V01.md — revocation list signing key is one of the keys signed by operator root.
- 2026-04-25_phase2_5_identity_model.md §4 — extends "offline cold-storage" from 1 line to operational spec.
- EU AI Act Article 26 (enforces 2026-08-02) — operator-key compromise has compliance implications; rotation schedule must satisfy "demonstrable security control."

## Decision

**LOCKED v0.1: YubiHSM 2 (FIPS 140-2 L3) + 2-of-3 Shamir + multi-party ceremony.** Move to AWS CloudHSM or Thales at first design-partner ramp.

To revisit only if: (a) FROST-Ed25519 threshold becomes production-grade (currently CFRG draft), (b) regulatory requirement forces FIPS 140-2 L4, (c) cost or operational profile of YubiHSM 2 proves wrong for scale, (d) PQC migration (see below) requires substrate change.

## Crypto-agility — PQC custody (forward-compat with v0.7+)

The operator root key is the HARDEST component to rotate (every credential ever issued chains back to it; rotation invalidates the trust anchor). PQC migration must be planned before v0.9 default-PQC issuance ramps.

**Constraint:** YubiHSM 2 firmware does not expose ML-DSA-65 or any PQC signature algorithm. Yubico has signaled a successor with PQC support; ship date unverified at time of writing.

**v0.7 hybrid-mode operator custody (interim):** maintain Ed25519 root in YubiHSM 2 (hardware-bound, FIPS 140-2 L3); introduce ML-DSA-65 software key wrapped under a YubiHSM-derived KEK with audit-logged unwrap-on-sign. This loses non-extractability for the PQC half but maintains hardware-bound auditability. Acceptable for v0.7 because the Ed25519 half remains fully hardware-bound (the half that proves "this hardware signed it"); the PQC half is the future-proofing layer.

**v0.9+ migration path (3 candidates, decide by 2027-Q1):**
1. **Yubico PQC-capable HSM** when ships — direct hardware-bound ML-DSA-65 issuance. Lowest operational change.
2. **AWS CloudHSM with PQC support** — CloudHSM has signaled PQC roadmap; defer to AWS public docs at decision time.
3. **Thales Luna 7 with PQC firmware** — Thales has shipped PQC HSM SKUs; cost much higher than YubiHSM but operationally proven.

Composes with `research/2026-05-10_pqc_migration_for_did_aiegis.md` for full algorithm/timing/library survey.
