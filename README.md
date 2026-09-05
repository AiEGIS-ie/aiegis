# AIEGIS — Substrate-Anchored AI Agent Identity

**Open standard for cryptographically anchoring AI agent identity to the silicon they run on.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-public%20preview-orange.svg)](#status)

---

## The problem

AI agents act on behalf of operators. Customers, regulators, and counterparties need to answer one question for every action:

> Did **this specific agent**, running on **this specific machine**, actually produce **this signed claim**?

Today the agent's signing key is mobile — a software keypair on disk, a cloud bearer token, or a vendor-managed credential. Steal the file, you impersonate the agent indefinitely. There is no cryptographic answer to *which machine was this?*

## What AIEGIS is

A **substrate-anchored agent identity standard**: the agent's signing key is generated inside, and remains inside, a hardware root-of-trust on the host. Every signed action is a chip-side operation.

This repository contains:

- `/spec` — `did:aiegis` DID method spec + substrate-binding spec + compliance bundle spec
- `/substrate-pack` — Python reference verifiers for TPM 2.0 / Apple Secure Enclave / Intel TDX / AMD SEV-SNP
- `/sdk` — `aiegis-agent-sdk` Python client (pip-installable, one-line `create_agent()`)
- `/compliance-bundle` — EU AI Act Article 50 compliance bundle generator + verifier
- `/docs` — design records, threat model, deployment guides

## Why open

AIEGIS is the spec + reference implementation. It is free under Apache 2.0. Adopt it, run your own operator, fork it, fight it.

The paid service we run on top — registry, trust root, managed substrate verification, EU sovereign hosting — stays paid. Open spec, paid operator. Same model as OAuth/Auth0, OpenID/Okta, TLS/Let's Encrypt.

## Status

**Public preview, v0.7.** Spec is stable enough for design-partner integration. v1.0 ships at first paying customer.

- Substrate pack: 3 verifier lanes covering 4 substrate types, 294+ tests combined (219 on substrate-pack, 75 on compliance-bundle), regression-locked
- Spec: aligned with W3C DID Core, VC Data Model v2; v0.7 cryptosuite is `eddsa-rdfc-2022` only; v0.8 adds `eddsa-jcs-2022` with full JCS canonicalization (RFC 8785)
- Compliance bundle: Ed25519 signatures, v0.8 adds hybrid Ed25519+ML-DSA-65 per NIST FIPS 204
- AIVSS contributions: [#31 — Runtime Enforcement](https://github.com/OWASP/www-project-artificial-intelligence-vulnerability-scoring-system/issues/31), [#32 — Multi-Agent Governance](https://github.com/OWASP/www-project-artificial-intelligence-vulnerability-scoring-system/issues/32), [#33 — Mutation Testing](https://github.com/OWASP/www-project-artificial-intelligence-vulnerability-scoring-system/issues/33)

**Not yet shipping:** ARM CCA verifier (production attestation flow pending), federated multi-operator registry, self-serve SMB checkout.

## Quick start

```bash
# Install from source (PyPI release pending v1.0)
git clone https://github.com/AIEGIS-ie/aiegis
cd aiegis/sdk
pip install --upgrade pip  # PEP-660 editable installs require pip >=21.3
pip install -e .

python3 -c "
from aiegis_agent import create_agent
agent = create_agent(name='my-agent')
print(agent.did)
"
```

For verifier integration:

```bash
git clone https://github.com/AIEGIS-ie/aiegis
cd aiegis
pip install --upgrade pip       # PEP-660 editable installs require pip >=21.3
pip install -e ./sdk            # test suites import aiegis_agent
python3 -m pytest
```

The `compliance-bundle/` directory is a flat-file Python module — there is no pip package for it in v0.7. Import directly from the cloned path:

```bash
cd aiegis/compliance-bundle
python3 -c "from errors import IdentityError, ErrorCode; print(ErrorCode.IDENTITY_NOT_FOUND.value)"
```

Or set `PYTHONPATH` if you need to import from another directory:

```bash
PYTHONPATH=aiegis/compliance-bundle python3 -c "from generator import build_bundle; help(build_bundle)"
```

## Spec

The substrate-binding spec is at `/spec/SUBSTRATE_BINDING_SPEC.md`. The `did:aiegis` DID method is at `/spec/DID_METHOD_SPEC.md`. Compliance-bundle spec at `/spec/COMPLIANCE_BUNDLE_SPEC.md`.

JSON-LD contexts are live at `https://aiegis.ie/ns/compliance/v1` and `https://aiegis.ie/ns/substrate/v1`.

## Security

See [SECURITY.md](SECURITY.md) for disclosure.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Design partners welcome before 2026-05-31.

## Contact

- Technical: hello@aiegis.ie
- Standards: OWASP AIVSS GitHub
- Website: https://aiegis.ie

---

*Apache License 2.0. See [LICENSE](LICENSE).*
