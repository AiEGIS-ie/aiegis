# `aiegis-agent-sdk` — Python + TS Package Design v0.1

**Authored:** 2026-05-10 ~16:27 IST per Trav directive (4) Phase 2 of Identity adoption strategy
**Composes with:** 2026-05-10_identity_default_adoption_strategy.md (sha ee32d094) Path B; DID_AIEGIS_METHOD_SPEC_V01.md (sha 62b228a0); VC_ENVELOPE_EXPORT_SPEC_V01.md (sha 709af301)

## Goal

Make "give my AI agent a cryptographic identity" a one-liner that any developer can drop into their LangChain/AutoGPT/CrewAI/Anthropic-SDK/OpenAI-SDK code.

## API design (Python)

```python
import aiegis

# Simplest path — auto-issues did:aiegis identity, signs all agent actions
agent = aiegis.create_agent(
    name="MyCustomerSupportBot",
    operator_id="acme_corp_ops",
    risk_classification="low",
    governance_policies=["EU_AI_ACT", "GDPR"]
)

# agent.passport — full v1.8 passport JSON
# agent.did — "did:aiegis:agent:z6Mkpz..."
# agent.sign(payload: bytes) -> bytes — Ed25519 signature
# agent.verify_response(other_agent_did: str, response: dict) -> bool — peer verification
```

### Drop-in for LangChain users

```python
from langchain.agents import create_agent
import aiegis

# Wrap any LangChain agent
identity = aiegis.create_identity(name="research-assistant", operator_id="myorg")
lc_agent = create_agent(...)
agent = aiegis.wrap(lc_agent, identity)

# Now lc_agent calls automatically include did:aiegis identity in headers
# + sign outbound prompts + log to BEACON registry
```

### Drop-in for OpenAI Assistants users

```python
from openai import OpenAI
import aiegis

client = aiegis.openai_client(api_key="sk-...", operator_id="myorg")
# client is a transparent proxy around OpenAI; every call signed + identity-tagged
assistant = client.beta.assistants.create(name="My Assistant", model="gpt-4")
```

### Drop-in for Anthropic SDK users

```python
import anthropic
import aiegis

anth = aiegis.anthropic_client(api_key="sk-ant-...", operator_id="myorg")
msg = anth.messages.create(model="claude-3.5-sonnet", messages=[...])
# Every message signed + identity-tagged
```

## API design (TypeScript)

```typescript
import { createAgent, createIdentity, wrap } from "aiegis-agent-sdk";

const agent = await createAgent({
  name: "MyAgent",
  operatorId: "acme_corp_ops",
  riskClassification: "low",
  governancePolicies: ["EU_AI_ACT", "GDPR"]
});

// Same wrap pattern for LangChain.js, AI SDK (Vercel), Anthropic TS SDK, OpenAI Node SDK
```

## Implementation surface

### Module layout (Python)

```
aiegis/
  __init__.py          # public API: create_agent, create_identity, wrap, ...
  identity.py          # Ed25519 keypair gen, did:aiegis encoding
  passport.py          # v1.8 passport construction
  vc.py                # W3C VC envelope export (per VC_ENVELOPE_EXPORT_SPEC)
  signer.py            # signs outbound payloads, verifies inbound
  wrappers/
    langchain.py
    openai.py
    anthropic.py
    crewai.py
  client.py            # AiEGIS API client (registers passport with /api/agent/issue)
  storage.py           # local keystore (macOS Keychain / Windows DPAPI / Linux keyring)
```

### Module layout (TypeScript)

```
aiegis-agent-sdk/
  src/
    index.ts          # public API
    identity.ts       # Ed25519 via @noble/curves
    passport.ts
    vc.ts
    signer.ts
    wrappers/
      langchain.ts
      openai.ts
      anthropic.ts
      ai-sdk.ts       # Vercel AI SDK
    client.ts
    storage.ts        # uses OS-level secure storage via node-keytar or platform-specific
  package.json
```

## Key generation + storage

- **Generate Ed25519 keypair** using cryptography (Python) or @noble/curves (TS) — both libraries are FIPS-validated.
- **Store private key** in OS-level secure storage:
  - macOS: Keychain via `keyring` (Python) or `node-keytar` (TS)
  - Windows: DPAPI via `keyring` or `node-keytar`
  - Linux: GNOME Keyring / KWallet via `keyring`
- **Public key + did:aiegis identifier** in plain config file (not secret).
- **First-run flow:** if no keypair exists, generate + store + register passport with AiEGIS via `/api/agent/issue`. ~3sec total.

## Distribution

- **Python:** PyPI as `aiegis-agent-sdk`. `pip install aiegis-agent-sdk`. Initial version: 0.1.0.
- **TypeScript/JavaScript:** npm as `@aiegis/agent-sdk`. `npm install @aiegis/agent-sdk`. Initial version: 0.1.0.

Both packages have:
- ✓ MIT or Apache-2.0 license (TBD)
- ✓ Comprehensive README with quickstart
- ✓ TypeScript types (Python via `py.typed` marker)
- ✓ Examples folder with end-to-end demos for each LLM SDK
- ✓ CI: pytest (Python), vitest (TS), publish to PyPI/npm on tag

## Ecosystem integration strategy

For maximum adoption, register aiegis-agent-sdk as an EXTENSION on:

- **LangChain integrations registry** (https://python.langchain.com/docs/integrations/) — submit PR with usage example
- **CrewAI third-party tools** — README mention + example
- **OpenAI Assistants ecosystem** — list on the Assistants Marketplace if/when it opens
- **Anthropic MCP integrations** — submit MCP server that exposes did:aiegis identity for Claude tools
- **Awesome lists** — awesome-langchain, awesome-llm-agents, awesome-ai-security

## Versioning + stability

- v0.1.0: initial public release. Marked EXPERIMENTAL. Breaking changes allowed.
- v0.2.0-v0.4.0: alpha cycle, stabilize API based on developer feedback.
- v0.5.0: feature-frozen, API frozen.
- v1.0.0: stable. SemVer guarantees from here.

## Open questions for v0.2

1. Should the SDK ship a built-in NMH classifier client, or rely on the customer's local AiEGIS Eye install? (Tradeoff: bundle-size vs install dependency.)
2. Should the SDK support OFFLINE-only mode (no network call to register passport)? Use case: air-gapped enterprise deployments.
3. License — MIT for max adoption, Apache 2.0 for patent grant clause? Lean Apache 2.0.
4. Telemetry — should SDK auto-report passport-issuance events back to AiEGIS for adoption metrics? Privacy concerns.

## Empirical receipts to be added during impl

- 5 fixtures × wrap(LangChain agent) × verify outbound prompts include did:aiegis header → 0 failures
- 5 fixtures × roundtrip passport ↔ VC envelope (per VC_ENVELOPE_EXPORT_SPEC) → 0 failures
- 3 fixtures × cross-SDK interop (LangChain agent + OpenAI agent + Anthropic agent verifying each other) → 0 failures

## Estimated engineering

- Python SDK: ~1-2 weeks (Velo or Nel lane, depending on bandwidth)
- TS SDK: ~1-2 weeks (parallel)
- LangChain wrapper: ~3-5 days
- OpenAI wrapper: ~2-3 days
- Anthropic wrapper: ~2-3 days
- CrewAI wrapper: ~2-3 days
- CI + PyPI/npm publish: ~2-3 days
- README + examples: ~3-5 days

**Total: ~3-4 weeks parallel V+N effort to ship v0.1.0 of both packages.**

## Decision needed

- (a) Approve v0.1.0 SDK build for Phase 2 of identity-default-adoption strategy
- (b) Pick lane assignment: Velo lane Python + Nel lane TS, OR Velo Python + RAV TS (when RAV returns Tuesday)
- (c) License decision: MIT vs Apache 2.0
- (d) Initial version number: 0.1.0 or 0.6.0 (matching browser-ext + native-msg-host)?

Per recommend-dont-ask: lean (a)+(b) Velo lane Python + Nel lane TS + (c) Apache 2.0 + (d) version 0.6.0 to match other AiEGIS components.

## Composes with

- 2026-05-10_identity_default_adoption_strategy.md (Path B = this design)
- DID_AIEGIS_METHOD_SPEC_V01.md (the identity layer this SDK distributes)
- VC_ENVELOPE_EXPORT_SPEC_V01.md (used by sdk's vc.py module)
- POP_DID_COMPOSITION_V01.md (Layer-2 session-bind hooks)
- v1.8 passport schema (the data structure SDK constructs)
- pop_challenge_storage.py (server-side dependency for /api/agent/issue PoP flow that SDK calls)
