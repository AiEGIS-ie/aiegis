# aiegis-agent-sdk

One-line did:aiegis identity for AI agents.

```python
import aiegis_agent

agent = aiegis_agent.create_agent(name="support-bot")
agent.did             # 'did:aiegis:...'
agent.sign(payload)   # Ed25519 signature
agent.passport()      # signed passport for /api/agent/issue
```

## Status

SDK **0.6.3** — package scaffold + crypto primitives + storage + client + compliance integration.

**Spec conformance:** SDK 0.6.x conforms to AiEGIS spec wire format **v0.7**. SDK 0.7.x will conform to spec v0.8. The SDK and spec use independent version-spaces; this section updates once per major SDK release (not per minor bump).

SDK wrappers (LangChain, OpenAI, Anthropic, CrewAI, Vercel AI SDK) land starting SDK 0.7.0.

## Install

```bash
# Install from source (PyPI release pending v1.0)
git clone https://github.com/AiEGIS-ie/aiegis
cd aiegis/sdk
pip install --upgrade pip  # PEP-660 editable installs require pip >=21.3
pip install -e .
```

Requires Python 3.10+ and the `keyring` package (auto-installed) for OS-level
private-key storage (macOS Keychain / Windows DPAPI / Linux libsecret).

## Quickstart — issue + sign

```python
import aiegis_agent

# Idempotent: creates on first call, loads on subsequent calls
agent = aiegis_agent.create_agent(name="support-bot", operator_id="acme")

# Identity surface
print(agent.did)                # did:aiegis:agent:z6Mk...
print(agent.public_key_hex)

# Sign any payload (bytes -> 64-byte Ed25519 signature)
sig = agent.sign(b"hello world")

# Build a signed passport for /api/agent/issue
passport = agent.passport()
```

## Compliance bundles (optional v0.7 feature)

For EU AI Act Article 50 compliance bundle generation, the SDK integrates with
the `aiegis-compliance-bundle` package via lazy-import.

**Customer onboarding — first 5 min:**

1. Clone or install `aiegis-compliance-bundle` separately.
2. Set the `AIEGIS_COMPLIANCE_PATH` environment variable to point at the
   directory containing `generator.py`:

   ```bash
   export AIEGIS_COMPLIANCE_PATH=/opt/aiegis-compliance-bundle
   ```

3. Import + use:

   ```python
   import aiegis_agent
   from aiegis_compliance_bundle import BeaconEvent
   from datetime import datetime, timezone

   agent = aiegis_agent.create_agent(name="audit-bot")
   bundle = aiegis_agent.build_compliance_bundle(
       agent=agent,
       events=[...],
       customer_did="did:aiegis:customer:abc",
       valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
       valid_until=datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
       policy_bundle={"rulesRsSha256": "...", "libRsSha256": "...",
                      "policyJsonSha256": "...", "binarySha256": "..."},
   )
   ```

**Health-check before first call:**

```bash
python3 -m aiegis_agent doctor
```

Prints the resolved path, import status, and actionable next-step. Returns
exit code 0 if integration is ready, 1 if setup is incomplete. Use this in
CI to fail-loud at deploy time instead of at first-customer call.

If `AIEGIS_COMPLIANCE_PATH` is unset OR points at a non-existent directory,
`aiegis_agent.build_compliance_bundle` raises `ImportError` with a clear
message naming the env var. This is intentional — silent
`HAS_COMPLIANCE=False` would mask customer mis-config until call-time, which
is worse UX than fail-loud at import.

## Why

did:aiegis is the identity layer for the agent economy — verifiable,
revocable, EU-sovereign, chip-bound on hardware-attested hosts. Without an
SDK, did:aiegis is a spec on paper. With an SDK, every Python developer
building an AI agent gets a one-line plug-in to AiEGIS-issued identity.

## License

Apache-2.0.
