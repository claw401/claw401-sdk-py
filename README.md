# claw401

Python SDK for the Claw401 X401 wallet authentication protocol.

## Install

```bash
pip install claw401
```

## Overview

Implements the X401 challenge-response authentication flow for Solana Ed25519 wallet keys.

## Usage

### Generate and verify a challenge

```python
from claw401 import generate_challenge, verify_signature, InMemoryNonceCache
from claw401.types import SignedChallenge

nonce_cache = InMemoryNonceCache()

# Server: generate challenge
challenge = generate_challenge(domain="app.example.com")

# Client signs challenge_signing_bytes(challenge) with their Ed25519 key
# ...

# Server: verify
signed = SignedChallenge(
    challenge=challenge,
    signature="<base64-signature>",
    public_key="<base58-public-key>",
)
result = verify_signature(signed, "app.example.com", nonce_cache)

if result.valid:
    print(result.public_key)  # authenticated wallet address
```

### Create a session

```python
from claw401 import create_session, verify_session

session = create_session(
    public_key=result.public_key,
    domain="app.example.com",
    nonce=challenge.nonce,
    scopes=["read", "write"],
)

# Later: verify session
result = verify_session(session, "app.example.com", required_scopes=["write"])
```

### Agent attestation

```python
from claw401 import create_agent_attestation, verify_agent_attestation

attestation = create_agent_attestation(
    agent_key=agent_pubkey,
    operator_key=operator_pubkey,
    operator_secret_key=operator_signing_key,
    agent_id="my-agent-001",
    actions=["read:orders", "submit:tx"],
    mcp_tools=["get_order", "submit_settlement"],
    ttl_ms=24 * 60 * 60 * 1000,
)

result = verify_agent_attestation(attestation, expected_operator_key=operator_pubkey)
```

## License

Apache-2.0
