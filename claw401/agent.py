"""
Agent attestation: create and verify operator-signed agent identity documents.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Optional, Sequence

import nacl.signing
import nacl.exceptions

from claw401.types import AgentAttestation, AgentCapabilities, PROTOCOL_VERSION
from claw401.utils import (
    generate_nonce,
    base64_to_bytes,
    bytes_to_base64,
    canonicalize,
    validate_base58_pubkey,
    derive_attestation_id,
)


@dataclass
class VerifyAttestationResult:
    valid: bool
    attestation: Optional[AgentAttestation]
    reason: Optional[str] = None


def create_agent_attestation(
    agent_key: str,
    operator_key: str,
    operator_secret_key: bytes,
    agent_id: str,
    actions: Sequence[str],
    resources: Sequence[str] = (),
    mcp_tools: Sequence[str] = (),
    ttl_ms: Optional[int] = None,
) -> AgentAttestation:
    """
    Create and sign an agent attestation.

    Called by the operator. Signs the canonical payload with the operator's Ed25519 key.

    Args:
        agent_key:            Agent's base58 public key.
        operator_key:         Operator's base58 public key.
        operator_secret_key:  Operator's Ed25519 secret key (32-byte seed or 64-byte expanded).
        agent_id:             Human-readable agent identifier.
        actions:              Permitted action strings.
        resources:            Optional resource patterns.
        mcp_tools:            Optional MCP tool names.
        ttl_ms:               Optional TTL in ms. None = no expiry.

    Returns:
        Signed AgentAttestation.
    """
    if len(operator_secret_key) not in (32, 64):
        raise ValueError("operator_secret_key must be 32-byte seed or 64-byte expanded key")

    seed = operator_secret_key[:32]
    signing_key = nacl.signing.SigningKey(seed)

    now_ms = int(time.time() * 1000)
    nonce = generate_nonce()
    expires_at = (now_ms + ttl_ms) if ttl_ms is not None else None
    attestation_id = derive_attestation_id(agent_key, operator_key, now_ms, nonce)

    capabilities = AgentCapabilities(
        actions=tuple(actions),
        resources=tuple(resources),
        mcp_tools=tuple(mcp_tools),
    )

    attestation = AgentAttestation(
        attestation_id=attestation_id,
        agent_key=agent_key,
        operator_key=operator_key,
        capabilities=capabilities,
        agent_id=agent_id,
        issued_at=now_ms,
        expires_at=expires_at,
        nonce=nonce,
        signature="",  # placeholder until signed
        version=PROTOCOL_VERSION,
    )

    payload_bytes = canonicalize(attestation.payload_dict())
    signed = signing_key.sign(payload_bytes)
    signature = bytes_to_base64(bytes(signed.signature))

    return AgentAttestation(
        attestation_id=attestation_id,
        agent_key=agent_key,
        operator_key=operator_key,
        capabilities=capabilities,
        agent_id=agent_id,
        issued_at=now_ms,
        expires_at=expires_at,
        nonce=nonce,
        signature=signature,
        version=PROTOCOL_VERSION,
    )


def verify_agent_attestation(
    attestation: AgentAttestation,
    expected_operator_key: Optional[str] = None,
    clock_skew_ms: int = 30_000,
) -> VerifyAttestationResult:
    """
    Verify an agent attestation.

    Checks:
        1. Attestation has not expired (if expires_at is set)
        2. Operator key matches expected_operator_key (if provided)
        3. Ed25519 signature is valid

    Args:
        attestation:           The attestation to verify.
        expected_operator_key: If provided, operator key must match exactly.
        clock_skew_ms:         Clock skew tolerance. Default: 30 seconds.
    """
    now_ms = int(time.time() * 1000)

    if attestation.expires_at is not None and now_ms > attestation.expires_at + clock_skew_ms:
        return VerifyAttestationResult(False, None, "Attestation has expired")

    if expected_operator_key is not None and attestation.operator_key != expected_operator_key:
        return VerifyAttestationResult(False, None, "Operator key mismatch")

    try:
        pubkey_bytes = validate_base58_pubkey(attestation.operator_key)
    except Exception as e:
        return VerifyAttestationResult(False, None, f"Invalid operator public key: {e}")

    try:
        sig_bytes = base64_to_bytes(attestation.signature)
    except Exception:
        return VerifyAttestationResult(False, None, "Invalid signature encoding")

    payload_bytes = canonicalize(attestation.payload_dict())

    try:
        verify_key = nacl.signing.VerifyKey(pubkey_bytes)
        verify_key.verify(payload_bytes, sig_bytes)
    except nacl.exceptions.BadSignatureError:
        return VerifyAttestationResult(False, None, "Signature verification failed")
    except Exception as e:
        return VerifyAttestationResult(False, None, f"Verification error: {e}")

    return VerifyAttestationResult(True, attestation)


def serialize_attestation(attestation: AgentAttestation) -> str:
    """Serialize attestation to base64 for MCP context header injection."""
    return base64.b64encode(json.dumps(attestation.to_dict()).encode("utf-8")).decode("ascii")


def deserialize_attestation(encoded: str) -> AgentAttestation:
    """Deserialize attestation from MCP context header. Does not validate."""
    return AgentAttestation.from_dict(json.loads(base64.b64decode(encoded).decode("utf-8")))
