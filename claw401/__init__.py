"""
claw401 — Python SDK for the Claw401 X401 wallet authentication protocol.

Exports:
    auth:    generate_challenge, verify_signature
    session: create_session, verify_session
    proof:   sign_proof, verify_proof
    agent:   create_agent_attestation, verify_agent_attestation
    types:   All dataclasses and TypedDicts
    utils:   Encoding, nonce, hashing utilities
    cache:   NonceCache, InMemoryNonceCache
"""

from claw401.auth import (
    generate_challenge,
    verify_signature,
    challenge_signing_bytes,
    encode_signature,
    VerifySignatureResult,
    GenerateChallengeOptions,
)
from claw401.session import (
    create_session,
    verify_session,
    serialize_session,
    deserialize_session,
    VerifySessionResult,
)
from claw401.proof import (
    sign_proof,
    verify_proof,
    VerifyProofResult,
)
from claw401.agent import (
    create_agent_attestation,
    verify_agent_attestation,
    serialize_attestation,
    deserialize_attestation,
    VerifyAttestationResult,
)
from claw401.cache import NonceCache, InMemoryNonceCache
from claw401 import types

__version__ = "0.1.0"
__all__ = [
    "generate_challenge",
    "verify_signature",
    "challenge_signing_bytes",
    "encode_signature",
    "VerifySignatureResult",
    "GenerateChallengeOptions",
    "create_session",
    "verify_session",
    "serialize_session",
    "deserialize_session",
    "VerifySessionResult",
    "sign_proof",
    "verify_proof",
    "VerifyProofResult",
    "create_agent_attestation",
    "verify_agent_attestation",
    "serialize_attestation",
    "deserialize_attestation",
    "VerifyAttestationResult",
    "NonceCache",
    "InMemoryNonceCache",
    "types",
]
