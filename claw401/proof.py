"""
Signed capability and identity proofs.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Literal, Optional

import nacl.signing
import nacl.exceptions

from claw401.types import Proof, PROTOCOL_VERSION
from claw401.utils import (
    generate_nonce,
    base64_to_bytes,
    bytes_to_base64,
    canonicalize,
    validate_base58_pubkey,
)


@dataclass
class VerifyProofResult:
    valid: bool
    proof: Optional[Proof]
    reason: Optional[str] = None


def sign_proof(
    type: Literal["capability", "identity", "delegation"],
    issuer_public_key: str,
    subject: str,
    claims: dict[str, Any],
    issuer_secret_key: bytes,
    ttl_ms: Optional[int] = None,
) -> Proof:
    """
    Sign a capability or identity proof.

    Args:
        type:               Proof type: "capability", "identity", or "delegation".
        issuer_public_key:  Issuer's base58 public key.
        subject:            Subject identifier (public key or opaque ID).
        claims:             Arbitrary claims dict.
        issuer_secret_key:  Ed25519 secret key (32 bytes seed).
        ttl_ms:             Optional TTL. If None, proof never expires.

    Returns:
        Signed Proof instance.
    """
    if len(issuer_secret_key) not in (32, 64):
        raise ValueError("issuer_secret_key must be 32-byte seed or 64-byte expanded key")

    # PyNaCl expects the 32-byte seed
    seed = issuer_secret_key[:32]
    signing_key = nacl.signing.SigningKey(seed)

    now_ms = int(time.time() * 1000)
    expires_at = (now_ms + ttl_ms) if ttl_ms is not None else None

    payload: dict[str, Any] = {
        "claims": claims,
        "issuedAt": now_ms,
        "issuer": issuer_public_key,
        "nonce": generate_nonce(),
        "subject": subject,
        "type": type,
        "version": PROTOCOL_VERSION,
    }
    if expires_at is not None:
        payload["expiresAt"] = expires_at

    payload_bytes = canonicalize(payload)
    signed = signing_key.sign(payload_bytes)
    # PyNaCl sign() prepends the signature to the message; extract first 64 bytes
    signature = bytes_to_base64(bytes(signed.signature))

    return Proof(
        type=type,
        issuer=issuer_public_key,
        subject=subject,
        claims=claims,
        issued_at=now_ms,
        expires_at=expires_at,
        nonce=payload["nonce"],
        signature=signature,
        version=PROTOCOL_VERSION,
    )


def verify_proof(
    proof: Proof,
    clock_skew_ms: int = 30_000,
) -> VerifyProofResult:
    """
    Verify a signed proof.

    Checks:
        1. Proof has not expired (if expires_at is set)
        2. Issuer public key is valid
        3. Ed25519 signature is valid over canonical payload

    Args:
        proof:         The proof to verify.
        clock_skew_ms: Clock skew tolerance. Default: 30 seconds.
    """
    now_ms = int(time.time() * 1000)

    if proof.expires_at is not None and now_ms > proof.expires_at + clock_skew_ms:
        return VerifyProofResult(False, None, "Proof has expired")

    try:
        pubkey_bytes = validate_base58_pubkey(proof.issuer)
    except Exception as e:
        return VerifyProofResult(False, None, f"Invalid issuer public key: {e}")

    try:
        sig_bytes = base64_to_bytes(proof.signature)
    except Exception:
        return VerifyProofResult(False, None, "Invalid signature encoding")

    payload_bytes = canonicalize(proof.payload_dict())

    try:
        verify_key = nacl.signing.VerifyKey(pubkey_bytes)
        verify_key.verify(payload_bytes, sig_bytes)
    except nacl.exceptions.BadSignatureError:
        return VerifyProofResult(False, None, "Signature verification failed")
    except Exception as e:
        return VerifyProofResult(False, None, f"Verification error: {e}")

    return VerifyProofResult(True, proof)
