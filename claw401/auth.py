"""
Challenge generation and signature verification (X401 protocol).

Security invariants:
- Challenges are domain-bound
- Challenges expire after DEFAULT_CHALLENGE_TTL_MS
- Nonce replay protection via caller-supplied cache
- Private keys never enter this module
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import nacl.signing
import nacl.exceptions

from claw401.cache import NonceCache
from claw401.types import Challenge, SignedChallenge, DEFAULT_CHALLENGE_TTL_MS
from claw401.utils import (
    generate_nonce,
    base64_to_bytes,
    bytes_to_base64,
    canonicalize,
    validate_base58_pubkey,
)


@dataclass
class GenerateChallengeOptions:
    domain: str
    ttl_ms: int = DEFAULT_CHALLENGE_TTL_MS


def generate_challenge(
    domain: str,
    ttl_ms: int = DEFAULT_CHALLENGE_TTL_MS,
) -> Challenge:
    """
    Generate a domain-scoped authentication challenge.

    Args:
        domain:  The relying party domain (e.g., 'app.example.com').
        ttl_ms:  Challenge lifetime in milliseconds. Default: 5 minutes.

    Returns:
        A Challenge instance ready to send to the client.
    """
    if not domain or not domain.strip():
        raise ValueError("Domain must not be empty")

    now_ms = int(time.time() * 1000)
    return Challenge(
        nonce=generate_nonce(),
        domain=domain.strip().lower(),
        issued_at=now_ms,
        expires_at=now_ms + ttl_ms,
    )


def challenge_signing_bytes(challenge: Challenge) -> bytes:
    """
    Return the canonical bytes that the client must sign.
    Uses the same canonicalization as the TypeScript and Rust implementations.
    """
    return canonicalize(challenge.to_dict())


def encode_signature(signature_bytes: bytes) -> str:
    """Base64-encode a raw Ed25519 signature for inclusion in SignedChallenge."""
    return bytes_to_base64(signature_bytes)


@dataclass
class VerifySignatureResult:
    valid: bool
    public_key: Optional[str]
    reason: Optional[str] = None
    error_code: Optional[str] = None


def verify_signature(
    signed_challenge: SignedChallenge,
    expected_domain: str,
    nonce_cache: NonceCache,
    clock_skew_ms: int = 30_000,
) -> VerifySignatureResult:
    """
    Verify a signed challenge.

    Checks, in order:
        1. Challenge has not expired
        2. Domain matches
        3. Nonce has not been replayed
        4. Signature is valid Ed25519 over canonical payload
        5. Mark nonce as consumed

    Args:
        signed_challenge:  The signed challenge from the client.
        expected_domain:   Domain the server expects.
        nonce_cache:       Nonce replay cache.
        clock_skew_ms:     Clock skew tolerance. Default: 30 seconds.

    Returns:
        VerifySignatureResult with valid=True and public_key on success.
    """
    challenge = signed_challenge.challenge
    now_ms = int(time.time() * 1000)

    # 1. Expiry
    if now_ms > challenge.expires_at + clock_skew_ms:
        return VerifySignatureResult(False, None, "Challenge has expired", "CHALLENGE_EXPIRED")

    if challenge.issued_at > now_ms + clock_skew_ms:
        return VerifySignatureResult(
            False, None, "Challenge issuedAt is in the future", "CHALLENGE_NOT_YET_VALID"
        )

    # 2. Domain binding
    if challenge.domain != expected_domain.strip().lower():
        return VerifySignatureResult(False, None, "Domain mismatch", "INVALID_DOMAIN")

    # 3. Replay protection
    if nonce_cache.has(challenge.nonce):
        return VerifySignatureResult(False, None, "Nonce has already been used", "NONCE_REPLAYED")

    # 4. Decode public key
    try:
        pubkey_bytes = validate_base58_pubkey(signed_challenge.public_key)
    except (ValueError, Exception) as e:
        return VerifySignatureResult(False, None, f"Invalid public key: {e}", "INVALID_PUBLIC_KEY")

    # 5. Decode and verify signature
    try:
        sig_bytes = base64_to_bytes(signed_challenge.signature)
    except Exception:
        return VerifySignatureResult(False, None, "Invalid signature encoding", "ENCODING_ERROR")

    payload = challenge_signing_bytes(challenge)

    try:
        verify_key = nacl.signing.VerifyKey(pubkey_bytes)
        verify_key.verify(payload, sig_bytes)
    except nacl.exceptions.BadSignatureError:
        return VerifySignatureResult(False, None, "Signature verification failed", "INVALID_SIGNATURE")
    except Exception as e:
        return VerifySignatureResult(False, None, f"Verification error: {e}", "INVALID_SIGNATURE")

    # Mark nonce as consumed — only after all checks pass
    nonce_cache.set(challenge.nonce)

    return VerifySignatureResult(True, signed_challenge.public_key)
