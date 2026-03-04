"""
Session issuance and verification.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Optional, Sequence

from claw401.types import Session, DEFAULT_SESSION_TTL_MS
from claw401.utils import derive_session_id


@dataclass
class VerifySessionResult:
    valid: bool
    session: Optional[Session]
    reason: Optional[str] = None


def create_session(
    public_key: str,
    domain: str,
    nonce: str,
    scopes: Sequence[str] = ("read",),
    ttl_ms: int = DEFAULT_SESSION_TTL_MS,
) -> Session:
    """
    Create an authenticated session after successful signature verification.

    The session_id is deterministic: sha256(nonce:publicKey:domain:createdAt).

    Args:
        public_key: Authenticated wallet address (base58).
        domain:     Session domain.
        nonce:      Challenge nonce from the originating challenge.
        scopes:     Permission scopes. Default: ["read"].
        ttl_ms:     Session TTL in milliseconds. Default: 24 hours.

    Returns:
        Session instance.
    """
    created_at = int(time.time() * 1000)
    expires_at = created_at + ttl_ms
    session_id = derive_session_id(nonce, public_key, domain, created_at)

    return Session(
        session_id=session_id,
        public_key=public_key,
        scopes=tuple(scopes),
        domain=domain,
        created_at=created_at,
        expires_at=expires_at,
        nonce=nonce,
    )


def verify_session(
    session: Session,
    expected_domain: str,
    required_scopes: Sequence[str] = (),
    clock_skew_ms: int = 30_000,
) -> VerifySessionResult:
    """
    Verify a session is valid for the given domain and scope requirements.

    Args:
        session:         The session to verify.
        expected_domain: Domain the session must be bound to.
        required_scopes: All listed scopes must be present in session.scopes.
        clock_skew_ms:   Clock skew tolerance. Default: 30 seconds.

    Returns:
        VerifySessionResult.
    """
    now_ms = int(time.time() * 1000)

    # 1. Expiry
    if now_ms > session.expires_at + clock_skew_ms:
        return VerifySessionResult(False, None, "Session has expired")

    # 2. Domain binding
    if session.domain != expected_domain.strip().lower():
        return VerifySessionResult(False, None, "Session domain mismatch")

    # 3. Scope check
    for required in required_scopes:
        if required not in session.scopes:
            return VerifySessionResult(False, None, f"Missing required scope: {required}")

    return VerifySessionResult(True, session)


def serialize_session(session: Session) -> str:
    """Serialize a session to JSON string for storage."""
    return json.dumps(session.to_dict())


def deserialize_session(raw: str) -> Session:
    """Deserialize a session from its JSON representation. Does not validate."""
    return Session.from_dict(json.loads(raw))
