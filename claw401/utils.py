"""
Encoding, hashing, and nonce utilities.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from typing import Any


def generate_nonce() -> str:
    """Generate a cryptographically random 32-byte nonce as a hex string."""
    return secrets.token_hex(32)


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def bytes_to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def base64_to_bytes(b64: str) -> bytes:
    return base64.b64decode(b64)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_session_id(nonce: str, public_key: str, domain: str, created_at: int) -> str:
    """Deterministic session ID: sha256(nonce:publicKey:domain:createdAt)."""
    raw = f"{nonce}:{public_key}:{domain}:{created_at}"
    return sha256_hex(raw.encode("utf-8"))


def derive_attestation_id(agent_key: str, operator_key: str, issued_at: int, nonce: str) -> str:
    """Deterministic attestation ID: sha256(agentKey:operatorKey:issuedAt:nonce)."""
    raw = f"{agent_key}:{operator_key}:{issued_at}:{nonce}"
    return sha256_hex(raw.encode("utf-8"))


def canonicalize(obj: Any) -> bytes:
    """
    Produce a canonical UTF-8 byte representation of a signing payload.
    Keys are sorted recursively. This matches the TypeScript and Rust implementations.
    """
    return json.dumps(_sort_keys(obj), separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sort_keys(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _sort_keys(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_sort_keys(v) for v in obj]
    return obj


def validate_base58_pubkey(pubkey: str) -> bytes:
    """
    Decode a base58-encoded Ed25519 public key to 32 bytes.
    Raises ValueError if the key is invalid.
    """
    import base58 as _base58  # type: ignore[import-untyped]
    decoded = _base58.b58decode(pubkey)
    if len(decoded) != 32:
        raise ValueError(f"Invalid public key length: expected 32 bytes, got {len(decoded)}")
    return bytes(decoded)
