"""
Core types for the Claw401 X401 protocol.
All types are dataclasses or TypedDicts for clear structural typing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional


PROTOCOL_VERSION = "x401/1.0"
DEFAULT_CHALLENGE_TTL_MS = 5 * 60 * 1000    # 5 minutes
DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000  # 24 hours


@dataclass(frozen=True)
class Challenge:
    """
    A server-generated, domain-scoped authentication challenge.
    """
    nonce: str          # 32-byte hex (64 chars)
    domain: str         # lowercase, trimmed domain string
    issued_at: int      # Unix ms
    expires_at: int     # Unix ms
    version: str = PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Return canonical dict for JSON serialization / signing."""
        return {
            "domain": self.domain,
            "expiresAt": self.expires_at,
            "issuedAt": self.issued_at,
            "nonce": self.nonce,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Challenge":
        return cls(
            nonce=d["nonce"],
            domain=d["domain"],
            issued_at=d["issuedAt"],
            expires_at=d["expiresAt"],
            version=d.get("version", PROTOCOL_VERSION),
        )


@dataclass(frozen=True)
class SignedChallenge:
    challenge: Challenge
    signature: str   # base64-encoded Ed25519 signature
    public_key: str  # base58-encoded public key


@dataclass(frozen=True)
class Session:
    session_id: str    # sha256-derived deterministic ID
    public_key: str    # base58 wallet address
    scopes: tuple[str, ...]
    domain: str
    created_at: int    # Unix ms
    expires_at: int    # Unix ms
    nonce: str         # originating challenge nonce

    def to_dict(self) -> dict[str, Any]:
        return {
            "sessionId": self.session_id,
            "publicKey": self.public_key,
            "scopes": list(self.scopes),
            "domain": self.domain,
            "createdAt": self.created_at,
            "expiresAt": self.expires_at,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Session":
        return cls(
            session_id=d["sessionId"],
            public_key=d["publicKey"],
            scopes=tuple(d["scopes"]),
            domain=d["domain"],
            created_at=d["createdAt"],
            expires_at=d["expiresAt"],
            nonce=d["nonce"],
        )


@dataclass(frozen=True)
class AgentCapabilities:
    actions: tuple[str, ...]
    resources: tuple[str, ...] = field(default_factory=tuple)
    mcp_tools: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"actions": list(self.actions)}
        if self.resources:
            d["resources"] = list(self.resources)
        if self.mcp_tools:
            d["mcpTools"] = list(self.mcp_tools)
        return d


@dataclass(frozen=True)
class AgentAttestation:
    attestation_id: str
    agent_key: str
    operator_key: str
    capabilities: AgentCapabilities
    agent_id: str
    issued_at: int
    nonce: str
    signature: str     # base64-encoded
    version: str = PROTOCOL_VERSION
    expires_at: Optional[int] = None

    def payload_dict(self) -> dict[str, Any]:
        """Returns the canonical dict used for signing (excludes signature)."""
        d: dict[str, Any] = {
            "agentId": self.agent_id,
            "agentKey": self.agent_key,
            "attestationId": self.attestation_id,
            "capabilities": self.capabilities.to_dict(),
            "issuedAt": self.issued_at,
            "nonce": self.nonce,
            "operatorKey": self.operator_key,
            "version": self.version,
        }
        if self.expires_at is not None:
            d["expiresAt"] = self.expires_at
        return d

    def to_dict(self) -> dict[str, Any]:
        d = self.payload_dict()
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AgentAttestation":
        caps_d = d["capabilities"]
        caps = AgentCapabilities(
            actions=tuple(caps_d["actions"]),
            resources=tuple(caps_d.get("resources", [])),
            mcp_tools=tuple(caps_d.get("mcpTools", [])),
        )
        return cls(
            attestation_id=d["attestationId"],
            agent_key=d["agentKey"],
            operator_key=d["operatorKey"],
            capabilities=caps,
            agent_id=d["agentId"],
            issued_at=d["issuedAt"],
            expires_at=d.get("expiresAt"),
            nonce=d["nonce"],
            signature=d["signature"],
            version=d.get("version", PROTOCOL_VERSION),
        )


@dataclass(frozen=True)
class Proof:
    type: Literal["capability", "identity", "delegation"]
    issuer: str
    subject: str
    claims: dict[str, Any]
    issued_at: int
    nonce: str
    signature: str
    version: str = PROTOCOL_VERSION
    expires_at: Optional[int] = None

    def payload_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "claims": self.claims,
            "issuedAt": self.issued_at,
            "issuer": self.issuer,
            "nonce": self.nonce,
            "subject": self.subject,
            "type": self.type,
            "version": self.version,
        }
        if self.expires_at is not None:
            d["expiresAt"] = self.expires_at
        return d

    def to_dict(self) -> dict[str, Any]:
        d = self.payload_dict()
        d["signature"] = self.signature
        return d
