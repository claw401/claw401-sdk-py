"""Tests for agent attestation."""

import pytest
import nacl.signing
import base58

from claw401.agent import create_agent_attestation, verify_agent_attestation


def pubkey_to_base58(verify_key: nacl.signing.VerifyKey) -> str:
    return base58.b58encode(bytes(verify_key)).decode("ascii")


class TestAgentAttestation:
    def setup_method(self):
        self.operator_key = nacl.signing.SigningKey.generate()
        self.agent_key = nacl.signing.SigningKey.generate()

    def test_create_and_verify(self):
        attestation = create_agent_attestation(
            agent_key=pubkey_to_base58(self.agent_key.verify_key),
            operator_key=pubkey_to_base58(self.operator_key.verify_key),
            operator_secret_key=bytes(self.operator_key),
            agent_id="test-agent-001",
            actions=["read:data", "submit:tx"],
        )
        result = verify_agent_attestation(attestation)
        assert result.valid is True
        assert result.attestation is not None
        assert result.attestation.agent_id == "test-agent-001"

    def test_rejects_expired(self):
        attestation = create_agent_attestation(
            agent_key=pubkey_to_base58(self.agent_key.verify_key),
            operator_key=pubkey_to_base58(self.operator_key.verify_key),
            operator_secret_key=bytes(self.operator_key),
            agent_id="test-agent-002",
            actions=["read:data"],
            ttl_ms=-1000,
        )
        result = verify_agent_attestation(attestation, clock_skew_ms=0)
        assert result.valid is False
        assert result.reason is not None and "expired" in result.reason.lower()

    def test_rejects_wrong_operator_key(self):
        wrong_key = nacl.signing.SigningKey.generate()
        attestation = create_agent_attestation(
            agent_key=pubkey_to_base58(self.agent_key.verify_key),
            operator_key=pubkey_to_base58(self.operator_key.verify_key),
            operator_secret_key=bytes(self.operator_key),
            agent_id="test-agent-003",
            actions=["read:data"],
        )
        result = verify_agent_attestation(
            attestation,
            expected_operator_key=pubkey_to_base58(wrong_key.verify_key),
        )
        assert result.valid is False
        assert result.reason is not None and "mismatch" in result.reason.lower()
