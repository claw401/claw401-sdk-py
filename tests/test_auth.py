"""
Tests for the X401 authentication flow.
"""

import time
import pytest
import nacl.signing

from claw401.auth import generate_challenge, verify_signature, challenge_signing_bytes, encode_signature
from claw401.cache import InMemoryNonceCache
from claw401.types import SignedChallenge
from claw401.utils import bytes_to_base64


def make_keypair():
    return nacl.signing.SigningKey.generate()


def pubkey_to_base58(verify_key: nacl.signing.VerifyKey) -> str:
    import base58
    return base58.b58encode(bytes(verify_key)).decode("ascii")


def sign_challenge(challenge, signing_key):
    payload = challenge_signing_bytes(challenge)
    signed = signing_key.sign(payload)
    signature = encode_signature(bytes(signed.signature))
    public_key = pubkey_to_base58(signing_key.verify_key)
    return SignedChallenge(challenge=challenge, signature=signature, public_key=public_key)


class TestGenerateChallenge:
    def test_returns_challenge_with_correct_structure(self):
        ch = generate_challenge("example.com")
        assert len(ch.nonce) == 64
        assert ch.domain == "example.com"
        assert ch.version == "x401/1.0"
        assert ch.expires_at > ch.issued_at

    def test_normalizes_domain_to_lowercase(self):
        ch = generate_challenge("Example.COM")
        assert ch.domain == "example.com"

    def test_raises_on_empty_domain(self):
        with pytest.raises(ValueError):
            generate_challenge("")

    def test_respects_custom_ttl(self):
        ch = generate_challenge("test.com", ttl_ms=60_000)
        assert ch.expires_at - ch.issued_at == 60_000


class TestVerifySignature:
    def setup_method(self):
        self.signing_key = make_keypair()
        self.cache = InMemoryNonceCache()

    def test_accepts_valid_signature(self):
        ch = generate_challenge("app.test")
        signed = sign_challenge(ch, self.signing_key)
        result = verify_signature(signed, "app.test", self.cache)
        assert result.valid is True
        assert result.public_key is not None

    def test_rejects_expired_challenge(self):
        ch = generate_challenge("app.test", ttl_ms=-1000)
        signed = sign_challenge(ch, self.signing_key)
        result = verify_signature(signed, "app.test", self.cache, clock_skew_ms=0)
        assert result.valid is False
        assert result.error_code == "CHALLENGE_EXPIRED"

    def test_rejects_domain_mismatch(self):
        ch = generate_challenge("correct.com")
        signed = sign_challenge(ch, self.signing_key)
        result = verify_signature(signed, "wrong.com", self.cache)
        assert result.valid is False
        assert result.error_code == "INVALID_DOMAIN"

    def test_rejects_replayed_nonce(self):
        ch = generate_challenge("app.test")
        signed = sign_challenge(ch, self.signing_key)

        first = verify_signature(signed, "app.test", self.cache)
        assert first.valid is True

        second = verify_signature(signed, "app.test", self.cache)
        assert second.valid is False
        assert second.error_code == "NONCE_REPLAYED"

    def test_rejects_invalid_signature(self):
        ch = generate_challenge("app.test")
        other_key = make_keypair()
        payload = challenge_signing_bytes(ch)
        wrong_sig = other_key.sign(payload).signature
        signed = SignedChallenge(
            challenge=ch,
            signature=encode_signature(bytes(wrong_sig)),
            public_key=pubkey_to_base58(self.signing_key.verify_key),
        )
        result = verify_signature(signed, "app.test", self.cache)
        assert result.valid is False
        assert result.error_code == "INVALID_SIGNATURE"
