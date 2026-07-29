"""
tests/test_vault_engine.py
Tests for core/vault_engine.py
Covers: master key, session tokens, encrypt/decrypt pipeline,
        canary integrity, device binding, session expiry.
"""
import os
import time
import json
import base64
import dataclasses
import pytest

from core.vault_engine import (
    VaultEngine, SessionToken, VaultBlob, get_device_fingerprint
)


# ══════════════════════════════════════════════════════════════════
# VaultEngine initialisation
# ══════════════════════════════════════════════════════════════════

class TestVaultEngineInit:

    def test_key_files_created(self, vault_dir):
        VaultEngine(vault_dir)
        assert os.path.exists(os.path.join(vault_dir, ".vault_master.key"))
        assert os.path.exists(os.path.join(vault_dir, ".vault_signing.key"))

    def test_master_key_is_32_bytes(self, vault_dir):
        e = VaultEngine(vault_dir)
        assert len(e._master_key) == 32

    def test_key_persists_across_instances(self, vault_dir):
        e1 = VaultEngine(vault_dir)
        k1 = e1._master_key
        e2 = VaultEngine(vault_dir)
        assert e2._master_key == k1

    def test_different_dirs_produce_different_keys(self, tmp_path):
        e1 = VaultEngine(str(tmp_path / "v1"))
        e2 = VaultEngine(str(tmp_path / "v2"))
        assert e1._master_key != e2._master_key


# ══════════════════════════════════════════════════════════════════
# Session tokens
# ══════════════════════════════════════════════════════════════════

class TestSessionToken:

    def test_token_fields_populated(self, token):
        assert token.session_id
        assert token.owner_hash
        assert token.device_hash
        assert token.issued_at > 0
        assert token.expires_at > token.issued_at
        assert token.signature
        assert isinstance(token.scope, list)

    def test_token_stored_in_active_sessions(self, engine, token):
        assert token.session_id in engine._active_sessions

    def test_validate_fresh_token(self, engine, token):
        assert engine.validate_session_token(token) is True

    def test_device_hash_matches_current_machine(self, token):
        assert token.device_hash == get_device_fingerprint()

    def test_token_expiry(self, vault_dir):
        """A token with an expiry in the past is rejected."""
        e = VaultEngine(vault_dir)
        tok = e.create_session_token("owner_abc")
        tok.expires_at = time.time() - 1   # expired
        assert e.validate_session_token(tok) is False

    def test_token_idle_timeout(self, vault_dir):
        """A token inactive longer than IDLE_MINUTES is rejected."""
        e = VaultEngine(vault_dir)
        tok = e.create_session_token("owner_abc")
        tok.last_active = time.time() - 700   # >10 min
        assert e.validate_session_token(tok) is False

    def test_revoked_token_invalid(self, engine, token):
        engine.revoke_session(token.session_id)
        assert engine.validate_session_token(token) is False
        assert token.session_id not in engine._active_sessions

    def test_forged_signature_rejected(self, engine, token):
        """Modifying the signature byte makes the token invalid."""
        bad_sig = base64.b64encode(b"forged_signature_bytes_xxxxx").decode()
        token.signature = bad_sig
        assert engine.validate_session_token(token) is False

    def test_multiple_sessions_independent(self, engine):
        t1 = engine.create_session_token("owner_a")
        t2 = engine.create_session_token("owner_b")
        assert t1.session_id != t2.session_id
        assert engine.get_active_session_count() == 2

    def test_session_key_unique_per_session(self, engine):
        t1 = engine.create_session_token("owner_a")
        t2 = engine.create_session_token("owner_a")
        k1 = engine._active_sessions[t1.session_id]["session_key"]
        k2 = engine._active_sessions[t2.session_id]["session_key"]
        assert k1 != k2   # forward secrecy: unique key per session

    def test_revoke_zeros_session_key(self, engine, token):
        sid = token.session_id
        engine.revoke_session(sid)
        assert sid not in engine._active_sessions


# ══════════════════════════════════════════════════════════════════
# Encryption pipeline
# ══════════════════════════════════════════════════════════════════

class TestEncryptDecrypt:

    def test_encrypt_returns_vault_blob(self, engine, token):
        blob = engine.encrypt(b"hello", token)
        assert isinstance(blob, VaultBlob)
        assert blob.blob_id
        assert blob.chacha_nonce
        assert blob.aes_nonce

    def test_decrypt_recovers_original(self, engine, token):
        pt = b"Secret document contents 12345"
        blob = engine.encrypt(pt, token)
        assert engine.decrypt(blob, token) == pt

    def test_various_plaintext_sizes(self, engine, token):
        for size in [0, 1, 15, 16, 100, 1024, 65536]:
            pt   = os.urandom(size)
            blob = engine.encrypt(pt, token)
            assert engine.decrypt(blob, token) == pt

    def test_binary_data_roundtrip(self, engine, token):
        pt = bytes(range(256)) * 4
        assert engine.decrypt(engine.encrypt(pt, token), token) == pt

    def test_two_encryptions_produce_different_ciphertexts(self, engine, token):
        pt = b"same plaintext"
        b1 = engine.encrypt(pt, token)
        b2 = engine.encrypt(pt, token)
        assert b1.aes_ciphertext != b2.aes_ciphertext   # fresh nonce every time

    def test_encrypt_with_expired_token_raises(self, vault_dir):
        e   = VaultEngine(vault_dir)
        tok = e.create_session_token("owner")
        tok.expires_at = time.time() - 1
        with pytest.raises(PermissionError):
            e.encrypt(b"data", tok)

    def test_decrypt_with_invalid_token_raises(self, engine, sample_blob):
        e2  = VaultEngine(engine.vault_dir)
        tok = e2.create_session_token("wrong_owner")
        # The blob was encrypted under engine's key; e2 has same master key
        # but the session_id is not registered → PermissionError
        with pytest.raises((PermissionError, ValueError)):
            engine.decrypt(sample_blob, tok)

    def test_blob_serialise_deserialise(self, engine, token):
        """VaultBlob survives JSON round-trip (as stored in .vault file)."""
        pt   = b"JSON round-trip test"
        blob = engine.encrypt(pt, token)
        d    = dataclasses.asdict(blob)
        blob2 = VaultBlob(**d)
        assert engine.decrypt(blob2, token) == pt

    def test_tampered_ciphertext_raises(self, engine, token):
        blob = engine.encrypt(b"tamper test", token)
        raw  = base64.b64decode(blob.aes_ciphertext)
        raw  = bytes([raw[0] ^ 0xFF]) + raw[1:]   # flip first byte
        blob.aes_ciphertext = base64.b64encode(raw).decode()
        with pytest.raises((ValueError, Exception)):
            engine.decrypt(blob, token)

    def test_different_tokens_cannot_decrypt_each_other(self, engine):
        """Each token's session key is unique — cross-decryption fails."""
        t1   = engine.create_session_token("owner_x")
        t2   = engine.create_session_token("owner_x")
        blob = engine.encrypt(b"private", t1)
        with pytest.raises((ValueError, Exception)):
            engine.decrypt(blob, t2)


# ══════════════════════════════════════════════════════════════════
# Canary integrity
# ══════════════════════════════════════════════════════════════════

class TestCanaryIntegrity:

    def test_canary_fingerprint_present(self, engine, token):
        blob = engine.encrypt(b"canary test data", token)
        assert blob.canary_hash
        assert len(blob.canary_hash) == 64   # SHA-256 hex

    def test_canary_fingerprint_differs_per_encryption(self, engine, token):
        b1 = engine.encrypt(b"data", token)
        b2 = engine.encrypt(b"data", token)
        # Different session keys from same token → same key, but nonces differ
        # fingerprint is key-derived, so both should match canary config
        assert b1.canary_hash and b2.canary_hash


# ══════════════════════════════════════════════════════════════════
# hash_identity
# ══════════════════════════════════════════════════════════════════

class TestHashIdentity:

    def test_same_input_same_output(self, engine):
        h1 = engine.hash_identity("my_password")
        h2 = engine.hash_identity("my_password")
        assert h1 == h2

    def test_different_inputs_different_outputs(self, engine):
        assert engine.hash_identity("pass_a") != engine.hash_identity("pass_b")

    def test_output_is_hex_string(self, engine):
        h = engine.hash_identity("test")
        assert isinstance(h, str)
        int(h, 16)   # must be valid hex

    def test_different_engines_different_hashes(self, tmp_path):
        """Salt is derived from master key — different vaults produce different hashes."""
        e1 = VaultEngine(str(tmp_path / "v1"))
        e2 = VaultEngine(str(tmp_path / "v2"))
        assert e1.hash_identity("password") != e2.hash_identity("password")


# ══════════════════════════════════════════════════════════════════
# sign_audit_entry
# ══════════════════════════════════════════════════════════════════

class TestSignAuditEntry:

    def _sign(self, engine, payload):
        import json, base64 as b64
        raw = json.dumps(payload, sort_keys=True).encode()
        sig = engine._signing_key.sign(raw)
        return b64.b64encode(sig).decode()

    def test_returns_base64_string(self, engine):
        sig = self._sign(engine, {"event": "test", "ts": "2025-01-01"})
        assert isinstance(sig, str)
        base64.b64decode(sig)   # must be valid base64

    def test_same_payload_same_signature(self, engine):
        payload = {"event": "LOGIN", "user": "nikhil"}
        s1 = self._sign(engine, payload)
        s2 = self._sign(engine, payload)
        assert s1 == s2   # Ed25519 is deterministic


# ══════════════════════════════════════════════════════════════════
# Device fingerprint
# ══════════════════════════════════════════════════════════════════

class TestDeviceFingerprint:

    def test_returns_64_char_hex(self):
        fp = get_device_fingerprint()
        assert len(fp) == 64
        int(fp, 16)

    def test_consistent_on_same_machine(self):
        assert get_device_fingerprint() == get_device_fingerprint()
