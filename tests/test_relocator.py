"""
tests/test_relocator.py
Tests for relocation/relocator.py
Covers: LocationRegistry, secure_wipe, Relocator.relocate().
"""
import os
import json
import time
import dataclasses
import hashlib
import pytest

from relocation.relocator import Relocator, LocationRegistry, secure_wipe
from core.vault_engine import VaultEngine


# ══════════════════════════════════════════════════════════════════
# LocationRegistry
# ══════════════════════════════════════════════════════════════════

class TestLocationRegistry:

    def test_register_and_verify_correct_path(self, tmp_path):
        reg  = LocationRegistry({})
        path = str(tmp_path / "blob.vault")
        reg.register("blob001", path)
        assert reg.verify_location("blob001", path) is True

    def test_wrong_path_fails_verification(self, tmp_path):
        reg   = LocationRegistry({})
        path1 = str(tmp_path / "a.vault")
        path2 = str(tmp_path / "b.vault")
        reg.register("blob001", path1)
        assert reg.verify_location("blob001", path2) is False

    def test_unregistered_blob_always_passes(self, tmp_path):
        reg = LocationRegistry({})
        assert reg.verify_location("unknown_blob", str(tmp_path / "any.vault")) is True

    def test_remove_releases_constraint(self, tmp_path):
        reg  = LocationRegistry({})
        path = str(tmp_path / "c.vault")
        reg.register("blob002", path)
        reg.remove("blob002")
        # After removal, any path is accepted
        assert reg.verify_location("blob002", str(tmp_path / "other.vault")) is True

    def test_path_stored_as_hash_not_plaintext(self, tmp_path):
        reg  = LocationRegistry({})
        path = str(tmp_path / "secret.vault")
        reg.register("blob003", path)
        # Raw path should not appear in the registry values
        assert path not in reg._reg.values()
        assert reg._reg.get("blob003") == hashlib.sha256(
            os.path.abspath(path).encode()
        ).hexdigest()


# ══════════════════════════════════════════════════════════════════
# secure_wipe
# ══════════════════════════════════════════════════════════════════

class TestSecureWipe:

    def test_file_deleted_after_wipe(self, tmp_path):
        f = tmp_path / "wipe_me.txt"
        f.write_bytes(b"sensitive data" * 100)
        assert secure_wipe(str(f)) is True
        assert not f.exists()

    def test_wipe_nonexistent_returns_false(self, tmp_path):
        assert secure_wipe(str(tmp_path / "ghost.txt")) is False

    def test_wipe_3_passes(self, tmp_path):
        f = tmp_path / "three_pass.bin"
        f.write_bytes(os.urandom(512))
        result = secure_wipe(str(f), passes=3)
        assert result is True
        assert not f.exists()

    def test_wipe_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        result = secure_wipe(str(f))
        assert result is True


# ══════════════════════════════════════════════════════════════════
# Relocator
# ══════════════════════════════════════════════════════════════════

class TestRelocator:

    def _write_blob(self, blob, path):
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(dataclasses.asdict(blob), f)

    def test_relocate_creates_new_file(self, engine, token, tmp_path):
        blob     = engine.encrypt(b"relocate me", token)
        old_path = str(tmp_path / "old.vault")
        new_path = str(tmp_path / "archive" / "new.vault")
        self._write_blob(blob, old_path)

        reg       = LocationRegistry({})
        relocator = Relocator(engine, reg)
        record    = relocator.relocate(old_path, new_path, token)

        assert os.path.exists(new_path)

    def test_relocate_wipes_old_file(self, engine, token, tmp_path):
        blob     = engine.encrypt(b"wipe old", token)
        old_path = str(tmp_path / "source.vault")
        new_path = str(tmp_path / "dest.vault")
        self._write_blob(blob, old_path)

        relocator = Relocator(engine, LocationRegistry({}))
        relocator.relocate(old_path, new_path, token)

        assert not os.path.exists(old_path)

    def test_relocate_produces_different_blob_id(self, engine, token, tmp_path):
        blob     = engine.encrypt(b"different blob id", token)
        old_path = str(tmp_path / "src.vault")
        new_path = str(tmp_path / "dst.vault")
        self._write_blob(blob, old_path)

        relocator = Relocator(engine, LocationRegistry({}))
        record    = relocator.relocate(old_path, new_path, token)

        assert record.old_blob_id != record.new_blob_id

    def test_relocated_blob_is_valid_vault_blob(self, engine, token, tmp_path):
        """New blob is valid VaultBlob JSON with all required fields."""
        plaintext = b"I must survive relocation intact"
        blob      = engine.encrypt(plaintext, token)
        old_path  = str(tmp_path / "pre_relocate.vault")
        new_path  = str(tmp_path / "post_relocate.vault")
        self._write_blob(blob, old_path)

        relocator = Relocator(engine, LocationRegistry({}))
        relocator.relocate(old_path, new_path, token)

        with open(new_path) as f:
            new_blob_data = json.load(f)

        from core.vault_engine import VaultBlob
        new_blob = VaultBlob(**new_blob_data)
        assert new_blob.blob_id
        assert new_blob.aes_ciphertext
        assert new_blob.chacha_ciphertext
        assert new_blob.canary_hash

    def test_relocate_missing_source_raises(self, engine, token, tmp_path):
        relocator = Relocator(engine, LocationRegistry({}))
        with pytest.raises(FileNotFoundError):
            relocator.relocate(
                str(tmp_path / "nonexistent.vault"),
                str(tmp_path / "dest.vault"),
                token,
            )

    def test_relocate_updates_registry(self, engine, token, tmp_path):
        blob     = engine.encrypt(b"registry test", token)
        old_path = str(tmp_path / "reg_old.vault")
        new_path = str(tmp_path / "reg_new.vault")
        self._write_blob(blob, old_path)

        registry  = LocationRegistry({})
        registry.register(blob.blob_id, old_path)
        relocator = Relocator(engine, registry)
        record    = relocator.relocate(old_path, new_path, token)

        # Old blob_id removed, new blob_id registered
        assert record.old_blob_id not in registry._reg
        assert record.new_blob_id in registry._reg

    def test_relocate_calls_audit_callback(self, engine, token, tmp_path):
        blob     = engine.encrypt(b"audit cb test", token)
        old_path = str(tmp_path / "audit_old.vault")
        new_path = str(tmp_path / "audit_new.vault")
        self._write_blob(blob, old_path)

        audit_calls = []
        relocator   = Relocator(engine, LocationRegistry({}),
                                 audit_callback=lambda et, d: audit_calls.append(et))
        relocator.relocate(old_path, new_path, token)

        assert any("RELOCATION" in c.upper() or "relocat" in c.lower()
                   for c in audit_calls)

    def test_relocation_record_fields(self, engine, token, tmp_path):
        blob     = engine.encrypt(b"record test", token)
        old_path = str(tmp_path / "rec_old.vault")
        new_path = str(tmp_path / "rec_new.vault")
        self._write_blob(blob, old_path)

        relocator = Relocator(engine, LocationRegistry({}))
        record    = relocator.relocate(old_path, new_path, token)

        assert record.old_blob_id
        assert record.new_blob_id
        assert record.old_path_hash
        assert record.new_path_hash
        assert record.wipe_passes >= 1
        assert record.relocated_at > 0
        assert record.wipe_verified is True
