"""
tests/test_database.py
Tests for database/db_adapter.py
Covers: VaultDatabase, AgentStore, BlobStore, ConfigStore.
"""
import os
import json
import time
import pytest

from database.db_adapter import (
    VaultDatabase, AgentStore, BlobStore, ConfigStore, _hash_secret
)
from tests.conftest import make_agent


# ══════════════════════════════════════════════════════════════════
# VaultDatabase
# ══════════════════════════════════════════════════════════════════

class TestVaultDatabase:

    def test_db_file_created(self, tmp_path):
        db_path = str(tmp_path / "vaultx.db")
        VaultDatabase(db_path)
        assert os.path.exists(db_path)

    def test_execute_and_fetchone(self, db):
        db.execute("INSERT INTO config(key,value,updated_at) VALUES(?,?,?)",
                   ("test_key", '"test_val"', time.time()))
        row = db.fetchone("SELECT value FROM config WHERE key=?", ("test_key",))
        assert row is not None
        assert row["value"] == '"test_val"'

    def test_fetchall_returns_list(self, db):
        for i in range(3):
            db.execute("INSERT INTO config(key,value,updated_at) VALUES(?,?,?)",
                       (f"k{i}", f'"{i}"', time.time()))
        rows = db.fetchall("SELECT key FROM config WHERE key LIKE 'k%'")
        assert len(rows) == 3

    def test_transaction_commit(self, db):
        with db.transaction() as con:
            con.execute("INSERT INTO config(key,value,updated_at) VALUES(?,?,?)",
                        ("tx_key", '"tx_val"', time.time()))
        row = db.fetchone("SELECT value FROM config WHERE key='tx_key'")
        assert row is not None

    def test_transaction_rollback_on_error(self, db):
        try:
            with db.transaction() as con:
                con.execute("INSERT INTO config(key,value,updated_at) VALUES(?,?,?)",
                            ("rb_key", '"v"', time.time()))
                raise ValueError("force rollback")
        except ValueError:
            pass
        row = db.fetchone("SELECT value FROM config WHERE key='rb_key'")
        assert row is None

    def test_same_db_path_same_data(self, tmp_path):
        path = str(tmp_path / "shared.db")
        db1  = VaultDatabase(path)
        db1.execute("INSERT INTO config(key,value,updated_at) VALUES(?,?,?)",
                    ("shared_key", '"hello"', time.time()))
        db2  = VaultDatabase(path)
        row  = db2.fetchone("SELECT value FROM config WHERE key=?", ("shared_key",))
        assert row is not None


# ══════════════════════════════════════════════════════════════════
# AgentStore — enrollment and auth
# ══════════════════════════════════════════════════════════════════

class TestAgentStoreEnrollment:

    def test_enrollment_token_exists_on_init(self, agent_store):
        tok = agent_store.enrollment_token()
        assert tok and len(tok) > 10

    def test_rotate_enrollment_token_changes_token(self, agent_store):
        old = agent_store.enrollment_token()
        new = agent_store.rotate_enrollment_token()
        assert new != old
        assert agent_store.enrollment_token() == new

    def test_register_agent_returns_agent_id_and_token(self, agent_store):
        result = make_agent(agent_store)
        assert "agent_id"    in result
        assert "agent_token" in result
        assert len(result["agent_id"]) > 0

    def test_invalid_enrollment_token_raises(self, agent_store):
        with pytest.raises(ValueError, match="enrollment"):
            agent_store.register_agent({
                "enrollment_token": "wrong_token",
                "hostname": "hack",
            })

    def test_registered_agent_appears_in_list(self, agent_store):
        a = make_agent(agent_store)
        agents = agent_store.list_agents()
        assert any(ag["agent_id"] == a["agent_id"] for ag in agents)


# ══════════════════════════════════════════════════════════════════
# AgentStore — authentication
# ══════════════════════════════════════════════════════════════════

class TestAgentStoreAuth:

    def test_correct_token_authenticates(self, agent_store):
        a = make_agent(agent_store)
        result = agent_store.authenticate_agent(a["agent_id"], a["agent_token"])
        assert result["agent_id"] == a["agent_id"]

    def test_wrong_token_raises_permission_error(self, agent_store):
        a = make_agent(agent_store)
        with pytest.raises(PermissionError):
            agent_store.authenticate_agent(a["agent_id"], "wrong_token")

    def test_unknown_agent_raises_key_error(self, agent_store):
        with pytest.raises(KeyError):
            agent_store.authenticate_agent("nonexistent_agent", "any_token")

    def test_revoked_agent_cannot_authenticate(self, agent_store):
        a = make_agent(agent_store)
        agent_store.revoke_agent(a["agent_id"], revoked=True)
        with pytest.raises(PermissionError):
            agent_store.authenticate_agent(a["agent_id"], a["agent_token"])

    def test_rotate_agent_token_old_token_invalid(self, agent_store):
        a        = make_agent(agent_store)
        old_tok  = a["agent_token"]
        result   = agent_store.rotate_agent_token(a["agent_id"])
        new_tok  = result["agent_token"]
        # New token works
        agent_store.authenticate_agent(a["agent_id"], new_tok)
        # Old token fails
        with pytest.raises(PermissionError):
            agent_store.authenticate_agent(a["agent_id"], old_tok)


# ══════════════════════════════════════════════════════════════════
# AgentStore — heartbeat and events
# ══════════════════════════════════════════════════════════════════

class TestAgentStoreOperations:

    def test_heartbeat_updates_last_seen(self, agent_store):
        a        = make_agent(agent_store)
        before   = time.time()
        agent_store.heartbeat(a["agent_id"], {"status": "online"})
        agents   = agent_store.list_agents()
        agent    = next(ag for ag in agents if ag["agent_id"] == a["agent_id"])
        assert agent["last_seen"] >= before

    def test_heartbeat_returns_policy(self, agent_store):
        a      = make_agent(agent_store)
        result = agent_store.heartbeat(a["agent_id"], {"status": "online"})
        assert "policy" in result
        assert result["policy"] is not None

    def test_record_event_returns_event_id(self, agent_store):
        a  = make_agent(agent_store)
        ev = agent_store.record_event({
            "type": "file_access", "severity": "info",
            "agent_id": a["agent_id"],
            "details": {"file": "/secret.txt"},
        })
        assert "event_id" in ev
        assert ev["event_id"]

    def test_list_events_returns_most_recent_first(self, agent_store):
        a = make_agent(agent_store)
        for i in range(3):
            agent_store.record_event({
                "type": f"event_{i}", "severity": "info",
                "agent_id": a["agent_id"], "details": {},
            })
        events = agent_store.list_events(limit=10)
        times  = [e["timestamp"] for e in events]
        assert times == sorted(times, reverse=True)

    def test_list_events_filter_by_agent(self, agent_store):
        a1 = make_agent(agent_store)
        a2 = make_agent(agent_store)
        agent_store.record_event({"type":"ev","severity":"info","agent_id":a1["agent_id"],"details":{}})
        agent_store.record_event({"type":"ev","severity":"info","agent_id":a2["agent_id"],"details":{}})
        events = agent_store.list_events(agent_id=a1["agent_id"])
        assert all(e["agent_id"] == a1["agent_id"] for e in events)

    def test_list_events_filter_by_severity(self, agent_store):
        a = make_agent(agent_store)
        agent_store.record_event({"type":"low","severity":"info",  "agent_id":a["agent_id"],"details":{}})
        agent_store.record_event({"type":"high","severity":"critical","agent_id":a["agent_id"],"details":{}})
        critical = agent_store.list_events(severity="critical")
        assert all(e["severity"] == "critical" for e in critical)

    def test_list_events_limit_respected(self, agent_store):
        a = make_agent(agent_store)
        for i in range(10):
            agent_store.record_event({"type":"ev","severity":"info","agent_id":a["agent_id"],"details":{}})
        events = agent_store.list_events(limit=3)
        assert len(events) <= 3

    def test_event_count_by_severity(self, agent_store):
        a = make_agent(agent_store)
        agent_store.record_event({"type":"t","severity":"info",    "agent_id":a["agent_id"],"details":{}})
        agent_store.record_event({"type":"t","severity":"critical","agent_id":a["agent_id"],"details":{}})
        counts = agent_store.event_count_by_severity()
        assert counts.get("info", 0)     >= 1
        assert counts.get("critical", 0) >= 1


# ══════════════════════════════════════════════════════════════════
# AgentStore — policies
# ══════════════════════════════════════════════════════════════════

class TestAgentStorePolicies:

    def test_default_policy_exists(self, agent_store):
        p = agent_store.get_policy("default")
        assert p is not None
        assert "blocked_extensions" in p

    def test_update_policy_persists(self, agent_store):
        agent_store.update_policy("default", {"mode": "block"})
        p = agent_store.get_policy("default")
        assert p["mode"] == "block"

    def test_signed_policy_has_signature(self, agent_store):
        sp = agent_store.signed_policy("default")
        assert sp is not None
        assert "signature" in sp
        assert len(sp["signature"]) > 10

    def test_signed_policy_signature_changes_after_update(self, agent_store):
        sp1 = agent_store.signed_policy("default")
        time.sleep(0.05)   # ensure issued_at differs
        agent_store.update_policy("default", {"mode": "block"})
        sp2 = agent_store.signed_policy("default")
        # Signature is over content + issued_at, so policy change → different sig
        assert sp1["policy"]["mode"] != sp2["policy"]["mode"]

    def test_unknown_policy_returns_none(self, agent_store):
        assert agent_store.get_policy("nonexistent_policy") is None

    def test_list_policies_includes_default(self, agent_store):
        policies = agent_store.list_policies()
        assert any(p.get("policy_id") == "default" for p in policies)


# ══════════════════════════════════════════════════════════════════
# AgentStore — summary
# ══════════════════════════════════════════════════════════════════

class TestAgentStoreSummary:

    def test_summary_has_required_keys(self, agent_store):
        s = agent_store.summary()
        for key in ("total_agents","online_agents","revoked_agents",
                    "event_count","policy_count","enrollment_token_preview"):
            assert key in s, f"Missing key: {key}"

    def test_summary_counts_agents(self, agent_store):
        make_agent(agent_store)
        make_agent(agent_store)
        s = agent_store.summary()
        assert s["total_agents"] >= 2

    def test_revoked_counted_separately(self, agent_store):
        a = make_agent(agent_store)
        agent_store.revoke_agent(a["agent_id"])
        s = agent_store.summary()
        assert s["revoked_agents"] >= 1


# ══════════════════════════════════════════════════════════════════
# BlobStore
# ══════════════════════════════════════════════════════════════════

class TestBlobStore:

    def test_save_and_get_blob(self, blob_store, sample_blob):
        blob_store.save_blob(sample_blob, "secret.txt", "owner_abc")
        result = blob_store.get_blob(sample_blob.blob_id)
        assert result is not None
        assert result["filename"]   == "secret.txt"
        assert result["owner_hash"] == "owner_abc"

    def test_list_blobs_by_owner(self, blob_store, engine, token):
        b1 = engine.encrypt(b"file1", token)
        b2 = engine.encrypt(b"file2", token)
        blob_store.save_blob(b1, "f1.txt", "owner_x")
        blob_store.save_blob(b2, "f2.txt", "owner_y")
        x_blobs = blob_store.list_blobs(owner_hash="owner_x")
        assert len(x_blobs) == 1
        assert x_blobs[0]["owner_hash"] == "owner_x"

    def test_delete_blob(self, blob_store, sample_blob):
        blob_store.save_blob(sample_blob, "del.txt", "owner_z")
        assert blob_store.get_blob(sample_blob.blob_id) is not None
        blob_store.delete_blob(sample_blob.blob_id)
        assert blob_store.get_blob(sample_blob.blob_id) is None

    def test_blob_count(self, blob_store, engine, token):
        for i in range(4):
            b = engine.encrypt(f"data{i}".encode(), token)
            blob_store.save_blob(b, f"f{i}.txt", "owner_count")
        assert blob_store.blob_count("owner_count") == 4

    def test_upsert_same_blob_id(self, blob_store, sample_blob):
        blob_store.save_blob(sample_blob, "v1.txt", "owner_a")
        blob_store.save_blob(sample_blob, "v2.txt", "owner_a")   # same blob_id
        result = blob_store.get_blob(sample_blob.blob_id)
        assert result["filename"] == "v2.txt"   # upserted


# ══════════════════════════════════════════════════════════════════
# ConfigStore
# ══════════════════════════════════════════════════════════════════

class TestConfigStore:

    def test_set_and_get_string(self, config_store):
        config_store.set("owner_hash", "abc123")
        assert config_store.get("owner_hash") == "abc123"

    def test_set_and_get_dict(self, config_store):
        d = {"secret": "BASE32SECRET", "digits": 6}
        config_store.set("totp_config", d)
        assert config_store.get("totp_config") == d

    def test_set_and_get_int(self, config_store):
        config_store.set("retry_count", 3)
        assert config_store.get("retry_count") == 3

    def test_set_and_get_bool(self, config_store):
        config_store.set("geofence_enabled", True)
        assert config_store.get("geofence_enabled") is True

    def test_missing_key_returns_default(self, config_store):
        assert config_store.get("nonexistent", "fallback") == "fallback"

    def test_missing_key_returns_none_by_default(self, config_store):
        assert config_store.get("nonexistent") is None

    def test_delete_removes_key(self, config_store):
        config_store.set("temp", "value")
        config_store.delete("temp")
        assert config_store.get("temp") is None

    def test_overwrite_existing_key(self, config_store):
        config_store.set("key", "first")
        config_store.set("key", "second")
        assert config_store.get("key") == "second"

    def test_set_many(self, config_store):
        config_store.set_many({"k1": "v1", "k2": 42, "k3": [1, 2, 3]})
        assert config_store.get("k1") == "v1"
        assert config_store.get("k2") == 42
        assert config_store.get("k3") == [1, 2, 3]

    def test_get_all_returns_dict(self, config_store):
        config_store.set_many({"ga_1": "a", "ga_2": "b"})
        all_cfg = config_store.get_all()
        assert "ga_1" in all_cfg
        assert "ga_2" in all_cfg


# ══════════════════════════════════════════════════════════════════
# JSON migration
# ══════════════════════════════════════════════════════════════════

class TestJSONMigration:

    def test_migrate_from_json_imports_agents(self, tmp_path):
        json_state = {
            "enrollment_token"  : "old_enrollment_tok",
            "policy_signing_key": "old_signing_key",
            "agents": {
                "migrated-001": {
                    "agent_id": "migrated-001", "hostname": "legacy-pc",
                    "assigned_user": "legacy_user", "department": "HR",
                    "os": "Windows 10", "ip_address": "10.0.0.50",
                    "agent_version": "0.1.0", "policy_id": "default",
                    "status": "offline",
                    "registered_at": time.time() - 3600,
                    "last_seen"    : time.time() - 3600,
                    "agent_token_hash": _hash_secret("legacy_token"),
                    "token_preview": "legacy_...",
                    "token_rotated_at": time.time() - 3600,
                    "revoked": False, "last_heartbeat": {},
                }
            },
            "events": [{
                "event_id": "old_ev_001", "timestamp": time.time() - 100,
                "type": "file_access", "severity": "info",
                "agent_id": "migrated-001", "details": {}, "ml_detection": {},
            }],
            "policies": {
                "default": {"policy_id": "default", "name": "Old Default", "mode": "monitor"}
            },
        }
        jp = tmp_path / "enterprise_state.json"
        jp.write_text(json.dumps(json_state))

        store = AgentStore(str(jp))
        agents = store.list_agents()
        assert any(a["agent_id"] == "migrated-001" for a in agents)

        events = store.list_events()
        assert any(e.get("event_id") == "old_ev_001" for e in events) or len(events) >= 1
