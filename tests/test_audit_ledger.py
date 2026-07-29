"""
tests/test_audit_ledger.py
Tests for core/audit_ledger.py  (flat-file JSONL ledger)
and database/db_adapter.py AuditLedgerDB (SQLite ledger).
Both must pass identical chain-integrity tests.
"""
import os
import json
import time
import hashlib
import pytest

from core.audit_ledger import AuditLedger, LedgerEntry


# ══════════════════════════════════════════════════════════════════
# LedgerEntry unit tests
# ══════════════════════════════════════════════════════════════════

class TestLedgerEntry:

    def test_entry_hash_computed(self):
        e = LedgerEntry(0, "LOGIN", {"user": "a"}, "0" * 64)
        assert len(e.entry_hash) == 64
        int(e.entry_hash, 16)

    def test_verify_hash_passes_on_fresh_entry(self):
        e = LedgerEntry(0, "ENCRYPT", {"blob": "x"}, "0" * 64)
        assert e.verify_hash() is True

    def test_verify_hash_fails_after_tampering(self):
        e = LedgerEntry(0, "DECRYPT", {}, "0" * 64)
        e.event_type = "TAMPERED"   # mutate after creation
        assert e.verify_hash() is False

    def test_to_dict_round_trip(self):
        e  = LedgerEntry(1, "LOGOUT", {"reason": "idle"}, "ab" * 32)
        d  = e.to_dict()
        e2 = LedgerEntry.from_dict(d)
        assert e2.index      == e.index
        assert e2.event_type == e.event_type
        assert e2.entry_hash == e.entry_hash

    def test_prev_hash_stored(self):
        prev = "a" * 64
        e    = LedgerEntry(2, "TEST", {}, prev)
        assert e.prev_hash == prev


# ══════════════════════════════════════════════════════════════════
# AuditLedger (JSONL flat file)
# ══════════════════════════════════════════════════════════════════

class TestAuditLedger:

    def test_log_creates_jsonl_file(self, ledger, vault_dir):
        ledger.log("LOGIN_SUCCESS", {"user": "nikhil"})
        assert os.path.exists(os.path.join(vault_dir, "vault_audit.jsonl"))

    def test_read_all_returns_entries(self, ledger):
        ledger.log("A", {})
        ledger.log("B", {})
        entries = ledger.read_all()
        assert len(entries) == 2
        assert entries[0].event_type == "A"
        assert entries[1].event_type == "B"

    def test_chain_valid_after_multiple_entries(self, ledger):
        for ev in ["LOGIN", "ENCRYPT", "DECRYPT", "LOGOUT"]:
            ledger.log(ev, {"ts": time.time()})
        valid, msg = ledger.verify_chain()
        assert valid, msg

    def test_entries_are_sequential(self, ledger):
        for i in range(5):
            ledger.log(f"EVENT_{i}", {})
        entries = ledger.read_all()
        for i, e in enumerate(entries):
            assert e.index == i

    def test_prev_hash_chain_links(self, ledger):
        ledger.log("FIRST",  {})
        ledger.log("SECOND", {})
        ledger.log("THIRD",  {})
        entries = ledger.read_all()
        assert entries[1].prev_hash == entries[0].entry_hash
        assert entries[2].prev_hash == entries[1].entry_hash

    def test_verify_chain_detects_tamper(self, ledger, vault_dir):
        ledger.log("LOGIN",   {})
        ledger.log("ENCRYPT", {})
        ledger.log("LOGOUT",  {})

        # Tamper with entry 1 in the JSONL file
        log_path = os.path.join(vault_dir, "vault_audit.jsonl")
        with open(log_path) as f:
            lines = f.readlines()
        entry = json.loads(lines[1])
        entry["event_type"] = "TAMPERED"
        lines[1] = json.dumps(entry) + "\n"
        with open(log_path, "w") as f:
            f.writelines(lines)

        # Re-open ledger to re-read the file
        ledger2 = AuditLedger(vault_dir)
        valid, msg = ledger2.verify_chain()
        assert valid is False
        assert "mismatch" in msg.lower() or "tamper" in msg.lower() or "hash" in msg.lower()

    def test_signed_entries_have_signature(self, ledger):
        e = ledger.log("SIGNED_EVENT", {"detail": "value"})
        assert e.signature is not None

    def test_export_creates_json_file(self, ledger, tmp_path):
        ledger.log("A", {})
        ledger.log("B", {})
        out = str(tmp_path / "export.json")
        ledger.export_for_audit(out)
        assert os.path.exists(out)
        with open(out) as f:
            data = json.load(f)
        assert data["entry_count"] == 2
        assert len(data["entries"]) == 2

    def test_persist_across_instances(self, vault_dir, engine):
        """Entries written by one ledger are readable by a new instance."""
        def _sign(e):
            import json, base64
            raw = json.dumps(e, sort_keys=True).encode()
            return base64.b64encode(engine._signing_key.sign(raw)).decode()
        l1 = AuditLedger(vault_dir, sign_fn=_sign)
        l1.log("PERSIST_TEST", {"x": 1})
        l2 = AuditLedger(vault_dir)
        entries = l2.read_all()
        assert any(e.event_type == "PERSIST_TEST" for e in entries)

    def test_empty_ledger_chain_valid(self, ledger):
        valid, msg = ledger.verify_chain()
        assert valid
        assert "0 entries" in msg


# ══════════════════════════════════════════════════════════════════
# AuditLedgerDB (SQLite) — same correctness tests
# ══════════════════════════════════════════════════════════════════

class TestAuditLedgerDB:

    def test_log_and_read_all(self, ledger_db):
        ledger_db.log("LOGIN",  {"user": "a"})
        ledger_db.log("ENCRYPT",{"blob": "x"})
        entries = ledger_db.read_all()
        assert len(entries) == 2
        assert entries[0].event_type == "LOGIN"
        assert entries[1].event_type == "ENCRYPT"

    def test_chain_valid(self, ledger_db):
        for ev in ["A", "B", "C", "D"]:
            ledger_db.log(ev, {})
        valid, msg = ledger_db.verify_chain()
        assert valid, msg

    def test_read_recent_newest_first(self, ledger_db):
        for ev in ["FIRST", "SECOND", "THIRD"]:
            ledger_db.log(ev, {})
        recent = ledger_db.read_recent(2)
        assert recent[0].event_type == "THIRD"
        assert recent[1].event_type == "SECOND"

    def test_search_by_event_type(self, ledger_db):
        ledger_db.log("LOGIN",   {})
        ledger_db.log("ENCRYPT", {})
        ledger_db.log("LOGIN",   {})
        results = ledger_db.search(event_type="LOGIN")
        assert len(results) == 2
        assert all(r.event_type == "LOGIN" for r in results)

    def test_search_since_ts(self, ledger_db):
        ledger_db.log("OLD_EVENT", {})
        cutoff = time.time()
        time.sleep(0.01)
        ledger_db.log("NEW_EVENT", {})
        results = ledger_db.search(since_ts=cutoff)
        assert len(results) == 1
        assert results[0].event_type == "NEW_EVENT"

    def test_verify_detects_tamper(self, ledger_db, db):
        ledger_db.log("FIRST",  {})
        ledger_db.log("SECOND", {})
        # Directly mutate the DB to simulate tamper
        db.execute(
            "UPDATE audit_chain SET event_type='TAMPERED' WHERE idx=0"
        )
        valid, msg = ledger_db.verify_chain()
        assert valid is False

    def test_export_for_audit(self, ledger_db, tmp_path):
        ledger_db.log("X", {"detail": 1})
        out = str(tmp_path / "export.json")
        ledger_db.export_for_audit(out)
        with open(out) as f:
            data = json.load(f)
        assert data["entry_count"] == 1

    def test_entry_verify_hash(self, ledger_db):
        e = ledger_db.log("HASH_TEST", {"k": "v"})
        assert e.verify_hash() is True

    def test_sequential_indexes(self, ledger_db):
        for i in range(5):
            ledger_db.log(f"EV_{i}", {})
        entries = ledger_db.read_all()
        for i, e in enumerate(entries):
            assert e.index == i
