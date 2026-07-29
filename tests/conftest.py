"""
Shared pytest fixtures for the VAULT-X test suite.
Every test module imports from here via pytest's automatic conftest discovery.
"""
import os
import json
import time
import tempfile
import pytest

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.vault_engine import VaultEngine, get_device_fingerprint
from core.audit_ledger import AuditLedger
from layers.auth_layers import (
    TOTPLayer, BiometricLayer, BehavioralLayer, ZKPLayer, GeofenceLayer
)
from database.db_adapter import VaultDatabase, AgentStore, AuditLedgerDB, BlobStore, ConfigStore


# ── Temporary vault directory ─────────────────────────────────────
@pytest.fixture
def vault_dir(tmp_path):
    """Fresh temporary vault directory for each test."""
    return str(tmp_path)


# ── VaultEngine ───────────────────────────────────────────────────
@pytest.fixture
def engine(vault_dir):
    """Initialized VaultEngine backed by a temp directory."""
    return VaultEngine(vault_dir)


@pytest.fixture
def token(engine):
    """Valid session token issued against the test engine."""
    return engine.create_session_token("test_owner_hash_abc123")


# ── Auth layers ───────────────────────────────────────────────────
@pytest.fixture
def totp():
    return TOTPLayer()


@pytest.fixture
def biometric():
    layer = BiometricLayer()
    layer.register("StrongPassphrase2025!")
    return layer


@pytest.fixture
def zkp():
    return ZKPLayer()


@pytest.fixture
def geofence(engine):
    geo = GeofenceLayer()
    geo.register_device(get_device_fingerprint())
    return geo


# ── AuditLedger ───────────────────────────────────────────────────
@pytest.fixture
def ledger(vault_dir, engine):
    def _sign(entry):
        import json, base64
        payload = json.dumps(entry, sort_keys=True).encode()
        sig = engine._signing_key.sign(payload)
        return base64.b64encode(sig).decode()
    return AuditLedger(vault_dir, sign_fn=_sign)


# ── Database ──────────────────────────────────────────────────────
@pytest.fixture
def db(tmp_path):
    return VaultDatabase(str(tmp_path / "vaultx.db"))


@pytest.fixture
def agent_store(tmp_path):
    return AgentStore(str(tmp_path / "vaultx.db"))


@pytest.fixture
def ledger_db(tmp_path, db, engine):
    def _sign(entry):
        import json, base64
        payload = json.dumps(entry, sort_keys=True).encode()
        sig = engine._signing_key.sign(payload)
        return base64.b64encode(sig).decode()
    return AuditLedgerDB(str(tmp_path), sign_fn=_sign, db=db)


@pytest.fixture
def blob_store(db):
    return BlobStore(db)


@pytest.fixture
def config_store(db):
    return ConfigStore(db)


# ── Encrypted blob ────────────────────────────────────────────────
@pytest.fixture
def sample_blob(engine, token):
    """A pre-encrypted VaultBlob for decrypt/relocate tests."""
    return engine.encrypt(b"VAULT-X sample secret payload", token)


# ── Helpers ───────────────────────────────────────────────────────
def make_agent(store: AgentStore) -> dict:
    """Register a fresh agent and return the full response dict."""
    tok = store.enrollment_token()
    return store.register_agent({
        "enrollment_token": tok,
        "hostname"        : "test-laptop",
        "assigned_user"   : "testuser",
        "department"      : "IT",
        "os"              : "Windows 11",
        "ip_address"      : "192.168.0.100",
    })
