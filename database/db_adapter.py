"""
╔══════════════════════════════════════════════════════════════════════════╗
║  VAULT-X  ·  SQLite Database Adapter                                     ║
║  File     : database/db_adapter.py                                       ║
║  Version  : 1.0.0                                                        ║
╚══════════════════════════════════════════════════════════════════════════╝

WHY THIS EXISTS:
  The original project uses two flat-file stores:
    enterprise_store.py  →  enterprise_state.json   (grows unboundedly)
    audit_ledger.py      →  vault_audit.jsonl        (no indexing, slow search)

  Problems with the JSON approach at scale:
    - Every read/write locks the entire file
    - 5,000 events means reading/parsing the entire JSON file on every request
    - No indexing — searching events requires full scan every time
    - Race conditions under concurrent agent heartbeats
    - No transaction support — partial writes can corrupt the file

  This module provides:
    1. VaultDatabase       — central SQLite connection manager
    2. AgentStore          — replaces EnterpriseStore's JSON agent/event storage
    3. AuditLedgerDB       — replaces AuditLedger's JSONL file
    4. PolicyStore         — replaces EnterpriseStore's JSON policy storage
    5. EncryptedBlobStore  — stores VaultBlob records in SQLite

BACKWARD COMPATIBILITY:
    AgentStore    is a drop-in replacement for EnterpriseStore
    AuditLedgerDB is a drop-in replacement for AuditLedger
    Both expose identical public method signatures.

HOW TO SWITCH:
    # Before (in vault_server.py):
    from server.enterprise_store import EnterpriseStore
    self.enterprise = EnterpriseStore(vault_dir / "enterprise_state.json")

    # After:
    from database.db_adapter import AgentStore
    self.enterprise = AgentStore(vault_dir / "vaultx.db")

    # Before (in vaultx.py / gui/vault_gui.py):
    from core.audit_ledger import AuditLedger
    ledger = AuditLedger(vault_dir)

    # After:
    from database.db_adapter import AuditLedgerDB
    ledger = AuditLedgerDB(vault_dir)          # same interface, SQLite backed

SCHEMA:
    TABLE agents          — endpoint records
    TABLE events          — security events from agents + monitoring
    TABLE policies        — DLP policy documents
    TABLE audit_chain     — immutable audit ledger (replaces vault_audit.jsonl)
    TABLE blobs           — encrypted VaultBlob metadata
    TABLE rate_limits     — auth attempt tracking for rate limiter
    TABLE config          — key-value store for vault config (replaces vault_config.json)
"""

import copy
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════
# SCHEMA DDL
# ══════════════════════════════════════════════════════════════════

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous  = NORMAL;

-- ── Endpoint agents ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agents (
    agent_id          TEXT PRIMARY KEY,
    hostname          TEXT NOT NULL DEFAULT '',
    assigned_user     TEXT NOT NULL DEFAULT 'unassigned',
    department        TEXT NOT NULL DEFAULT 'unassigned',
    os                TEXT NOT NULL DEFAULT 'unknown',
    ip_address        TEXT NOT NULL DEFAULT '',
    agent_version     TEXT NOT NULL DEFAULT '0.1.0',
    policy_id         TEXT NOT NULL DEFAULT 'default',
    status            TEXT NOT NULL DEFAULT 'offline',
    registered_at     REAL NOT NULL,
    last_seen         REAL NOT NULL DEFAULT 0,
    agent_token_hash  TEXT NOT NULL,
    token_preview     TEXT NOT NULL DEFAULT '',
    token_rotated_at  REAL NOT NULL DEFAULT 0,
    revoked           INTEGER NOT NULL DEFAULT 0,
    last_heartbeat    TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_agents_revoked   ON agents(revoked);

-- ── Security events ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
    event_id     TEXT PRIMARY KEY,
    timestamp    REAL NOT NULL,
    type         TEXT NOT NULL,
    severity     TEXT NOT NULL DEFAULT 'info',
    agent_id     TEXT NOT NULL DEFAULT '',
    details      TEXT NOT NULL DEFAULT '{}',
    ml_detection TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_agent_id  ON events(agent_id);
CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events(type);

-- ── DLP policies ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS policies (
    policy_id  TEXT PRIMARY KEY,
    name       TEXT NOT NULL DEFAULT '',
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL DEFAULT 0
);

-- ── Immutable audit ledger ────────────────────────────────────────
-- Replaces vault_audit.jsonl
-- INSERT ONLY — no UPDATE or DELETE ever issued by application code
CREATE TABLE IF NOT EXISTS audit_chain (
    idx         INTEGER PRIMARY KEY,
    event_type  TEXT    NOT NULL,
    details     TEXT    NOT NULL DEFAULT '{}',
    ts          TEXT    NOT NULL,
    unix_ts     REAL    NOT NULL,
    prev_hash   TEXT    NOT NULL,
    entry_hash  TEXT    NOT NULL,
    signature   TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_unix_ts    ON audit_chain(unix_ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_chain(event_type);

-- ── Encrypted blob metadata ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS blobs (
    blob_id           TEXT PRIMARY KEY,
    session_id        TEXT NOT NULL,
    filename          TEXT NOT NULL DEFAULT '',
    chacha_nonce      TEXT NOT NULL,
    aes_nonce         TEXT NOT NULL,
    chacha_ciphertext TEXT NOT NULL,
    aes_ciphertext    TEXT NOT NULL,
    canary_hash       TEXT NOT NULL,
    created_at        REAL NOT NULL,
    vault_version     TEXT NOT NULL DEFAULT '1.0.0',
    owner_hash        TEXT NOT NULL DEFAULT '',
    size_bytes        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_blobs_owner    ON blobs(owner_hash);
CREATE INDEX IF NOT EXISTS idx_blobs_created  ON blobs(created_at DESC);

-- ── Rate limit tracking ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rate_limits (
    device_hash   TEXT    NOT NULL,
    attempt_ts    REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_device ON rate_limits(device_hash, attempt_ts);

-- ── Key-value config store ────────────────────────────────────────
-- Replaces vault_config.json for lightweight key-value pairs
CREATE TABLE IF NOT EXISTS config (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at REAL NOT NULL DEFAULT 0
);

-- ── Vault meta ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vault_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


# ══════════════════════════════════════════════════════════════════
# VAULT DATABASE — CONNECTION MANAGER
# ══════════════════════════════════════════════════════════════════

class VaultDatabase:
    """
    Central SQLite connection manager for the VAULT-X database.

    THREAD SAFETY:
      Uses a per-thread connection pool via threading.local().
      Each thread gets its own SQLite connection so no locking
      is needed at the Python level.
      SQLite WAL mode handles concurrent reads/writes at the DB level.

    USAGE:
      db = VaultDatabase("./my_vault/vaultx.db")
      with db.conn() as con:
          con.execute("INSERT INTO events ...")
    """

    def __init__(self, db_path: str):
        """
        Args:
            db_path: Path to the SQLite database file.
                     Created automatically if it doesn't exist.
        """
        self.db_path  = str(db_path)
        self._local   = threading.local()
        os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else ".", exist_ok=True)
        # Bootstrap schema on the main thread
        self._bootstrap()

    def _connect(self) -> sqlite3.Connection:
        """Open a per-thread SQLite connection."""
        con = sqlite3.connect(self.db_path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode = WAL")
        con.execute("PRAGMA foreign_keys = ON")
        con.execute("PRAGMA synchronous  = NORMAL")
        return con

    def _get_conn(self) -> sqlite3.Connection:
        """Return (or create) the per-thread connection."""
        if not getattr(self._local, "con", None):
            self._local.con = self._connect()
        return self._local.con

    def conn(self) -> sqlite3.Connection:
        """Return the active connection for this thread (context manager safe)."""
        return self._get_conn()

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a single statement and auto-commit."""
        con = self._get_conn()
        cur = con.execute(sql, params)
        con.commit()
        return cur

    def executemany(self, sql: str, params_list: list):
        """Execute a statement for multiple parameter sets."""
        con = self._get_conn()
        con.executemany(sql, params_list)
        con.commit()

    def fetchall(self, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
        return self._get_conn().execute(sql, params).fetchall()

    def fetchone(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        return self._get_conn().execute(sql, params).fetchone()

    def _bootstrap(self):
        """Create all tables and indexes if they don't exist."""
        con = self._connect()
        con.executescript(_SCHEMA)
        con.commit()
        con.close()

    def transaction(self):
        """Context manager for explicit transactions."""
        return _Transaction(self._get_conn())

    def close(self):
        """Close the current thread's connection."""
        if getattr(self._local, "con", None):
            self._local.con.close()
            self._local.con = None


class _Transaction:
    """Context manager for explicit SQLite transactions."""
    def __init__(self, con: sqlite3.Connection):
        self._con = con
    def __enter__(self):
        self._con.execute("BEGIN")
        return self._con
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self._con.execute("ROLLBACK")
        else:
            self._con.execute("COMMIT")
        return False


# ══════════════════════════════════════════════════════════════════
# AGENT STORE  — drop-in replacement for EnterpriseStore
# ══════════════════════════════════════════════════════════════════

_DEFAULT_POLICY = {
    "policy_id": "default",
    "name": "Default DLP Policy",
    "mode": "monitor",
    "blocked_extensions": [".pem", ".key", ".pfx", ".env"],
    "sensitive_patterns": ["password", "secret", "api_key", "token"],
    "network_controls": {
        "block_usb_exfiltration": True,
        "block_unknown_cloud_uploads": False,
        "alert_on_large_upload_mb": 100,
    },
    "collection": {
        "file_metadata": True,
        "file_contents": False,
        "network_metadata": True,
        "browser_history": False,
    },
}


class AgentStore:
    """
    SQLite-backed replacement for EnterpriseStore.

    IDENTICAL PUBLIC API to EnterpriseStore:
      .summary()
      .enrollment_token()
      .rotate_enrollment_token()
      .register_agent(payload)
      .authenticate_agent(agent_id, token)
      .rotate_agent_token(agent_id)
      .revoke_agent(agent_id, revoked)
      .heartbeat(agent_id, payload)
      .list_agents()
      .record_event(payload)
      .list_events(limit)
      .get_policy(policy_id)
      .signed_policy(policy_id)
      .list_policies()
      .update_policy(policy_id, payload)

    IMPROVEMENTS OVER JSON EnterpriseStore:
      - Events stored in indexed SQLite rows (fast range queries)
      - Agents fetched individually, no full-file parse
      - WAL mode: multiple readers + one writer simultaneously
      - No 5,000-event arbitrary cap — DB handles any volume
      - Atomic transactions — no partial-write corruption
    """

    def __init__(self, db_path_or_json_path):
        """
        Args:
            db_path_or_json_path: Either a Path/str to:
              - .db  file → opened as SQLite (new behaviour)
              - .json file → migrated to SQLite automatically
        """
        path = Path(db_path_or_json_path)

        # Accept old JSON path → derive .db path alongside it
        if path.suffix == ".json":
            self._db_path = path.with_suffix(".db")
            self._migrate_from_json(path)
        else:
            self._db_path = path

        self._db   = VaultDatabase(str(self._db_path))
        self._lock = threading.RLock()
        self._ensure_bootstrap()

        # Optional ML detector (mirrors EnterpriseStore)
        try:
            from server.ml_detector import MaliciousActivityDetector
            self.detector = MaliciousActivityDetector()
        except ImportError:
            self.detector = None

    # ── Bootstrap ──────────────────────────────────────────────────

    def _ensure_bootstrap(self):
        """Seed enrollment token and default policy on first run."""
        if not self._db.fetchone("SELECT value FROM vault_meta WHERE key='enrollment_token'"):
            self._db.execute(
                "INSERT INTO vault_meta(key,value) VALUES(?,?)",
                ("enrollment_token", secrets.token_urlsafe(32))
            )
        if not self._db.fetchone("SELECT value FROM vault_meta WHERE key='policy_signing_key'"):
            self._db.execute(
                "INSERT INTO vault_meta(key,value) VALUES(?,?)",
                ("policy_signing_key", secrets.token_urlsafe(48))
            )
        if not self._db.fetchone("SELECT policy_id FROM policies WHERE policy_id='default'"):
            self._db.execute(
                "INSERT INTO policies(policy_id,name,data,updated_at) VALUES(?,?,?,?)",
                ("default", "Default DLP Policy",
                 json.dumps(_DEFAULT_POLICY), time.time())
            )

    # ── Summary ────────────────────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        """Fleet counters for the admin dashboard."""
        now     = time.time()
        total   = self._db.fetchone("SELECT COUNT(*) as n FROM agents")["n"]
        online  = self._db.fetchone(
            "SELECT COUNT(*) as n FROM agents WHERE revoked=0 AND last_seen>=?",
            (now - 300,)
        )["n"]
        revoked = self._db.fetchone(
            "SELECT COUNT(*) as n FROM agents WHERE revoked=1"
        )["n"]
        ev_ct   = self._db.fetchone("SELECT COUNT(*) as n FROM events")["n"]
        pol_ct  = self._db.fetchone("SELECT COUNT(*) as n FROM policies")["n"]
        tok_row = self._db.fetchone(
            "SELECT value FROM vault_meta WHERE key='enrollment_token'"
        )
        tok_preview = (tok_row["value"][:10] + "...") if tok_row else "N/A"

        return {
            "total_agents"           : total,
            "online_agents"          : online,
            "revoked_agents"         : revoked,
            "event_count"            : ev_ct,
            "policy_count"           : pol_ct,
            "enrollment_token_preview": tok_preview,
        }

    # ── Enrollment Token ───────────────────────────────────────────

    def enrollment_token(self) -> str:
        row = self._db.fetchone(
            "SELECT value FROM vault_meta WHERE key='enrollment_token'"
        )
        return row["value"] if row else ""

    def rotate_enrollment_token(self) -> str:
        new_tok = secrets.token_urlsafe(32)
        self._db.execute(
            "UPDATE vault_meta SET value=? WHERE key='enrollment_token'",
            (new_tok,)
        )
        return new_tok

    # ── Agent Management ───────────────────────────────────────────

    def register_agent(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Enroll an endpoint. Returns agent dict with one-time token."""
        token = payload.get("enrollment_token", "")
        expected = self.enrollment_token()
        if not token or not secrets.compare_digest(token, expected):
            raise ValueError("invalid enrollment token")

        agent_id    = payload.get("agent_id") or secrets.token_hex(12)
        now         = time.time()
        agent_token = secrets.token_urlsafe(40)
        tok_hash    = _hash_secret(agent_token)

        existing = self._db.fetchone(
            "SELECT registered_at FROM agents WHERE agent_id=?", (agent_id,)
        )
        reg_at = existing["registered_at"] if existing else now

        self._db.execute(
            """INSERT OR REPLACE INTO agents
               (agent_id,hostname,assigned_user,department,os,ip_address,
                agent_version,policy_id,status,registered_at,last_seen,
                agent_token_hash,token_preview,token_rotated_at,revoked,last_heartbeat)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                agent_id,
                payload.get("hostname", "unknown"),
                payload.get("assigned_user", "unassigned"),
                payload.get("department", "unassigned"),
                payload.get("os", "unknown"),
                payload.get("ip_address", ""),
                payload.get("agent_version", "0.1.0"),
                payload.get("policy_id", "default"),
                "online",
                reg_at, now,
                tok_hash,
                agent_token[:8] + "...",
                now, 0,
                json.dumps(payload.get("heartbeat", {})),
            )
        )
        self._append_event(
            "agent_registered", "info", agent_id,
            {"hostname": payload.get("hostname", ""),
             "assigned_user": payload.get("assigned_user", "")}
        )
        result = self._public_agent(agent_id)
        result["agent_token"] = agent_token
        result["policy"]      = self.signed_policy(payload.get("policy_id", "default"))
        return result

    def authenticate_agent(
        self, agent_id: str, agent_token: Optional[str]
    ) -> Dict[str, Any]:
        """Validate agent credentials. Raises on failure."""
        if not agent_id or not agent_token:
            raise PermissionError("missing agent credentials")
        row = self._db.fetchone(
            "SELECT * FROM agents WHERE agent_id=?", (agent_id,)
        )
        if not row:
            raise KeyError(agent_id)
        if row["revoked"]:
            raise PermissionError("agent revoked")
        stored = row["agent_token_hash"] or ""
        if not stored or not hmac.compare_digest(stored, _hash_secret(agent_token)):
            raise PermissionError("invalid agent token")
        return dict(row)

    def rotate_agent_token(self, agent_id: str) -> Dict[str, Any]:
        """Issue a replacement token for an agent."""
        token    = secrets.token_urlsafe(40)
        tok_hash = _hash_secret(token)
        now      = time.time()
        self._db.execute(
            "UPDATE agents SET agent_token_hash=?,token_preview=?,token_rotated_at=? WHERE agent_id=?",
            (tok_hash, token[:8] + "...", now, agent_id)
        )
        self._append_event("agent_token_rotated", "info", agent_id, {})
        return {"agent_id": agent_id, "agent_token": token, "token_preview": token[:8] + "..."}

    def revoke_agent(self, agent_id: str, revoked: bool = True) -> Dict[str, Any]:
        """Revoke or restore an agent."""
        status = "revoked" if revoked else "offline"
        self._db.execute(
            "UPDATE agents SET revoked=?,status=? WHERE agent_id=?",
            (int(revoked), status, agent_id)
        )
        self._append_event(
            "agent_revoked" if revoked else "agent_restored",
            "medium", agent_id, {}
        )
        return self._public_agent(agent_id)

    def heartbeat(self, agent_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Update agent liveness, return latest signed policy."""
        row = self._db.fetchone(
            "SELECT revoked,policy_id FROM agents WHERE agent_id=?", (agent_id,)
        )
        if not row:
            raise KeyError(agent_id)
        if row["revoked"]:
            raise PermissionError("agent revoked")

        now = time.time()
        self._db.execute(
            """UPDATE agents
               SET last_seen=?,status=?,ip_address=?,last_heartbeat=?
               WHERE agent_id=?""",
            (
                now,
                payload.get("status", "online"),
                payload.get("ip_address", ""),
                json.dumps(payload),
                agent_id,
            )
        )
        return {
            "agent" : self._public_agent(agent_id),
            "policy": self.signed_policy(row["policy_id"] or "default"),
        }

    def list_agents(self) -> List[Dict[str, Any]]:
        """Return all agents ordered by last_seen (newest first)."""
        now  = time.time()
        rows = self._db.fetchall(
            "SELECT * FROM agents ORDER BY last_seen DESC"
        )
        result = []
        for r in rows:
            d = dict(r)
            d["online"]           = (now - d.get("last_seen", 0)) <= 300
            d["last_heartbeat"]   = json.loads(d.get("last_heartbeat", "{}"))
            d.pop("agent_token_hash", None)
            result.append(d)
        return result

    def _public_agent(self, agent_id: str) -> Dict[str, Any]:
        row = self._db.fetchone(
            "SELECT * FROM agents WHERE agent_id=?", (agent_id,)
        )
        if not row:
            return {}
        d = dict(row)
        d["last_heartbeat"] = json.loads(d.get("last_heartbeat", "{}"))
        d.pop("agent_token_hash", None)
        return d

    # ── Events ─────────────────────────────────────────────────────

    def record_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Score, store, and return a security event."""
        details   = payload.get("details", {})
        ev_type   = payload.get("type", "agent_event")
        severity  = payload.get("severity", "info")

        ml_dict = {}
        if self.detector:
            try:
                detection = self.detector.score_event(ev_type, severity, details)
                if detection.verdict in {"high", "critical"}:
                    severity = detection.verdict
                elif detection.verdict == "suspicious" and severity == "info":
                    severity = "medium"
                ml_dict = detection.to_dict()
            except Exception:
                pass

        event_id = secrets.token_hex(12)
        now      = time.time()

        self._db.execute(
            """INSERT INTO events(event_id,timestamp,type,severity,agent_id,details,ml_detection)
               VALUES(?,?,?,?,?,?,?)""",
            (
                event_id, now, ev_type, severity,
                payload.get("agent_id", ""),
                json.dumps(details),
                json.dumps(ml_dict),
            )
        )

        return {
            "event_id"    : event_id,
            "timestamp"   : now,
            "type"        : ev_type,
            "severity"    : severity,
            "agent_id"    : payload.get("agent_id", ""),
            "details"     : details,
            "ml_detection": ml_dict,
        }

    def list_events(
        self,
        limit       : int = 100,
        agent_id    : Optional[str] = None,
        severity    : Optional[str] = None,
        event_type  : Optional[str] = None,
        since_ts    : Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """
        Return events newest-first.
        Supports optional server-side filtering — no full-table scan needed.

        Args:
            limit     : Max rows to return (capped at 500)
            agent_id  : Filter to one agent
            severity  : Filter by severity string
            event_type: Filter by event type string
            since_ts  : Only events after this Unix timestamp
        """
        limit  = max(1, min(limit, 500))
        where  = []
        params = []

        if agent_id:
            where.append("agent_id = ?")
            params.append(agent_id)
        if severity:
            where.append("severity = ?")
            params.append(severity)
        if event_type:
            where.append("type = ?")
            params.append(event_type)
        if since_ts:
            where.append("timestamp >= ?")
            params.append(since_ts)

        sql = "SELECT * FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self._db.fetchall(sql, tuple(params))
        result = []
        for r in rows:
            d = dict(r)
            d["details"]     = json.loads(d.get("details", "{}"))
            d["ml_detection"]= json.loads(d.get("ml_detection", "{}"))
            result.append(d)
        return result

    def event_count_by_severity(self) -> Dict[str, int]:
        """Return counts grouped by severity for dashboard stats."""
        rows = self._db.fetchall(
            "SELECT severity, COUNT(*) as n FROM events GROUP BY severity"
        )
        return {r["severity"]: r["n"] for r in rows}

    def _append_event(
        self, event_type: str, severity: str,
        agent_id: str, details: Dict[str, Any]
    ):
        """Internal: append a system-generated event."""
        self.record_event({
            "type"    : event_type,
            "severity": severity,
            "agent_id": agent_id,
            "details" : details,
        })

    # ── Policies ───────────────────────────────────────────────────

    def get_policy(self, policy_id: str = "default") -> Optional[Dict[str, Any]]:
        row = self._db.fetchone(
            "SELECT data FROM policies WHERE policy_id=?", (policy_id,)
        )
        return json.loads(row["data"]) if row else None

    def signed_policy(self, policy_id: str = "default") -> Optional[Dict[str, Any]]:
        """Return a policy with HMAC signature envelope."""
        policy = self.get_policy(policy_id)
        if not policy:
            return None
        key_row = self._db.fetchone(
            "SELECT value FROM vault_meta WHERE key='policy_signing_key'"
        )
        signing_key = (key_row["value"] if key_row else "").encode("utf-8")
        payload     = {
            "policy"       : copy.deepcopy(policy),
            "issued_at"    : time.time(),
            "signature_alg": "HMAC-SHA256",
        }
        raw = json.dumps(
            {k: payload[k] for k in ("policy", "issued_at", "signature_alg")},
            sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        payload["signature"] = hmac.new(signing_key, raw, hashlib.sha256).hexdigest()
        return payload

    def list_policies(self) -> List[Dict[str, Any]]:
        rows = self._db.fetchall("SELECT data FROM policies")
        return [json.loads(r["data"]) for r in rows]

    def update_policy(self, policy_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        existing = self.get_policy(policy_id) or copy.deepcopy(_DEFAULT_POLICY)
        existing.update(payload)
        existing["policy_id"]  = policy_id
        existing["updated_at"] = time.time()
        self._db.execute(
            "INSERT OR REPLACE INTO policies(policy_id,name,data,updated_at) VALUES(?,?,?,?)",
            (policy_id, existing.get("name", policy_id),
             json.dumps(existing), existing["updated_at"])
        )
        self._append_event("policy_updated", "info", "", {"policy_id": policy_id})
        return existing

    # ── JSON Migration ─────────────────────────────────────────────

    def _migrate_from_json(self, json_path: Path):
        """
        One-time migration from the old enterprise_state.json to SQLite.
        Called automatically when the constructor receives a .json path.
        Safe to call repeatedly — already-migrated data is skipped.
        """
        if not json_path.exists():
            return
        try:
            state = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            return

        db = VaultDatabase(str(self._db_path))

        # Migrate agents
        for agent in state.get("agents", {}).values():
            existing = db.fetchone(
                "SELECT agent_id FROM agents WHERE agent_id=?",
                (agent.get("agent_id", ""),)
            )
            if not existing:
                db.execute(
                    """INSERT OR IGNORE INTO agents
                       (agent_id,hostname,assigned_user,department,os,ip_address,
                        agent_version,policy_id,status,registered_at,last_seen,
                        agent_token_hash,token_preview,token_rotated_at,revoked,last_heartbeat)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        agent.get("agent_id", ""),
                        agent.get("hostname", ""),
                        agent.get("assigned_user", "unassigned"),
                        agent.get("department", "unassigned"),
                        agent.get("os", "unknown"),
                        agent.get("ip_address", ""),
                        agent.get("agent_version", "0.1.0"),
                        agent.get("policy_id", "default"),
                        agent.get("status", "offline"),
                        agent.get("registered_at", time.time()),
                        agent.get("last_seen", 0),
                        agent.get("agent_token_hash", _hash_secret(secrets.token_hex(8))),
                        agent.get("token_preview", ""),
                        agent.get("token_rotated_at", time.time()),
                        int(agent.get("revoked", False)),
                        json.dumps(agent.get("last_heartbeat", {})),
                    )
                )

        # Migrate events
        for ev in state.get("events", []):
            existing = db.fetchone(
                "SELECT event_id FROM events WHERE event_id=?",
                (ev.get("event_id", ""),)
            )
            if not existing and ev.get("event_id"):
                db.execute(
                    """INSERT OR IGNORE INTO events
                       (event_id,timestamp,type,severity,agent_id,details,ml_detection)
                       VALUES(?,?,?,?,?,?,?)""",
                    (
                        ev.get("event_id", secrets.token_hex(12)),
                        ev.get("timestamp", time.time()),
                        ev.get("type", "migrated"),
                        ev.get("severity", "info"),
                        ev.get("agent_id", ""),
                        json.dumps(ev.get("details", {})),
                        json.dumps(ev.get("ml_detection", {})),
                    )
                )

        # Migrate policies
        for policy_id, policy in state.get("policies", {}).items():
            existing = db.fetchone(
                "SELECT policy_id FROM policies WHERE policy_id=?", (policy_id,)
            )
            if not existing:
                db.execute(
                    "INSERT OR IGNORE INTO policies(policy_id,name,data,updated_at) VALUES(?,?,?,?)",
                    (policy_id, policy.get("name", policy_id),
                     json.dumps(policy), time.time())
                )

        # Migrate meta keys
        for key in ("enrollment_token", "policy_signing_key"):
            if key in state:
                existing = db.fetchone(
                    "SELECT key FROM vault_meta WHERE key=?", (key,)
                )
                if not existing:
                    db.execute(
                        "INSERT OR IGNORE INTO vault_meta(key,value) VALUES(?,?)",
                        (key, state[key])
                    )

        db.close()
        print(f"[VaultDB] Migrated enterprise_state.json → {self._db_path}")


# ══════════════════════════════════════════════════════════════════
# AUDIT LEDGER DB — drop-in replacement for AuditLedger
# ══════════════════════════════════════════════════════════════════

class AuditLedgerDB:
    """
    SQLite-backed replacement for AuditLedger.

    IDENTICAL PUBLIC API to AuditLedger:
      .log(event_type, details)    → returns entry-like object
      .read_all()                  → list of LedgerEntry-compatible dicts
      .verify_chain()              → (bool, message)
      .print_recent(n)
      .export_for_audit(path)

    IMPROVEMENTS OVER JSONL AuditLedger:
      - Indexed queries: search by event_type, time range in milliseconds
      - No full-file parse needed for pagination
      - WAL mode: concurrent reads while writing
      - Atomic inserts: no partial-line corruption possible
      - Backward migration: imports existing vault_audit.jsonl automatically

    IMMUTABILITY GUARANTEE:
      Application code only ever calls INSERT on audit_chain.
      No UPDATE or DELETE is ever issued.
      The hash chain provides cryptographic tamper evidence
      (identical to the JSONL version).
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, vault_dir: str, sign_fn=None, db: Optional[VaultDatabase] = None):
        """
        Args:
            vault_dir: Path to vault directory.
                       DB stored at vault_dir/vaultx.db
                       JSONL imported from vault_dir/vault_audit.jsonl if present
            sign_fn  : Optional Ed25519 signer (same interface as AuditLedger)
            db       : Optional shared VaultDatabase (avoids opening a second file)
        """
        self.vault_dir   = vault_dir
        self._sign_fn    = sign_fn
        self._db         = db or VaultDatabase(os.path.join(vault_dir, "vaultx.db"))
        self._lock       = threading.Lock()
        self._count      : int   = 0
        self._last_hash  : str   = self.GENESIS_HASH

        os.makedirs(vault_dir, exist_ok=True)
        self._recover_chain_state()
        self._migrate_jsonl()

    def _recover_chain_state(self):
        """Read the last entry to restore in-memory chain head."""
        row = self._db.fetchone(
            "SELECT idx, entry_hash FROM audit_chain ORDER BY idx DESC LIMIT 1"
        )
        if row:
            self._count     = row["idx"] + 1
            self._last_hash = row["entry_hash"]

    def _migrate_jsonl(self):
        """
        One-time import of existing vault_audit.jsonl into audit_chain.
        Safe to call repeatedly — already-present entries are skipped.
        """
        jsonl_path = os.path.join(self.vault_dir, "vault_audit.jsonl")
        if not os.path.exists(jsonl_path):
            return

        existing_count = self._db.fetchone(
            "SELECT COUNT(*) as n FROM audit_chain"
        )["n"]
        if existing_count > 0:
            return  # Already migrated

        import_count = 0
        with open(jsonl_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    self._db.execute(
                        """INSERT OR IGNORE INTO audit_chain
                           (idx,event_type,details,ts,unix_ts,prev_hash,entry_hash,signature)
                           VALUES(?,?,?,?,?,?,?,?)""",
                        (
                            e.get("index", import_count),
                            e.get("event_type", "migrated"),
                            json.dumps(e.get("details", {})),
                            e.get("timestamp", datetime.now().isoformat()),
                            e.get("unix_ts", time.time()),
                            e.get("prev_hash", self.GENESIS_HASH),
                            e.get("entry_hash", "0" * 64),
                            e.get("signature"),
                        )
                    )
                    import_count += 1
                except Exception:
                    pass

        if import_count:
            self._recover_chain_state()
            print(f"[AuditLedgerDB] Migrated {import_count} entries from vault_audit.jsonl")

    # ── Core API ────────────────────────────────────────────────────

    def log(self, event_type: str, details: dict) -> "_AuditEntry":
        """
        Append an event to the audit chain.

        ATOMICITY: The INSERT is atomic — either it fully succeeds
        or the chain state is unchanged. No partial entries possible.

        Returns an _AuditEntry object (compatible with LedgerEntry).
        """
        with self._lock:
            import hashlib as _h

            ts     = datetime.now().isoformat()
            unix_ts= time.time()
            idx    = self._count
            prev_h = self._last_hash

            # Compute entry hash (same algorithm as AuditLedger)
            core = json.dumps({
                "index"     : idx,
                "event_type": event_type,
                "details"   : details,
                "timestamp" : ts,
                "prev_hash" : prev_h,
            }, sort_keys=True).encode()
            entry_hash = _h.sha256(core).hexdigest()

            # Sign if signer available
            signature = None
            if self._sign_fn:
                try:
                    signature = self._sign_fn({
                        "index"     : idx,
                        "event_type": event_type,
                        "entry_hash": entry_hash,
                        "timestamp" : ts,
                    })
                except Exception:
                    signature = "unavailable"

            self._db.execute(
                """INSERT INTO audit_chain
                   (idx,event_type,details,ts,unix_ts,prev_hash,entry_hash,signature)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (idx, event_type, json.dumps(details), ts,
                 unix_ts, prev_h, entry_hash, signature)
            )

            self._last_hash = entry_hash
            self._count     = idx + 1

            return _AuditEntry(
                index      = idx,
                event_type = event_type,
                details    = details,
                timestamp  = ts,
                unix_ts    = unix_ts,
                prev_hash  = prev_h,
                entry_hash = entry_hash,
                signature  = signature,
            )

    def read_all(self) -> List["_AuditEntry"]:
        """Return all entries in ascending index order."""
        rows = self._db.fetchall(
            "SELECT * FROM audit_chain ORDER BY idx ASC"
        )
        return [_AuditEntry.from_row(r) for r in rows]

    def read_recent(self, n: int = 50) -> List["_AuditEntry"]:
        """Return the last n entries, newest first. Much faster than read_all()."""
        rows = self._db.fetchall(
            "SELECT * FROM audit_chain ORDER BY idx DESC LIMIT ?", (n,)
        )
        return [_AuditEntry.from_row(r) for r in rows]

    def search(
        self,
        event_type : Optional[str]   = None,
        since_ts   : Optional[float] = None,
        until_ts   : Optional[float] = None,
        limit      : int             = 100,
    ) -> List["_AuditEntry"]:
        """
        Filtered search — not available in original AuditLedger.
        Uses indexes on event_type and unix_ts for fast results.
        """
        where  = []
        params = []
        if event_type:
            where.append("event_type = ?")
            params.append(event_type)
        if since_ts:
            where.append("unix_ts >= ?")
            params.append(since_ts)
        if until_ts:
            where.append("unix_ts <= ?")
            params.append(until_ts)

        sql = "SELECT * FROM audit_chain"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += f" ORDER BY idx DESC LIMIT {int(limit)}"

        rows = self._db.fetchall(sql, tuple(params))
        return [_AuditEntry.from_row(r) for r in rows]

    def verify_chain(self) -> Tuple[bool, str]:
        """
        Verify the full hash chain integrity.
        Identical result to AuditLedger.verify_chain().
        """
        import hashlib as _h

        rows     = self._db.fetchall(
            "SELECT * FROM audit_chain ORDER BY idx ASC"
        )
        prev     = self.GENESIS_HASH
        count    = 0

        for row in rows:
            idx  = row["idx"]
            if idx != count:
                return False, f"Sequence error at entry {idx}"
            if row["prev_hash"] != prev:
                return False, f"Chain break at entry {idx}"

            # Recompute hash
            core = json.dumps({
                "index"     : idx,
                "event_type": row["event_type"],
                "details"   : json.loads(row["details"]),
                "timestamp" : row["ts"],
                "prev_hash" : row["prev_hash"],
            }, sort_keys=True).encode()
            expected = _h.sha256(core).hexdigest()

            if expected != row["entry_hash"]:
                return False, f"Hash mismatch at entry {idx}"

            prev  = row["entry_hash"]
            count += 1

        return True, f"Chain valid. {count} entries verified."

    def print_recent(self, n: int = 20):
        """Print last n entries — same output as AuditLedger.print_recent()."""
        entries = self.read_recent(n)
        print(f"\n{'─'*68}")
        print(f"  VAULT-X Audit Ledger (SQLite) — Last {len(entries)} entries")
        print(f"{'─'*68}")
        for e in entries:
            print(f"\n  [{e.timestamp[:19]}] #{e.index}  {e.event_type}")
            print(f"   hash: {e.entry_hash[:24]}...")
            for k, v in (e.details or {}).items():
                if k != "signature":
                    print(f"   {k}: {v}")
        print(f"{'─'*68}\n")

    def export_for_audit(self, output_path: str):
        """Export complete ledger as structured JSON — same as AuditLedger."""
        entries = self.read_all()
        with open(output_path, "w") as f:
            json.dump({
                "vault_x_version": "2.0.0",
                "exported_at"    : datetime.now().isoformat(),
                "entry_count"    : len(entries),
                "entries"        : [e.to_dict() for e in entries],
            }, f, indent=2)
        print(f"[AuditLedgerDB] Exported {len(entries)} entries → {output_path}")

    @property
    def _count_prop(self) -> int:
        return self._count


class _AuditEntry:
    """
    Lightweight audit entry object matching the LedgerEntry interface.
    Returned by AuditLedgerDB.log() and read operations.
    """
    __slots__ = (
        "index", "event_type", "details", "timestamp",
        "unix_ts", "prev_hash", "entry_hash", "signature",
    )

    def __init__(self, index, event_type, details, timestamp,
                 unix_ts, prev_hash, entry_hash, signature):
        self.index      = index
        self.event_type = event_type
        self.details    = details
        self.timestamp  = timestamp
        self.unix_ts    = unix_ts
        self.prev_hash  = prev_hash
        self.entry_hash = entry_hash
        self.signature  = signature

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "_AuditEntry":
        return cls(
            index      = row["idx"],
            event_type = row["event_type"],
            details    = json.loads(row["details"]),
            timestamp  = row["ts"],
            unix_ts    = row["unix_ts"],
            prev_hash  = row["prev_hash"],
            entry_hash = row["entry_hash"],
            signature  = row["signature"],
        )

    def to_dict(self) -> dict:
        return {
            "index"     : self.index,
            "event_type": self.event_type,
            "details"   : self.details,
            "timestamp" : self.timestamp,
            "unix_ts"   : self.unix_ts,
            "prev_hash" : self.prev_hash,
            "entry_hash": self.entry_hash,
            "signature" : self.signature,
        }

    def verify_hash(self) -> bool:
        import hashlib as _h
        core = json.dumps({
            "index"     : self.index,
            "event_type": self.event_type,
            "details"   : self.details,
            "timestamp" : self.timestamp,
            "prev_hash" : self.prev_hash,
        }, sort_keys=True).encode()
        return _h.sha256(core).hexdigest() == self.entry_hash


# ══════════════════════════════════════════════════════════════════
# ENCRYPTED BLOB STORE
# ══════════════════════════════════════════════════════════════════

class BlobStore:
    """
    Store VaultBlob metadata in SQLite for indexing and querying.

    The actual encrypted content remains in .vault files on disk.
    This table stores the blob metadata so the GUI and server
    can list, search, and look up blobs without reading every file.

    USAGE:
      store = BlobStore(db)
      store.save_blob(blob, filename="secret.txt", owner_hash="abc123")
      blobs = store.list_blobs(owner_hash="abc123")
      store.delete_blob(blob_id)
    """

    def __init__(self, db: VaultDatabase):
        self._db = db

    def save_blob(
        self,
        blob,            # VaultBlob instance
        filename   : str = "",
        owner_hash : str = "",
    ):
        """
        Store VaultBlob metadata.

        Args:
            blob      : VaultBlob dataclass instance from vault_engine
            filename  : Original filename (e.g. "secret.txt")
            owner_hash: Hash of the owner's identity
        """
        import dataclasses
        d = dataclasses.asdict(blob)
        self._db.execute(
            """INSERT OR REPLACE INTO blobs
               (blob_id,session_id,filename,chacha_nonce,aes_nonce,
                chacha_ciphertext,aes_ciphertext,canary_hash,
                created_at,vault_version,owner_hash,size_bytes)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                d["blob_id"], d["session_id"], filename,
                d["chacha_nonce"], d["aes_nonce"],
                d["chacha_ciphertext"], d["aes_ciphertext"],
                d["canary_hash"], d["created_at"],
                d.get("vault_version", "1.0.0"),
                owner_hash,
                len(d.get("aes_ciphertext", "")),
            )
        )

    def get_blob(self, blob_id: str) -> Optional[Dict]:
        row = self._db.fetchone(
            "SELECT * FROM blobs WHERE blob_id=?", (blob_id,)
        )
        return dict(row) if row else None

    def list_blobs(
        self,
        owner_hash : Optional[str] = None,
        limit      : int = 100,
    ) -> List[Dict]:
        if owner_hash:
            rows = self._db.fetchall(
                "SELECT * FROM blobs WHERE owner_hash=? ORDER BY created_at DESC LIMIT ?",
                (owner_hash, limit)
            )
        else:
            rows = self._db.fetchall(
                "SELECT * FROM blobs ORDER BY created_at DESC LIMIT ?",
                (limit,)
            )
        return [dict(r) for r in rows]

    def delete_blob(self, blob_id: str):
        self._db.execute("DELETE FROM blobs WHERE blob_id=?", (blob_id,))

    def blob_count(self, owner_hash: Optional[str] = None) -> int:
        if owner_hash:
            return self._db.fetchone(
                "SELECT COUNT(*) as n FROM blobs WHERE owner_hash=?", (owner_hash,)
            )["n"]
        return self._db.fetchone("SELECT COUNT(*) as n FROM blobs")["n"]


# ══════════════════════════════════════════════════════════════════
# CONFIG STORE
# ══════════════════════════════════════════════════════════════════

class ConfigStore:
    """
    SQLite key-value store replacing vault_config.json for
    lightweight configuration values.

    Handles concurrent access safely via WAL mode.
    All values serialized as JSON strings.

    USAGE:
      cfg = ConfigStore(db)
      cfg.set("owner_hash", "abc123def...")
      cfg.set("layer_a_totp", {"secret": "..."})
      val = cfg.get("owner_hash")
      cfg.delete("temp_key")
    """

    def __init__(self, db: VaultDatabase):
        self._db = db

    def get(self, key: str, default=None):
        row = self._db.fetchone(
            "SELECT value FROM config WHERE key=?", (key,)
        )
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except Exception:
            return row["value"]

    def set(self, key: str, value: Any):
        self._db.execute(
            "INSERT OR REPLACE INTO config(key,value,updated_at) VALUES(?,?,?)",
            (key, json.dumps(value), time.time())
        )

    def delete(self, key: str):
        self._db.execute("DELETE FROM config WHERE key=?", (key,))

    def get_all(self) -> Dict[str, Any]:
        rows = self._db.fetchall("SELECT key,value FROM config")
        result = {}
        for r in rows:
            try:
                result[r["key"]] = json.loads(r["value"])
            except Exception:
                result[r["key"]] = r["value"]
        return result

    def set_many(self, data: Dict[str, Any]):
        """Batch insert/update multiple keys in one transaction."""
        now = time.time()
        with self._db.transaction() as con:
            for k, v in data.items():
                con.execute(
                    "INSERT OR REPLACE INTO config(key,value,updated_at) VALUES(?,?,?)",
                    (k, json.dumps(v), now)
                )


# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════

def _hash_secret(secret: str) -> str:
    """SHA-256 hash of a secret string (mirrors EnterpriseStore._hash_secret)."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()
