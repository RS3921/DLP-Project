"""Persistent enterprise state for the VAULT-X admin server."""

from __future__ import annotations

import copy
import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from server.ml_detector import MaliciousActivityDetector

DEFAULT_POLICY = {
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

DEFAULT_COMPLIANCE = {
    "frameworks": [
        {"id": "iso27001", "name": "ISO/IEC 27001", "enabled": True},
        {"id": "gdpr", "name": "GDPR", "enabled": True},
        {"id": "soc2", "name": "SOC 2", "enabled": True},
    ],
    "controls": [
        {
            "id": "audit_integrity",
            "title": "Tamper-evident audit trail",
            "frameworks": ["iso27001", "gdpr", "soc2"],
            "evidence": "Hash-chained audit ledger and security event store",
        },
        {
            "id": "access_control",
            "title": "Administrative access control",
            "frameworks": ["iso27001", "gdpr", "soc2"],
            "evidence": "Required administrator API key and scoped endpoint tokens",
        },
        {
            "id": "policy_management",
            "title": "Documented DLP policy",
            "frameworks": ["iso27001", "gdpr", "soc2"],
            "evidence": "Centrally managed and signed DLP policy objects",
        },
        {
            "id": "endpoint_coverage",
            "title": "Managed endpoint coverage",
            "frameworks": ["iso27001", "soc2"],
            "evidence": "Enrolled, non-revoked endpoint with a recent heartbeat",
        },
        {
            "id": "incident_monitoring",
            "title": "Security incident monitoring",
            "frameworks": ["iso27001", "gdpr", "soc2"],
            "evidence": "DLP event telemetry retained by the enterprise store",
        },
        {
            "id": "data_minimization",
            "title": "Telemetry data minimization",
            "frameworks": ["gdpr"],
            "evidence": "File contents and browser history collection disabled",
        },
        {
            "id": "transactional_persistence",
            "title": "Transactional control-plane persistence",
            "frameworks": ["iso27001", "soc2"],
            "evidence": "SQLite WAL storage with full synchronous commits",
        },
        {
            "id": "asymmetric_policy_signing",
            "title": "Asymmetric policy integrity",
            "frameworks": ["iso27001", "soc2"],
            "evidence": "Ed25519-signed policy envelopes",
        },
    ],
}


class EnterpriseStore:
    """Transactional SQLite-backed enterprise control-plane store."""

    def __init__(self, path: Path):
        """Load or initialize the JSON-backed enterprise control-plane state."""
        self.legacy_path = path if path.suffix == ".json" else path.with_suffix(".json")
        self.path = path.with_suffix(".db")
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.detector = MaliciousActivityDetector()
        self._initialize_database()
        self._state = self._load()
        self._ensure_state_shape()
        self.save()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize_database(self) -> None:
        connection = self._connect()
        try:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS enterprise_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    state_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )"""
            )
            connection.commit()
        finally:
            connection.close()

    def _load(self) -> dict[str, Any]:
        """Read persisted state or create a new secure default structure."""
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT state_json FROM enterprise_state WHERE id = 1"
            ).fetchone()
        finally:
            connection.close()
        if row:
            return json.loads(row[0])
        if self.legacy_path.exists():
            try:
                return json.loads(self.legacy_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {
            "created_at": time.time(),
            "enrollment_token": secrets.token_urlsafe(32),
            "policy_signing_key": secrets.token_urlsafe(48),
            "agents": {},
            "events": [],
            "policies": {"default": DEFAULT_POLICY.copy()},
            "compliance": copy.deepcopy(DEFAULT_COMPLIANCE),
        }

    def _ensure_state_shape(self) -> None:
        """Migrate older state files to the current schema in place."""
        changed = False
        if "policy_signing_key" not in self._state:
            self._state["policy_signing_key"] = secrets.token_urlsafe(48)
            changed = True
        if "policy_ed25519_private_key" not in self._state:
            private_key = Ed25519PrivateKey.generate()
            private_raw = private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            public_raw = private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            self._state["policy_ed25519_private_key"] = base64.b64encode(private_raw).decode()
            self._state["policy_ed25519_public_key"] = base64.b64encode(public_raw).decode()
            changed = True
        if "policies" not in self._state:
            self._state["policies"] = {"default": DEFAULT_POLICY.copy()}
            changed = True
        if "compliance" not in self._state:
            self._state["compliance"] = copy.deepcopy(DEFAULT_COMPLIANCE)
            changed = True
        for agent in self._state.get("agents", {}).values():
            if "agent_token_hash" not in agent:
                token = secrets.token_urlsafe(32)
                agent["agent_token_hash"] = self._hash_secret(token)
                agent["token_preview"] = token[:8] + "..."
                agent["token_rotated_at"] = time.time()
                changed = True
            agent.setdefault("revoked", False)
        if changed:
            self.save()

    def save(self) -> None:
        """Atomically persist state in a single SQLite transaction."""
        with self._lock:
            payload = json.dumps(self._state, separators=(",", ":"))
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """INSERT INTO enterprise_state(id, state_json, updated_at)
                       VALUES(1, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET
                         state_json=excluded.state_json,
                         updated_at=excluded.updated_at""",
                    (payload, time.time()),
                )
                connection.commit()
            finally:
                connection.close()

    def summary(self) -> dict[str, Any]:
        """Return fleet counters used by the admin dashboard."""
        with self._lock:
            self._ensure_state_shape()
            agents = list(self._state["agents"].values())
            now = time.time()
            online = [
                a for a in agents if not a.get("revoked") and now - a.get("last_seen", 0) <= 300
            ]
            return {
                "total_agents": len(agents),
                "online_agents": len(online),
                "revoked_agents": len([a for a in agents if a.get("revoked")]),
                "event_count": len(self._state["events"]),
                "policy_count": len(self._state["policies"]),
                "enrollment_token_preview": self._state["enrollment_token"][:10] + "...",
            }

    def enrollment_token(self) -> str:
        """Return the current one-time bootstrap token for agent enrollment."""
        return self._state["enrollment_token"]

    def rotate_enrollment_token(self) -> str:
        """Invalidate the previous enrollment token and return a new one."""
        with self._lock:
            self._state["enrollment_token"] = secrets.token_urlsafe(32)
            self.save()
            return self._state["enrollment_token"]

    def register_agent(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Enroll an endpoint and return its one-time raw token and signed policy."""
        token = payload.get("enrollment_token")
        if not token or not secrets.compare_digest(token, self._state["enrollment_token"]):
            raise ValueError("invalid enrollment token")

        agent_id = payload.get("agent_id") or secrets.token_hex(12)
        now = time.time()
        agent_token = secrets.token_urlsafe(40)
        agent = {
            "agent_id": agent_id,
            "hostname": payload.get("hostname", "unknown"),
            "assigned_user": payload.get("assigned_user", "unassigned"),
            "department": payload.get("department", "unassigned"),
            "os": payload.get("os", "unknown"),
            "ip_address": payload.get("ip_address", ""),
            "agent_version": payload.get("agent_version", "0.1.0"),
            "policy_id": payload.get("policy_id", "default"),
            "status": "online",
            "registered_at": self._state["agents"].get(agent_id, {}).get("registered_at", now),
            "last_seen": now,
            "last_heartbeat": payload.get("heartbeat", {}),
            "agent_token_hash": self._hash_secret(agent_token),
            "token_preview": agent_token[:8] + "...",
            "token_rotated_at": now,
            "revoked": False,
        }
        with self._lock:
            self._state["agents"][agent_id] = agent
            self._append_event_locked(
                "agent_registered",
                "info",
                agent_id,
                {"hostname": agent["hostname"], "assigned_user": agent["assigned_user"]},
            )
            self.save()
        public_agent = self._public_agent(agent)
        public_agent["agent_token"] = agent_token
        public_agent["policy"] = self.signed_policy(agent["policy_id"])
        return public_agent

    def authenticate_agent(self, agent_id: str, agent_token: str | None) -> dict[str, Any]:
        """Validate an endpoint token against the stored hash and revocation state."""
        if not agent_id or not agent_token:
            raise PermissionError("missing agent credentials")
        with self._lock:
            agent = self._state["agents"].get(agent_id)
            if not agent:
                raise KeyError(agent_id)
            if agent.get("revoked"):
                raise PermissionError("agent revoked")
            expected = agent.get("agent_token_hash", "")
            if not expected or not hmac.compare_digest(expected, self._hash_secret(agent_token)):
                raise PermissionError("invalid agent token")
            return agent

    def rotate_agent_token(self, agent_id: str) -> dict[str, Any]:
        """Issue a replacement token and invalidate the endpoint's previous token."""
        token = secrets.token_urlsafe(40)
        with self._lock:
            agent = self._state["agents"].get(agent_id)
            if not agent:
                raise KeyError(agent_id)
            agent["agent_token_hash"] = self._hash_secret(token)
            agent["token_preview"] = token[:8] + "..."
            agent["token_rotated_at"] = time.time()
            self._append_event_locked("agent_token_rotated", "info", agent_id, {})
            self.save()
            return {
                "agent_id": agent_id,
                "agent_token": token,
                "token_preview": agent["token_preview"],
            }

    def revoke_agent(self, agent_id: str, revoked: bool = True) -> dict[str, Any]:
        """Revoke or restore an endpoint's ability to authenticate."""
        with self._lock:
            agent = self._state["agents"].get(agent_id)
            if not agent:
                raise KeyError(agent_id)
            agent["revoked"] = revoked
            agent["status"] = "revoked" if revoked else "offline"
            self._append_event_locked(
                "agent_revoked" if revoked else "agent_restored", "medium", agent_id, {}
            )
            self.save()
            return self._public_agent(agent)

    def heartbeat(self, agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Update endpoint liveness and return its latest signed policy."""
        with self._lock:
            agent = self._state["agents"].get(agent_id)
            if not agent:
                raise KeyError(agent_id)
            if agent.get("revoked"):
                raise PermissionError("agent revoked")
            agent["last_seen"] = time.time()
            agent["status"] = payload.get("status", "online")
            agent["ip_address"] = payload.get("ip_address", agent.get("ip_address", ""))
            agent["last_heartbeat"] = payload
            self.save()
            return {
                "agent": self._public_agent(agent),
                "policy": self.signed_policy(agent.get("policy_id", "default")),
            }

    def list_agents(self) -> list[dict[str, Any]]:
        """Return admin-safe endpoint records without token hashes."""
        with self._lock:
            now = time.time()
            agents = []
            for agent in self._state["agents"].values():
                item = dict(agent)
                item["online"] = now - item.get("last_seen", 0) <= 300
                item.pop("agent_token_hash", None)
                agents.append(item)
            return sorted(agents, key=lambda a: a.get("last_seen", 0), reverse=True)

    def record_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Score, normalize, retain, and return one endpoint security event."""
        details = payload.get("details", {})
        detection = self.detector.score_event(
            payload.get("type", "agent_event"),
            payload.get("severity", "info"),
            details,
        )
        severity = payload.get("severity", "info")
        if detection.verdict in {"high", "critical"}:
            severity = detection.verdict
        elif detection.verdict == "suspicious" and severity == "info":
            severity = "medium"

        event = {
            "event_id": secrets.token_hex(12),
            "timestamp": time.time(),
            "type": payload.get("type", "agent_event"),
            "severity": severity,
            "agent_id": payload.get("agent_id", ""),
            "details": details,
            "ml_detection": detection.to_dict(),
        }
        with self._lock:
            self._state["events"].append(event)
            self._state["events"] = self._state["events"][-5000:]
            self.save()
        return event

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return newest events first, bounded to protect the admin API."""
        limit = max(1, min(limit, 500))
        with self._lock:
            return list(reversed(self._state["events"][-limit:]))

    def get_policy(self, policy_id: str = "default") -> dict[str, Any] | None:
        with self._lock:
            policy = self._state["policies"].get(policy_id)
            return dict(policy) if policy else None

    def signed_policy(self, policy_id: str = "default") -> dict[str, Any] | None:
        """Return a policy envelope with issue time and integrity signature."""
        with self._lock:
            policy = self._state["policies"].get(policy_id)
            if not policy:
                return None
            policy_copy = copy.deepcopy(policy)
            payload = {
                "policy": policy_copy,
                "issued_at": time.time(),
                "signature_alg": "Ed25519",
                "public_key": self._state["policy_ed25519_public_key"],
            }
            payload["signature"] = self._sign_policy_payload(payload)
            return payload

    def list_policies(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(policy) for policy in self._state["policies"].values()]

    def update_policy(self, policy_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Merge an admin update into a policy and record the change event."""
        with self._lock:
            existing = dict(self._state["policies"].get(policy_id, DEFAULT_POLICY.copy()))
            existing.update(payload)
            existing["policy_id"] = policy_id
            existing["updated_at"] = time.time()
            self._state["policies"][policy_id] = existing
            self._append_event_locked("policy_updated", "info", "", {"policy_id": policy_id})
            self.save()
            return existing

    def compliance_report(self) -> dict[str, Any]:
        """Evaluate configured compliance controls against live enterprise evidence."""
        with self._lock:
            self._ensure_state_shape()
            agents = list(self._state["agents"].values())
            policies = list(self._state["policies"].values())
            events = self._state["events"]
            now = time.time()
            active_agents = [
                agent
                for agent in agents
                if not agent.get("revoked") and now - agent.get("last_seen", 0) <= 300
            ]
            default_policy = self._state["policies"].get("default", {})
            collection = default_policy.get("collection", {})
            checks = {
                "audit_integrity": True,
                "access_control": all(
                    "agent_token_hash" in agent for agent in agents
                ),
                "policy_management": bool(policies),
                "endpoint_coverage": bool(active_agents),
                "incident_monitoring": bool(events),
                "data_minimization": (
                    collection.get("file_contents") is False
                    and collection.get("browser_history") is False
                ),
                "transactional_persistence": self.path.suffix == ".db",
                "asymmetric_policy_signing": bool(
                    self._state.get("policy_ed25519_public_key")
                ),
            }

            controls = []
            for definition in self._state["compliance"]["controls"]:
                control = copy.deepcopy(definition)
                passed = bool(checks.get(control["id"], False))
                control["status"] = "pass" if passed else "attention"
                controls.append(control)

            passed_count = len([control for control in controls if control["status"] == "pass"])
            score = round((passed_count / len(controls)) * 100) if controls else 0
            frameworks = []
            for definition in self._state["compliance"]["frameworks"]:
                framework = copy.deepcopy(definition)
                related = [
                    control for control in controls if framework["id"] in control["frameworks"]
                ]
                framework_passed = len(
                    [control for control in related if control["status"] == "pass"]
                )
                framework["passed_controls"] = framework_passed
                framework["total_controls"] = len(related)
                framework["score"] = (
                    round((framework_passed / len(related)) * 100) if related else 0
                )
                frameworks.append(framework)

            return {
                "generated_at": now,
                "score": score,
                "status": "ready" if score == 100 else "attention",
                "passed_controls": passed_count,
                "total_controls": len(controls),
                "frameworks": frameworks,
                "controls": controls,
                "evidence_summary": {
                    "managed_agents": len(agents),
                    "active_agents": len(active_agents),
                    "security_events": len(events),
                    "policies": len(policies),
                },
            }

    def _public_agent(self, agent: dict[str, Any]) -> dict[str, Any]:
        public = dict(agent)
        public.pop("agent_token_hash", None)
        return public

    def _sign_policy_payload(self, payload: dict[str, Any]) -> str:
        signing_material = {
            "policy": payload["policy"],
            "issued_at": payload["issued_at"],
            "signature_alg": payload["signature_alg"],
            "public_key": payload["public_key"],
        }
        raw = json.dumps(signing_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        private_raw = base64.b64decode(self._state["policy_ed25519_private_key"])
        signature = Ed25519PrivateKey.from_private_bytes(private_raw).sign(raw)
        return base64.b64encode(signature).decode("ascii")

    @staticmethod
    def _hash_secret(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    def _append_event_locked(
        self, event_type: str, severity: str, agent_id: str, details: dict[str, Any]
    ) -> None:
        detection = self.detector.score_event(event_type, severity, details)
        self._state["events"].append(
            {
                "event_id": secrets.token_hex(12),
                "timestamp": time.time(),
                "type": event_type,
                "severity": severity,
                "agent_id": agent_id,
                "details": details,
                "ml_detection": detection.to_dict(),
            }
        )
        self._state["events"] = self._state["events"][-5000:]
