"""Persistent enterprise state for the VAULT-X admin server."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Any

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


class EnterpriseStore:
    """Small JSON-backed store for admin console state."""

    def __init__(self, path: Path):
        """Load or initialize the JSON-backed enterprise control-plane state."""
        self.path = path
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.detector = MaliciousActivityDetector()
        self._state = self._load()
        self._ensure_state_shape()

    def _load(self) -> dict[str, Any]:
        """Read persisted state or create a new secure default structure."""
        if self.path.exists():
            try:
                return json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {
            "created_at": time.time(),
            "enrollment_token": secrets.token_urlsafe(32),
            "policy_signing_key": secrets.token_urlsafe(48),
            "agents": {},
            "events": [],
            "policies": {"default": DEFAULT_POLICY.copy()},
        }

    def _ensure_state_shape(self) -> None:
        """Migrate older state files to the current schema in place."""
        changed = False
        if "policy_signing_key" not in self._state:
            self._state["policy_signing_key"] = secrets.token_urlsafe(48)
            changed = True
        if "policies" not in self._state:
            self._state["policies"] = {"default": DEFAULT_POLICY.copy()}
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
        """Atomically persist state by replacing it with a completed temp file."""
        with self._lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._state, indent=2), encoding="utf-8")
            tmp.replace(self.path)

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
                "signature_alg": "HMAC-SHA256",
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

    def _public_agent(self, agent: dict[str, Any]) -> dict[str, Any]:
        public = dict(agent)
        public.pop("agent_token_hash", None)
        return public

    def _sign_policy_payload(self, payload: dict[str, Any]) -> str:
        signing_material = {
            "policy": payload["policy"],
            "issued_at": payload["issued_at"],
            "signature_alg": payload["signature_alg"],
        }
        raw = json.dumps(signing_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        key = self._state["policy_signing_key"].encode("utf-8")
        return hmac.new(key, raw, hashlib.sha256).hexdigest()

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
