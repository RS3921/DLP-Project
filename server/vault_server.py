"""
VAULT-X HTTP service.

This module exposes a small JSON API around the existing vault engine.
It intentionally uses Python's standard library so the service can run on
minimal server installations without adding a web framework dependency.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import json
import logging
import os
import secrets
import sys
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from core.auth_gateway import AuthGateway
from core.vault_engine import SessionToken, VaultBlob
from server.enterprise_store import EnterpriseStore
from server.ml_detector import MaliciousActivityDetector

LOG = logging.getLogger("vaultx.server")


class JsonFormatter(logging.Formatter):
    """Emit compact structured logs for service deployments."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"))


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        handlers=[handler],
        force=True,
    )


class VaultService:
    """Thin service layer that keeps HTTP concerns outside the vault core."""

    def __init__(self, vault_dir: Path, data_root: Path, api_key: str):
        self.vault_dir = vault_dir.resolve()
        self.data_root = data_root.resolve()
        self.api_key = api_key
        self.gateway = AuthGateway(str(self.vault_dir))
        self.enterprise = EnterpriseStore(self.vault_dir / "enterprise_state.json")
        self.detector = MaliciousActivityDetector()
        self._request_count = 0
        self._started_at = time.time()

    @property
    def setup_complete(self) -> bool:
        return bool(self.gateway.config.get("setup_complete"))

    def require_setup(self) -> None:
        if not self.setup_complete:
            raise ServiceError(
                HTTPStatus.CONFLICT,
                "setup_required",
                "Vault setup is not complete. Run `python vaultx.py setup` first.",
            )

    def check_api_key(self, candidate: str | None) -> bool:
        if not candidate:
            return False
        return secrets.compare_digest(candidate, self.api_key)

    def authenticate_agent_headers(
        self, agent_id: str | None, agent_token: str | None
    ) -> dict[str, Any]:
        try:
            return self.enterprise.authenticate_agent(agent_id or "", agent_token)
        except KeyError as exc:
            raise ServiceError(
                HTTPStatus.UNAUTHORIZED, "agent_unknown", "Agent is not enrolled."
            ) from exc
        except PermissionError as exc:
            raise ServiceError(HTTPStatus.UNAUTHORIZED, "agent_unauthorized", str(exc)) from exc

    def issue_session(self, scope: list[str] | None = None) -> dict[str, Any]:
        self.require_setup()
        owner_hash = self.gateway.config.get("owner_hash")
        if not owner_hash:
            raise ServiceError(
                HTTPStatus.CONFLICT,
                "owner_missing",
                "Vault owner hash is missing from configuration.",
            )
        token = self.gateway.vault.create_session_token(owner_hash, scope=scope)
        self.gateway._audit(
            "SERVER_SESSION_CREATED",
            {"session": token.session_id[:16], "scope": token.scope},
        )
        return {
            "session_id": token.session_id,
            "expires_at": token.expires_at,
            "scope": token.scope,
        }

    def get_token(self, session_id: str | None) -> SessionToken:
        if not session_id:
            raise ServiceError(
                HTTPStatus.UNAUTHORIZED,
                "session_required",
                "Missing X-Vault-Session header.",
            )
        session = self.gateway.vault._active_sessions.get(session_id)
        if not session:
            raise ServiceError(
                HTTPStatus.UNAUTHORIZED,
                "session_invalid",
                "Session is not active or has already expired.",
            )
        token = session["token"]
        if not self.gateway.vault.validate_session_token(token):
            raise ServiceError(
                HTTPStatus.UNAUTHORIZED,
                "session_invalid",
                "Session token validation failed.",
            )
        return token

    def revoke_session(self, session_id: str | None) -> dict[str, Any]:
        token = self.get_token(session_id)
        self.gateway.vault.revoke_session(token.session_id)
        self.gateway._audit(
            "SERVER_SESSION_REVOKED",
            {"session": token.session_id[:16]},
        )
        return {"revoked": True, "session_id": token.session_id}

    def status(self) -> dict[str, Any]:
        return {
            "service": "vaultx",
            "setup_complete": self.setup_complete,
            "vault_dir": str(self.vault_dir),
            "data_root": str(self.data_root),
            "active_sessions": self.gateway.vault.get_active_session_count(),
            "uptime_seconds": int(time.time() - self._started_at),
            "requests": self._request_count,
            "enterprise": self.enterprise.summary(),
        }

    def audit(self, limit: int = 50) -> dict[str, Any]:
        limit = max(1, min(limit, 500))
        entries = self.gateway.audit_ledger.read_all()[-limit:]
        return {
            "entries": [entry.to_dict() for entry in entries],
            "count": len(entries),
            "chain_valid": self.gateway.audit_ledger.verify_chain(),
        }

    def encrypt_path(
        self,
        session_id: str | None,
        input_path: str,
        output_path: str | None = None,
    ) -> dict[str, Any]:
        token = self.get_token(session_id)
        source = self._safe_path(input_path)
        if not source.exists() or not source.is_file():
            raise ServiceError(HTTPStatus.NOT_FOUND, "file_not_found", str(source))
        target = (
            self._safe_path(output_path)
            if output_path
            else source.with_suffix(source.suffix + ".vault")
        )
        plaintext = source.read_bytes()
        blob = self.gateway.vault.encrypt(plaintext, token)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(dataclasses.asdict(blob), indent=2), encoding="utf-8")
        self.gateway._audit(
            "SERVER_ENCRYPT",
            {
                "input": self._redact_path(source),
                "output": self._redact_path(target),
                "blob": blob.blob_id[:16],
            },
        )
        return {
            "ok": True,
            "input_path": str(source),
            "output_path": str(target),
            "blob_id": blob.blob_id,
            "bytes_in": len(plaintext),
        }

    def decrypt_path(
        self,
        session_id: str | None,
        input_path: str,
        output_path: str | None = None,
    ) -> dict[str, Any]:
        token = self.get_token(session_id)
        source = self._safe_path(input_path)
        if not source.exists() or not source.is_file():
            raise ServiceError(HTTPStatus.NOT_FOUND, "file_not_found", str(source))
        target = self._safe_path(output_path) if output_path else self._default_decrypt_path(source)
        blob = VaultBlob(**json.loads(source.read_text(encoding="utf-8")))
        plaintext = self.gateway.vault.decrypt(blob, token)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(plaintext)
        self.gateway._audit(
            "SERVER_DECRYPT",
            {
                "input": self._redact_path(source),
                "output": self._redact_path(target),
                "blob": blob.blob_id[:16],
            },
        )
        return {
            "ok": True,
            "input_path": str(source),
            "output_path": str(target),
            "blob_id": blob.blob_id,
            "bytes_out": len(plaintext),
        }

    def encrypt_bytes(self, session_id: str | None, data_b64: str) -> dict[str, Any]:
        token = self.get_token(session_id)
        try:
            plaintext = base64.b64decode(data_b64, validate=True)
        except Exception as exc:
            raise ServiceError(
                HTTPStatus.BAD_REQUEST, "invalid_base64", "data_b64 is not valid base64."
            ) from exc
        blob = self.gateway.vault.encrypt(plaintext, token)
        return {"blob": dataclasses.asdict(blob)}

    def decrypt_bytes(self, session_id: str | None, blob_data: dict[str, Any]) -> dict[str, Any]:
        token = self.get_token(session_id)
        blob = VaultBlob(**blob_data)
        plaintext = self.gateway.vault.decrypt(blob, token)
        return {"data_b64": base64.b64encode(plaintext).decode("ascii")}

    def _safe_path(self, value: str | None) -> Path:
        if not value:
            raise ServiceError(HTTPStatus.BAD_REQUEST, "path_required", "A path value is required.")
        path = Path(value)
        if not path.is_absolute():
            path = self.data_root / path
        resolved = path.resolve()
        try:
            resolved.relative_to(self.data_root)
        except ValueError as exc:
            raise ServiceError(
                HTTPStatus.FORBIDDEN,
                "path_forbidden",
                f"Path must stay inside data root: {self.data_root}",
            ) from exc
        return resolved

    def _redact_path(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.data_root))
        except ValueError:
            return path.name

    @staticmethod
    def _default_decrypt_path(source: Path) -> Path:
        if source.name.endswith(".vault"):
            return source.with_name(source.name[:-6] + ".decrypted")
        return source.with_suffix(source.suffix + ".decrypted")


class ServiceError(Exception):
    def __init__(self, status: HTTPStatus, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class VaultRequestHandler(BaseHTTPRequestHandler):
    server_version = "VaultXHTTP/1.0"

    @property
    def service(self) -> VaultService:
        return self.server.service  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.info("%s - %s", self.client_address[0], fmt % args)

    def _dispatch(self, method: str) -> None:
        self.service._request_count += 1
        try:
            if method == "GET" and self.path == "/health":
                self._send_json({"ok": True, "service": "vaultx"})
                return

            if method == "GET" and self.path == "/assets/logo.png":
                self._send_bytes(
                    (PROJECT_ROOT / "app_gui" / "assets" / "logo.png").read_bytes(),
                    "image/png",
                )
                return

            if method == "GET" and self.path == "/assets/theme.css":
                self._send_bytes(
                    (PROJECT_ROOT / "app_gui" / "assets" / "theme.css").read_bytes(),
                    "text/css; charset=utf-8",
                )
                return

            if method == "GET" and self.path == "/login.html":
                self._send_html(
                    (PROJECT_ROOT / "app_gui" / "login.html").read_text(encoding="utf-8")
                )
                return

            if method == "GET" and self.path in {"/", "/index.html"}:
                self._send_html(self._advanced_home_page())
                return

            if method == "POST" and self.path == "/v1/agents/register":
                try:
                    agent = self.service.enterprise.register_agent(self._read_json())
                except ValueError as exc:
                    raise ServiceError(
                        HTTPStatus.UNAUTHORIZED, "invalid_enrollment_token", str(exc)
                    ) from exc
                self._send_json({"agent": agent}, HTTPStatus.CREATED)
                return

            is_agent_route = self._is_agent_route(method, self.path)
            if is_agent_route:
                self._require_agent_auth()
            else:
                self._require_auth()

            if method == "GET" and self.path == "/v1/status":
                self._send_json(self.service.status())
                return

            if method == "GET" and self.path.startswith("/v1/audit"):
                self._send_json(self.service.audit(limit=self._query_limit(default=50)))
                return

            if method == "GET" and self.path == "/v1/enterprise/summary":
                self._send_json(self.service.enterprise.summary())
                return

            if method == "GET" and self.path == "/v1/agents":
                self._send_json({"agents": self.service.enterprise.list_agents()})
                return

            if method == "GET" and self.path.startswith("/v1/events"):
                self._send_json(
                    {
                        "events": self.service.enterprise.list_events(
                            limit=self._query_limit(default=100)
                        )
                    }
                )
                return

            if method == "GET" and self.path == "/v1/policies":
                self._send_json({"policies": self.service.enterprise.list_policies()})
                return

            if method == "GET" and self.path == "/v1/compliance":
                self._send_json(self.service.enterprise.compliance_report())
                return

            if method == "GET" and self.path == "/v1/agent/policy":
                agent_id = self.headers.get("X-Agent-Id")
                agent = self.service.enterprise.authenticate_agent(
                    agent_id or "", self.headers.get("X-Agent-Token")
                )
                self._send_json(
                    {
                        "policy": self.service.enterprise.signed_policy(
                            agent.get("policy_id", "default")
                        )
                    }
                )
                return

            if method == "POST" and self.path == "/v1/policies/default":
                self._send_json(self.service.enterprise.update_policy("default", self._read_json()))
                return

            if method == "POST" and self.path == "/v1/enrollment-token/rotate":
                token = self.service.enterprise.rotate_enrollment_token()
                self._send_json({"enrollment_token": token})
                return

            if (
                method == "POST"
                and self.path.startswith("/v1/agents/")
                and self.path.endswith("/revoke")
            ):
                agent_id = self.path.split("/")[3]
                self._send_json({"agent": self.service.enterprise.revoke_agent(agent_id, True)})
                return

            if (
                method == "POST"
                and self.path.startswith("/v1/agents/")
                and self.path.endswith("/restore")
            ):
                agent_id = self.path.split("/")[3]
                self._send_json({"agent": self.service.enterprise.revoke_agent(agent_id, False)})
                return

            if (
                method == "POST"
                and self.path.startswith("/v1/agents/")
                and self.path.endswith("/rotate-token")
            ):
                agent_id = self.path.split("/")[3]
                self._send_json(self.service.enterprise.rotate_agent_token(agent_id))
                return

            if (
                method == "POST"
                and self.path.startswith("/v1/agents/")
                and self.path.endswith("/heartbeat")
            ):
                agent_id = self.path.split("/")[3]
                self._send_json(self.service.enterprise.heartbeat(agent_id, self._read_json()))
                return

            if method == "POST" and self.path == "/v1/events":
                payload = self._read_json()
                if is_agent_route:
                    payload["agent_id"] = self.headers.get("X-Agent-Id", "")
                self._send_json(
                    {"event": self.service.enterprise.record_event(payload)}, HTTPStatus.CREATED
                )
                return

            if method == "POST" and self.path == "/v1/detect":
                payload = self._read_json()
                result = self.service.detector.score_event(
                    payload.get("type", "manual_check"),
                    payload.get("severity", "info"),
                    payload.get("details", {}),
                )
                self._send_json({"detection": result.to_dict()})
                return

            if method == "POST" and self.path == "/v1/session":
                payload = self._read_json()
                scope = payload.get("scope")
                self._send_json(self.service.issue_session(scope=scope), HTTPStatus.CREATED)
                return

            if method == "POST" and self.path == "/v1/session/revoke":
                self._send_json(self.service.revoke_session(self.headers.get("X-Vault-Session")))
                return

            if method == "POST" and self.path == "/v1/encrypt-file":
                payload = self._read_json()
                self._send_json(
                    self.service.encrypt_path(
                        self.headers.get("X-Vault-Session"),
                        payload.get("input_path"),
                        payload.get("output_path"),
                    )
                )
                return

            if method == "POST" and self.path == "/v1/decrypt-file":
                payload = self._read_json()
                self._send_json(
                    self.service.decrypt_path(
                        self.headers.get("X-Vault-Session"),
                        payload.get("input_path"),
                        payload.get("output_path"),
                    )
                )
                return

            if method == "POST" and self.path == "/v1/encrypt":
                payload = self._read_json()
                self._send_json(
                    self.service.encrypt_bytes(
                        self.headers.get("X-Vault-Session"),
                        payload.get("data_b64", ""),
                    )
                )
                return

            if method == "POST" and self.path == "/v1/decrypt":
                payload = self._read_json()
                self._send_json(
                    self.service.decrypt_bytes(
                        self.headers.get("X-Vault-Session"),
                        payload.get("blob", {}),
                    )
                )
                return

            raise ServiceError(HTTPStatus.NOT_FOUND, "not_found", "Endpoint not found.")
        except ServiceError as exc:
            self._send_json({"ok": False, "error": exc.code, "message": exc.message}, exc.status)
        except json.JSONDecodeError:
            self._send_json(
                {
                    "ok": False,
                    "error": "invalid_json",
                    "message": "Request body is not valid JSON.",
                },
                HTTPStatus.BAD_REQUEST,
            )
        except Exception as exc:
            LOG.exception("Unhandled request error")
            self._send_json(
                {"ok": False, "error": "server_error", "message": str(exc)},
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    def _require_auth(self) -> None:
        auth = self.headers.get("Authorization", "")
        prefix = "Bearer "
        token = auth[len(prefix) :] if auth.startswith(prefix) else None
        if not self.service.check_api_key(token):
            raise ServiceError(
                HTTPStatus.UNAUTHORIZED, "unauthorized", "Valid bearer API key required."
            )

    def _is_agent_route(self, method: str, path: str) -> bool:
        if method == "GET" and path == "/v1/agent/policy":
            return True
        if method == "POST" and path.startswith("/v1/agents/") and path.endswith("/heartbeat"):
            return True
        if method == "POST" and path == "/v1/events" and self.headers.get("X-Agent-Token"):
            return True
        return False

    def _require_agent_auth(self) -> None:
        self.service.authenticate_agent_headers(
            self.headers.get("X-Agent-Id"),
            self.headers.get("X-Agent-Token"),
        )

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(
        self,
        body: bytes,
        content_type: str,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _home_page(self) -> str:
        status = self.service.status()
        setup_text = "Ready" if status["setup_complete"] else "Setup Required"
        setup_class = "ok" if status["setup_complete"] else "warn"
        enterprise = status["enterprise"]
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VAULT-X Admin Console</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0b0f14;
      --panel: #121922;
      --panel2: #0f1720;
      --line: #263241;
      --text: #e8edf3;
      --muted: #94a3b8;
      --blue: #60a5fa;
      --green: #34d399;
      --amber: #fbbf24;
      --red: #fb7185;
      --violet: #a78bfa;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    main {{
      max-width: 1220px;
      margin: 0 auto;
      padding: 40px 24px;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: flex-start;
      border-bottom: 1px solid var(--line);
      padding-bottom: 24px;
      margin-bottom: 24px;
    }}
    h1 {{ margin: 0; font-size: 30px; letter-spacing: 0; }}
    h2 {{ margin: 0 0 14px; font-size: 18px; }}
    p {{ color: var(--muted); line-height: 1.6; }}
    .topline {{ color: var(--blue); font-size: 13px; font-weight: 700; margin-bottom: 6px; }}
    .badge {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 10px;
      font-weight: 700;
      white-space: nowrap;
    }}
    .ok {{ color: var(--green); }}
    .warn {{ color: var(--amber); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 12px;
      margin: 24px 0;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
    }}
    .label {{ color: var(--muted); font-size: 13px; margin-bottom: 8px; }}
    .value {{ font-size: 18px; font-weight: 700; overflow-wrap: anywhere; }}
    .layout {{
      display: grid;
      grid-template-columns: 1.35fr .9fr;
      gap: 12px;
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{
      padding: 10px 8px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      font-size: 14px;
      vertical-align: top;
    }}
    th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    input, button {{
      border-radius: 6px;
      border: 1px solid var(--line);
      background: #0a1017;
      color: var(--text);
      padding: 10px 12px;
      font: inherit;
    }}
    button {{
      background: var(--blue);
      border-color: var(--blue);
      color: #06111f;
      font-weight: 800;
      cursor: pointer;
    }}
    .toolbar {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      margin: 12px 0 0;
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 4px 8px;
      color: var(--muted);
      font-size: 12px;
      margin: 2px 4px 2px 0;
    }}
    .sev-high {{ color: var(--red); }}
    .sev-medium {{ color: var(--amber); }}
    .sev-info {{ color: var(--green); }}
    .empty {{ color: var(--muted); padding: 18px 0; }}
    .event {{
      border-bottom: 1px solid var(--line);
      padding: 10px 0;
      margin: 0;
    }}
    .event-title {{
      display: flex;
      justify-content: space-between;
      gap: 8px;
      align-items: center;
      margin-bottom: 4px;
    }}
    .reason {{
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
    }}
    code {{
      display: block;
      background: #080b10;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 12px;
      color: #cbd5e1;
      overflow-x: auto;
    }}
    a {{ color: var(--blue); }}
    @media (max-width: 860px) {{
      header, .layout, .toolbar {{ grid-template-columns: 1fr; display: grid; }}
      header {{ display: grid; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <div class="topline">Enterprise DLP Control Plane</div>
        <h1>VAULT-X Admin Console</h1>
        <p>Central admin surface for managed laptops, DLP policies, vault operations, and endpoint security events.</p>
      </div>
      <div class="badge {setup_class}">{setup_text}</div>
    </header>

    <section class="grid" aria-label="Enterprise status">
      <div class="card">
        <div class="label">Managed Laptops</div>
        <div class="value" id="totalAgents">{enterprise["total_agents"]}</div>
      </div>
      <div class="card">
        <div class="label">Online Agents</div>
        <div class="value" id="onlineAgents">{enterprise["online_agents"]}</div>
      </div>
      <div class="card">
        <div class="label">Revoked Agents</div>
        <div class="value" id="revokedAgents">{enterprise["revoked_agents"]}</div>
      </div>
      <div class="card">
        <div class="label">Security Events</div>
        <div class="value" id="eventCount">{enterprise["event_count"]}</div>
      </div>
      <div class="card">
        <div class="label">Policies</div>
        <div class="value" id="policyCount">{enterprise["policy_count"]}</div>
      </div>
    </section>

    <section class="card">
      <h2>Admin Access</h2>
      <p>Enter the server API key to load managed devices and events. For this local test server, the key is the one used in <code style="display:inline;padding:2px 6px;">VAULTX_API_KEY</code>.</p>
      <div class="toolbar">
        <input id="apiKey" type="password" placeholder="Bearer API key">
        <button id="refreshBtn">Refresh Console</button>
      </div>
      <p id="authState" class="label">No admin API key loaded in this browser.</p>
    </section>

    <section class="layout" style="margin-top: 12px;">
      <div class="card">
        <h2>Managed Laptops</h2>
        <table>
          <thead>
            <tr><th>Device</th><th>User</th><th>Department</th><th>Status</th><th>Trust</th><th>Policy</th></tr>
          </thead>
          <tbody id="agentsBody">
            <tr><td colspan="5" class="empty">Enter the admin API key and refresh.</td></tr>
          </tbody>
        </table>
      </div>
      <div class="card">
        <h2>Recent Security Events</h2>
        <div id="eventsBody" class="empty">Enter the admin API key and refresh.</div>
      </div>
    </section>

    <section class="layout" style="margin-top: 12px;">
      <div class="card">
        <h2>Default Policy</h2>
        <pre id="policyView">Admin refresh required.</pre>
      </div>
      <div class="card">
        <h2>AI/ML Detection</h2>
        <p>Every endpoint event is scored by the VAULT-X risk model. Verdicts are stored with reasons so admins can review why an activity was flagged.</p>
        <code>POST /v1/agents/register
POST /v1/agents/:id/heartbeat
POST /v1/events
POST /v1/detect</code>
      </div>
    </section>
  </main>
  <script>
    const keyInput = document.getElementById("apiKey");
    const saved = localStorage.getItem("vaultx_admin_key");
    if (saved) {{
      keyInput.value = saved;
      document.getElementById("authState").textContent = "Admin API key loaded from this browser.";
    }}

    async function api(path) {{
      const key = keyInput.value.trim();
      if (!key) throw new Error("API key required");
      localStorage.setItem("vaultx_admin_key", key);
      const res = await fetch(path, {{ headers: {{ Authorization: "Bearer " + key }} }});
      if (!res.ok) throw new Error(await res.text());
      return await res.json();
    }}

    function fmtTime(ts) {{
      if (!ts) return "never";
      return new Date(ts * 1000).toLocaleString();
    }}

    async function refreshConsole() {{
      const state = document.getElementById("authState");
      try {{
        state.textContent = "Loading admin data...";
        const [summary, agents, events, policies] = await Promise.all([
          api("/v1/enterprise/summary"),
          api("/v1/agents"),
          api("/v1/events?limit=20"),
          api("/v1/policies")
        ]);

        document.getElementById("totalAgents").textContent = summary.total_agents;
        document.getElementById("onlineAgents").textContent = summary.online_agents;
        document.getElementById("revokedAgents").textContent = summary.revoked_agents;
        document.getElementById("eventCount").textContent = summary.event_count;
        document.getElementById("policyCount").textContent = summary.policy_count;

        const rows = agents.agents.map(agent => `
          <tr>
            <td><strong>${{agent.hostname}}</strong><br><span class="label">${{agent.os}}</span></td>
            <td>${{agent.assigned_user}}</td>
            <td>${{agent.department}}</td>
            <td><span class="pill">${{agent.revoked ? "revoked" : (agent.online ? "online" : "offline")}}</span><br><span class="label">${{fmtTime(agent.last_seen)}}</span></td>
            <td><span class="label">token</span><br>${{agent.token_preview || "n/a"}}</td>
            <td>${{agent.policy_id}}</td>
          </tr>`).join("");
        document.getElementById("agentsBody").innerHTML = rows || `<tr><td colspan="6" class="empty">No laptops enrolled yet.</td></tr>`;

        document.getElementById("eventsBody").innerHTML = events.events.map(event => `
          <div class="event">
            <div class="event-title">
              <strong class="sev-${{event.severity}}">${{event.type}}</strong>
              <span class="pill">${{event.severity}}</span>
            </div>
            <span class="label">${{fmtTime(event.timestamp)}} · ${{event.agent_id || "server"}}</span><br>
            <span class="pill">ML: ${{event.ml_detection?.verdict || "n/a"}} ${{event.ml_detection ? Math.round(event.ml_detection.score * 100) + "%" : ""}}</span>
            <div class="reason">${{(event.ml_detection?.reasons || []).slice(0, 3).join(" · ")}}</div>
          </div>
        `).join("") || `<div class="empty">No events yet.</div>`;

        document.getElementById("policyView").textContent = JSON.stringify(policies.policies[0] || {{}}, null, 2);
        state.textContent = "Admin data refreshed.";
      }} catch (err) {{
        state.textContent = "Could not load admin data. Check the API key.";
      }}
    }}

    document.getElementById("refreshBtn").addEventListener("click", refreshConsole);
    if (saved) refreshConsole();
  </script>
</body>
</html>"""

    def _advanced_home_page(self) -> str:
        ui_path = PROJECT_ROOT / "server" / "admin_console.html"
        return ui_path.read_text(encoding="utf-8")

    def _query_limit(self, default: int) -> int:
        if "?" not in self.path:
            return default
        query = self.path.split("?", 1)[1]
        for part in query.split("&"):
            key, _, value = part.partition("=")
            if key == "limit":
                try:
                    return int(value)
                except ValueError:
                    return default
        return default


class VaultHTTPServer(ThreadingHTTPServer):
    def __init__(
        self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], service: VaultService
    ):
        super().__init__(address, handler)
        self.service = service


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the VAULT-X HTTP service.")
    parser.add_argument("--host", default=os.getenv("VAULTX_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("VAULTX_PORT", "8765")))
    parser.add_argument(
        "--vault-dir", default=os.getenv("VAULTX_VAULT_DIR", str(PROJECT_ROOT / "my_vault"))
    )
    parser.add_argument("--data-root", default=os.getenv("VAULTX_DATA_ROOT", str(PROJECT_ROOT)))
    parser.add_argument("--log-level", default=os.getenv("VAULTX_LOG_LEVEL", "INFO"))
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.log_level)

    api_key = os.getenv("VAULTX_API_KEY")
    if not api_key:
        parser.error("VAULTX_API_KEY must be set before starting the server.")

    service = VaultService(Path(args.vault_dir), Path(args.data_root), api_key)
    server = VaultHTTPServer((args.host, args.port), VaultRequestHandler, service)

    LOG.info(
        "starting vaultx server host=%s port=%s vault_dir=%s data_root=%s",
        args.host,
        args.port,
        args.vault_dir,
        args.data_root,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("shutdown requested")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
