"""VAULT-X managed endpoint agent.

This is the laptop-side process for enterprise deployments. It is intentionally
small for now: enroll, heartbeat, receive policy, and report events.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from agent.activity_monitor import ActivityEvent, EndpointActivityMonitor

DEFAULT_STATE = Path.home() / ".vaultx_agent.json"


class AgentClient:
    """Client used by a managed endpoint to communicate with the admin server."""

    def __init__(self, server: str, api_key: str, state_path: Path):
        """Configure server access and load locally persisted agent credentials."""
        self.server = server.rstrip("/")
        self.api_key = api_key
        self.state_path = state_path
        self.state = self._load_state()

    def _load_state(self) -> dict[str, Any]:
        """Read enrolled identity and policy state from disk when available."""
        if self.state_path.exists():
            try:
                return json.loads(self.state_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def save(self) -> None:
        """Persist agent identity, token, and cached policy to the state file."""
        self.state_path.write_text(json.dumps(self.state, indent=2), encoding="utf-8")

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        auth: str = "agent",
    ) -> dict[str, Any]:
        """Send one JSON request using admin, agent, or unauthenticated mode."""
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if auth == "admin":
            headers["Authorization"] = f"Bearer {self.api_key}"
        elif auth == "agent":
            agent_id = self.state.get("agent_id", "")
            agent_token = self.state.get("agent_token", "")
            headers["X-Agent-Id"] = agent_id
            headers["X-Agent-Token"] = agent_token
        req = urllib.request.Request(
            self.server + path,
            data=body,
            method=method,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as res:
                return json.loads(res.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc

    def enroll(
        self, enrollment_token: str, assigned_user: str = "", department: str = ""
    ) -> dict[str, Any]:
        """Exchange a bootstrap token for a unique agent identity and policy."""
        payload = {
            "enrollment_token": enrollment_token,
            "agent_id": self.state.get("agent_id"),
            "hostname": socket.gethostname(),
            "assigned_user": assigned_user or getpass.getuser(),
            "department": department or "unassigned",
            "os": f"{platform.system()} {platform.release()}",
            "agent_version": "0.1.0",
            "heartbeat": self._heartbeat_payload(),
        }
        data = self.request("POST", "/v1/agents/register", payload, auth="none")
        agent = data["agent"]
        self.state["agent_id"] = agent["agent_id"]
        self.state["agent_token"] = agent["agent_token"]
        self.state["policy_id"] = agent.get("policy_id", "default")
        self.state["signed_policy"] = agent.get("policy")
        self.save()
        return agent

    def heartbeat(self) -> dict[str, Any]:
        """Report liveness and cache the latest signed policy response."""
        agent_id = self.state.get("agent_id")
        if not agent_id:
            raise RuntimeError("Agent is not enrolled. Run enroll first.")
        result = self.request(
            "POST", f"/v1/agents/{agent_id}/heartbeat", self._heartbeat_payload(), auth="agent"
        )
        if result.get("policy"):
            self.state["signed_policy"] = result["policy"]
            self.save()
        return result

    def fetch_policy(self) -> dict[str, Any]:
        """Fetch and cache the endpoint's currently assigned policy envelope."""
        result = self.request("GET", "/v1/agent/policy", auth="agent")
        if result.get("policy"):
            self.state["signed_policy"] = result["policy"]
            self.save()
        return result

    def report_event(
        self, event_type: str, severity: str, details: dict[str, Any]
    ) -> dict[str, Any]:
        """Submit endpoint telemetry for server-side normalization and ML scoring."""
        agent_id = self.state.get("agent_id", "")
        return self.request(
            "POST",
            "/v1/events",
            {
                "agent_id": agent_id,
                "type": event_type,
                "severity": severity,
                "details": details,
            },
            auth="agent",
        )

    def run_monitor(self, roots: list[str], once: bool = False) -> None:
        """Run one scan or continuously monitor configured filesystem roots."""

        def emit(event: ActivityEvent) -> None:
            try:
                result = self.report_event(event.event_type, event.severity, event.details)
                detection = result.get("event", {}).get("ml_detection", {})
                print(
                    json.dumps(
                        {
                            "sent": event.event_type,
                            "severity": result.get("event", {}).get("severity"),
                            "ml": detection.get("verdict"),
                            "score": detection.get("score"),
                        }
                    )
                )
            except Exception as exc:
                print(json.dumps({"send_failed": event.event_type, "error": str(exc)}))

        monitor = EndpointActivityMonitor(
            emit=emit,
            roots=[Path(root) for root in roots],
            poll_seconds=20,
        )
        if once:
            monitor.scan_once()
        else:
            monitor.run_forever()

    def _heartbeat_payload(self) -> dict[str, Any]:
        """Build the platform and network metadata included with a heartbeat."""
        return {
            "status": "online",
            "hostname": socket.gethostname(),
            "ip_address": self._local_ip(),
            "time": time.time(),
            "platform": platform.platform(),
        }

    @staticmethod
    def _local_ip() -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                return sock.getsockname()[0]
        except Exception:
            return "127.0.0.1"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="VAULT-X endpoint agent")
    parser.add_argument(
        "command", choices=["enroll", "heartbeat", "policy", "event", "monitor", "scan-once"]
    )
    parser.add_argument("--server", default=os.getenv("VAULTX_SERVER", "http://127.0.0.1:8765"))
    parser.add_argument("--api-key", default=os.getenv("VAULTX_API_KEY", ""))
    parser.add_argument("--state", default=os.getenv("VAULTX_AGENT_STATE", str(DEFAULT_STATE)))
    parser.add_argument("--enrollment-token", default=os.getenv("VAULTX_ENROLLMENT_TOKEN", ""))
    parser.add_argument("--user", default="")
    parser.add_argument("--department", default="")
    parser.add_argument("--event-type", default="dlp_test_event")
    parser.add_argument("--severity", default="info")
    parser.add_argument("--details", default="{}")
    parser.add_argument(
        "--watch-root",
        action="append",
        default=[],
        help="Directory to watch. Can be passed multiple times.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    client = AgentClient(args.server, args.api_key, Path(args.state))

    if args.command == "enroll":
        if not args.enrollment_token:
            raise SystemExit("VAULTX_ENROLLMENT_TOKEN or --enrollment-token is required.")
        result = client.enroll(args.enrollment_token, args.user, args.department)
    elif args.command == "heartbeat":
        result = client.heartbeat()
    elif args.command == "policy":
        result = client.fetch_policy()
    elif args.command == "event":
        try:
            details = json.loads(args.details)
        except json.JSONDecodeError:
            details = {"message": args.details}
        result = client.report_event(args.event_type, args.severity, details)
    else:
        roots = args.watch_root or [str(Path.home() / "Desktop"), str(Path.home() / "Documents")]
        client.run_monitor(roots, once=args.command == "scan-once")
        return 0

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
