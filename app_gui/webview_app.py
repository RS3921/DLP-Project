"""Run VAULT-X with its manual five-layer login and enterprise dashboard."""

from __future__ import annotations

import importlib
import base64
import io
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_DIR = PROJECT_ROOT / "app_gui"
VAULT_DIR = PROJECT_ROOT / "my_vault"
LOGIN_HTML = APP_DIR / "login.html"
HOST = "127.0.0.1"
PORT = 8765

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")


def _ensure_dependencies(include_webview: bool = True) -> None:
    required = ["cryptography", "qrcode"]
    if include_webview:
        required.append("webview")
    missing = []
    for module_name in required:
        try:
            importlib.import_module(module_name)
        except ImportError:
            missing.append(module_name)
    if missing:
        print("Installing VAULT-X application dependencies (first launch only)...")
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "-r",
                str(PROJECT_ROOT / "requirements.txt"),
            ]
        )


def _load_webview() -> Any:
    _ensure_dependencies(include_webview=True)
    return importlib.import_module("webview")


def _server_components():
    from server.vault_server import VaultHTTPServer, VaultRequestHandler, VaultService

    return VaultHTTPServer, VaultRequestHandler, VaultService


def _build_server(api_key: str, port: int = PORT) -> Any:
    VaultHTTPServer, VaultRequestHandler, VaultService = _server_components()
    data_root = Path(os.getenv("VAULTX_DATA_ROOT", str(PROJECT_ROOT)))
    service = VaultService(VAULT_DIR, data_root, api_key)
    return VaultHTTPServer((HOST, port), VaultRequestHandler, service)


def _start_server(server: Any) -> threading.Thread:
    thread = threading.Thread(
        target=server.serve_forever,
        name="vaultx-local-server",
        daemon=True,
    )
    thread.start()
    return thread


class Api:
    """Native bridge used by the exact manual-login UI."""

    def __init__(self, dashboard_key: str):
        self._dashboard_key = dashboard_key
        self._gateway = None
        self._window = None
        self._token = None
        self._vault_index = VAULT_DIR / "file_vault_index.json"
        self._vault_lock = threading.RLock()

    def _get_gateway(self):
        if self._gateway is None:
            from core.auth_gateway import AuthGateway

            self._gateway = AuthGateway(vault_dir=str(VAULT_DIR))
        return self._gateway

    def get_status(self):
        gateway = self._get_gateway()
        return {"setup_complete": bool(gateway.config.get("setup_complete"))}

    def verify_setup_totp(self, code: str):
        try:
            passed = self._get_gateway().totp.verify(str(code).strip())
            return {
                "ok": passed,
                "message": "Authenticator confirmed." if passed else "The TOTP code is incorrect or expired.",
            }
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    def setup(
        self, passphrase: str, recovery_key: str = "", behavioral_timings=None,
        geofence_location=None, geofence_radius_meters: float = 500.0,
    ):
        try:
            result = self._get_gateway().setup_with_credentials(
                passphrase, recovery_key, behavioral_timings or [],
                geofence_location, geofence_radius_meters
            )
            if result.get("ok") and result.get("totp_uri"):
                import qrcode

                image = qrcode.make(result["totp_uri"])
                buffer = io.BytesIO()
                image.save(buffer, format="PNG")
                result["totp_qr_data_url"] = (
                    "data:image/png;base64,"
                    + base64.b64encode(buffer.getvalue()).decode("ascii")
                )
            return result
        except Exception as exc:
            return {"ok": False, "message": f"Setup failed: {exc}"}

    def login(
        self, totp_code: str, passphrase: str, behavioral_timings=None,
        layer_d_key: str = "", current_location=None,
    ):
        try:
            result = self._get_gateway().login_with_credentials(
                totp_code, passphrase, behavioral_timings or [],
                layer_d_key, current_location
            )
        except RuntimeError:
            return {
                "ok": False,
                "failed": ["A", "B"],
                "layers": {},
                "locked": False,
                "error": "Vault not set up yet — click SETUP (FIRST TIME).",
            }
        except Exception as exc:
            return {
                "ok": False,
                "failed": [],
                "layers": {},
                "locked": False,
                "error": str(exc),
            }

        if result.get("locked_until"):
            return {"ok": False, "failed": [], "layers": {}, "locked": True}
        if result.get("ok") and result.get("token") is not None:
            self._token = result["token"]
        layers = result["layers"]
        return {
            "ok": result["ok"],
            "failed": [key for key, passed in layers.items() if not passed],
            "layers": layers,
            "locked": False,
        }

    def go_dashboard(self):
        key = urllib.parse.quote(self._dashboard_key, safe="")
        return f"http://{HOST}:{PORT}/#desktop_key={key}"

    def _require_vault_session(self):
        gateway = self._get_gateway()
        if self._token is None or not gateway.vault.validate_session_token(self._token):
            raise PermissionError("Your authenticated vault session has expired. Log in again.")
        return gateway

    @staticmethod
    def _dialog_path(selection) -> Path | None:
        if not selection:
            return None
        if isinstance(selection, (list, tuple)):
            selection = selection[0] if selection else None
        return Path(selection).resolve() if selection else None

    def _choose_open_file(self, vault_only: bool = False) -> Path | None:
        if not self._window:
            return None
        webview = _load_webview()
        file_types = ("VAULT-X files (*.vault)",) if vault_only else ("All files (*.*)",)
        selection = self._window.create_file_dialog(
            webview.FileDialog.OPEN,
            allow_multiple=False,
            file_types=file_types,
        )
        return self._dialog_path(selection)

    def _choose_save_file(self, source: Path, suggested_name: str) -> Path | None:
        if not self._window:
            return None
        webview = _load_webview()
        selection = self._window.create_file_dialog(
            webview.FileDialog.SAVE,
            directory=str(source.parent),
            save_filename=suggested_name,
        )
        return self._dialog_path(selection)

    def _read_vault_index(self) -> list[dict]:
        with self._vault_lock:
            if not self._vault_index.exists():
                return []
            try:
                data = json.loads(self._vault_index.read_text(encoding="utf-8"))
                return data if isinstance(data, list) else []
            except (OSError, ValueError):
                return []

    def _write_vault_index(self, entries: list[dict]) -> None:
        with self._vault_lock:
            self._vault_index.parent.mkdir(parents=True, exist_ok=True)
            temp = self._vault_index.with_suffix(".tmp")
            temp.write_text(json.dumps(entries[-500:], indent=2), encoding="utf-8")
            os.replace(temp, self._vault_index)

    def _record_vault_file(self, record: dict) -> None:
        entries = self._read_vault_index()
        entries.insert(0, record)
        self._write_vault_index(entries)

    def list_file_vault(self):
        try:
            self._require_vault_session()
            entries = self._read_vault_index()
            for entry in entries:
                entry["exists"] = Path(entry.get("path", "")).is_file()
            return {"ok": True, "files": entries[:100]}
        except Exception as exc:
            return {"ok": False, "message": str(exc), "files": []}

    def encrypt_file(self):
        """Select and encrypt one file into a durable .vault package."""
        try:
            gateway = self._require_vault_session()
            source = self._choose_open_file()
            if source is None:
                return {"ok": False, "cancelled": True, "message": "No file selected."}
            if not source.is_file():
                raise FileNotFoundError("The selected file does not exist.")
            if source.suffix.lower() == ".vault":
                raise ValueError("Select a normal file. Use Decrypt for .vault files.")
            size = source.stat().st_size
            if size > 256 * 1024 * 1024:
                raise ValueError("Files larger than 256 MB are not supported in this edition.")
            target = self._choose_save_file(source, source.name + ".vault")
            if target is None:
                return {"ok": False, "cancelled": True, "message": "Save cancelled."}
            if target.suffix.lower() != ".vault":
                target = target.with_name(target.name + ".vault")
            package = gateway.vault.encrypt_file_payload(
                source.read_bytes(), source.name, self._token
            )
            temp = target.with_name(target.name + "." + secrets.token_hex(4) + ".tmp")
            try:
                temp.write_text(json.dumps(package, separators=(",", ":")), encoding="utf-8")
                os.replace(temp, target)
            finally:
                temp.unlink(missing_ok=True)
            gateway._audit(
                "FILE_VAULT_ENCRYPT",
                {"source": source.name, "output": target.name, "bytes": size},
            )
            self._record_vault_file(
                {
                    "name": source.name,
                    "path": str(target),
                    "bytes": size,
                    "encrypted_at": package["created_at"],
                    "status": "protected",
                }
            )
            return {
                "ok": True,
                "message": f"Encrypted {source.name}",
                "output_path": str(target),
                "bytes": size,
            }
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    def decrypt_file(self):
        """Select, authenticate, and restore one .vault package."""
        try:
            gateway = self._require_vault_session()
            source = self._choose_open_file(vault_only=True)
            if source is None:
                return {"ok": False, "cancelled": True, "message": "No vault file selected."}
            if not source.is_file():
                raise FileNotFoundError("The selected vault file does not exist.")
            package = json.loads(source.read_text(encoding="utf-8"))
            plaintext, original_name = gateway.vault.decrypt_file_payload(
                package, self._token
            )
            target = self._choose_save_file(source, original_name)
            if target is None:
                return {"ok": False, "cancelled": True, "message": "Restore cancelled."}
            temp = target.with_name(target.name + "." + secrets.token_hex(4) + ".tmp")
            try:
                temp.write_bytes(plaintext)
                os.replace(temp, target)
            finally:
                temp.unlink(missing_ok=True)
            gateway._audit(
                "FILE_VAULT_DECRYPT",
                {"source": source.name, "output": target.name, "bytes": len(plaintext)},
            )
            self._record_vault_file(
                {
                    "name": original_name,
                    "path": str(source),
                    "bytes": len(plaintext),
                    "encrypted_at": float(package["created_at"]),
                    "last_restored_at": time.time(),
                    "status": "restored",
                }
            )
            return {
                "ok": True,
                "message": f"Restored {original_name}",
                "output_path": str(target),
                "bytes": len(plaintext),
            }
        except Exception as exc:
            return {"ok": False, "message": str(exc)}


def _self_check() -> int:
    _ensure_dependencies(include_webview=False)
    dashboard_key = secrets.token_urlsafe(32)
    server = _build_server(dashboard_key, port=0)
    thread = _start_server(server)
    port = server.server_address[1]
    try:
        with urllib.request.urlopen(f"http://{HOST}:{port}/health", timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if payload.get("ok") is not True:
            raise RuntimeError("VAULT-X health check returned an unexpected response")
        gateway = Api(dashboard_key)._get_gateway()
        if not hasattr(gateway, "login_with_credentials"):
            raise RuntimeError("Manual login API is unavailable")
        if not LOGIN_HTML.exists():
            raise RuntimeError("Manual login UI is unavailable")
        print("VAULT-X manual-login desktop self-check: OK")
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main() -> int:
    if "--check" in sys.argv:
        return _self_check()

    webview = _load_webview()
    dashboard_key = secrets.token_urlsafe(32)
    server = _build_server(dashboard_key)
    thread = _start_server(server)
    api = Api(dashboard_key)
    try:
        window = webview.create_window(
            "VAULT-X · Personal Data Vault",
            url=f"http://{HOST}:{PORT}/login.html",
            js_api=api,
            width=1180,
            height=760,
            min_size=(1000, 680),
            background_color="#0A0000",
            text_select=True,
        )
        api._window = window
        webview.start()
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
