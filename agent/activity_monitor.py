"""Endpoint activity monitoring for managed Windows laptops.

The monitor observes normal user activity and reports metadata events to the
VAULT-X admin server. It does not present a user UI. It is designed to run as a
background service in an organization-managed endpoint deployment.
"""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    WATCHDOG_AVAILABLE = True
except Exception:
    FileSystemEventHandler = object
    Observer = None
    WATCHDOG_AVAILABLE = False


SENSITIVE_NAMES = {
    "password",
    "secret",
    "credential",
    "token",
    "api_key",
    "salary",
    "finance",
    "customer",
    "confidential",
}

SENSITIVE_EXTENSIONS = {
    ".env",
    ".key",
    ".pem",
    ".pfx",
    ".p12",
    ".kdbx",
    ".xlsx",
    ".docx",
    ".pdf",
    ".db",
    ".sqlite",
}

SCRIPT_EXTENSIONS = {
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".hta",
    ".exe",
    ".dll",
}

SUSPICIOUS_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}


@dataclass
class ActivityEvent:
    event_type: str
    severity: str
    details: dict


class EndpointActivityMonitor:
    """Collects local endpoint activity and emits DLP events."""

    def __init__(
        self,
        emit: Callable[[ActivityEvent], None],
        roots: Iterable[Path],
        poll_seconds: int = 20,
    ):
        self.emit = emit
        self.roots = [Path(root).expanduser().resolve() for root in roots]
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._observer = None
        self._seen_processes: set[str] = set()
        self._known_files: dict[str, tuple[int, float]] = {}

    def run_forever(self) -> None:
        self.emit(
            ActivityEvent(
                "agent_monitor_started",
                "info",
                {
                    "roots": [str(root) for root in self.roots],
                    "watchdog": WATCHDOG_AVAILABLE,
                    "platform": platform.platform(),
                },
            )
        )
        if WATCHDOG_AVAILABLE:
            self._start_watchdog()
        else:
            self._snapshot_files()

        while not self._stop.is_set():
            self.scan_once()
            self._stop.wait(self.poll_seconds)

    def stop(self) -> None:
        self._stop.set()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)

    def scan_once(self) -> None:
        self._scan_processes()
        if not WATCHDOG_AVAILABLE:
            self._poll_files()

    def _start_watchdog(self) -> None:
        handler = _WatchdogHandler(self)
        self._observer = Observer()
        for root in self.roots:
            root.mkdir(parents=True, exist_ok=True)
            self._observer.schedule(handler, str(root), recursive=True)
        self._observer.start()

    def handle_file_activity(self, action: str, path: str) -> None:
        file_path = Path(path)
        if not file_path.name:
            return
        details = self._file_details(file_path)
        details["action"] = action

        event_type = "file_activity"
        severity = "info"

        lower_name = file_path.name.lower()
        ext = file_path.suffix.lower()
        if ext in SENSITIVE_EXTENSIONS or any(term in lower_name for term in SENSITIVE_NAMES):
            event_type = "sensitive_file_activity"
            severity = "medium"
        if ext in SCRIPT_EXTENSIONS:
            event_type = "script_or_binary_activity"
            severity = "medium"

        self.emit(ActivityEvent(event_type, severity, details))

    def _file_details(self, path: Path) -> dict:
        try:
            stat = path.stat()
            size = stat.st_size
            modified = stat.st_mtime
        except Exception:
            size = 0
            modified = time.time()
        return {
            "path": str(path),
            "file_name": path.name,
            "extension": path.suffix.lower(),
            "size_bytes": size,
            "modified_at": modified,
            "path_hash": hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:16],
        }

    def _snapshot_files(self) -> None:
        self._known_files = {}
        for path in self._iter_files():
            try:
                stat = path.stat()
                self._known_files[str(path)] = (stat.st_size, stat.st_mtime)
            except Exception:
                continue

    def _poll_files(self) -> None:
        current = {}
        for path in self._iter_files():
            try:
                stat = path.stat()
                current[str(path)] = (stat.st_size, stat.st_mtime)
            except Exception:
                continue

        previous_paths = set(self._known_files)
        current_paths = set(current)
        for created in current_paths - previous_paths:
            self.handle_file_activity("created", created)
        for deleted in previous_paths - current_paths:
            self.emit(
                ActivityEvent(
                    "file_deleted",
                    "info",
                    {"path_hash": hashlib.sha256(deleted.encode()).hexdigest()[:16]},
                )
            )
        for existing in current_paths & previous_paths:
            if current[existing] != self._known_files[existing]:
                self.handle_file_activity("modified", existing)
        self._known_files = current

    def _iter_files(self):
        for root in self.roots:
            if not root.exists():
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [
                    d for d in dirnames if d not in {".git", "__pycache__", "node_modules"}
                ]
                for name in filenames:
                    yield Path(dirpath) / name

    def _scan_processes(self) -> None:
        if platform.system().lower() != "windows":
            return
        try:
            result = subprocess.run(
                ["tasklist", "/fo", "csv", "/nh"],
                capture_output=True,
                text=True,
                timeout=8,
            )
        except Exception:
            return
        if result.returncode != 0:
            return

        for line in result.stdout.splitlines():
            parts = [part.strip('"') for part in line.split('","')]
            if not parts:
                continue
            process = parts[0].lower()
            if process not in SUSPICIOUS_PROCESSES or process in self._seen_processes:
                continue
            self._seen_processes.add(process)
            self.emit(
                ActivityEvent(
                    "suspicious_process_observed",
                    "medium",
                    {
                        "process": process,
                        "rule": "known command or script interpreter",
                    },
                )
            )


class _WatchdogHandler(FileSystemEventHandler):
    def __init__(self, monitor: EndpointActivityMonitor):
        self.monitor = monitor

    def on_created(self, event):
        if not event.is_directory:
            self.monitor.handle_file_activity("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.monitor.handle_file_activity("modified", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.monitor.handle_file_activity("moved", event.dest_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.monitor.handle_file_activity("deleted", event.src_path)
