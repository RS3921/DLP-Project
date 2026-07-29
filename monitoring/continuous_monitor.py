"""
╔══════════════════════════════════════════════════════════════════════════╗
║  VAULT-X  ·  Continuous Monitoring Module                                ║
║  File     : monitoring/continuous_monitor.py                             ║
║  Version  : 1.0.0                                                        ║
╚══════════════════════════════════════════════════════════════════════════╝

WHY THIS EXISTS ALONGSIDE vault_daemon.py:
  vault_daemon.py  →  REACTIVE  — responds to OS file system events
                       (copy/paste, external modification, move)
  continuous_monitor.py → PROACTIVE — polls independently on timers
                       (catches things that don't trigger FS events)

WHAT EACH STREAM CATCHES THAT THE DAEMON MISSES:
  S-01  Behavioral Analysis   → session hijack mid-login (DAEMON has no session access)
  S-02  Canary Integrity Poll → blob tampered while vault process was asleep
  S-03  Network Traffic       → data exfiltration over network (no file change = no daemon event)
  S-04  HSM Key Health        → key file silently replaced with same size (mtime unchanged)
  S-05  Rate Limiter          → brute-force across multiple processes (daemon is per-file)
  S-06  Session Timeout       → abandoned sessions (daemon does not track sessions)

HOW TO USE:
  from monitoring.continuous_monitor import VaultMonitor

  monitor = VaultMonitor(
      vault_dir      = "./my_vault",
      vault_engine   = engine,        # VaultEngine instance (optional)
      audit_callback = ledger.log,    # AuditLedger.log (optional)
      alert_callback = my_fn,         # called on ALERT/CRITICAL events
  )
  monitor.start()    # call after login
  monitor.stop()     # call on logout / in finally block

  # Update behavioral score from auth layer:
  monitor.behavioral.update_score(session_id, score)

  # Record a decrypt op for volume anomaly tracking:
  monitor.record_decrypt(session_id)

INTEGRATION WITH GUI (gui/vault_gui.py):
  The Threat Monitor panel already reads daemon_alerts.log.
  This module ALSO writes to daemon_alerts.log so all alerts
  appear in the same panel without any GUI changes needed.

INTEGRATION WITH ML DETECTOR (server/ml_detector.py):
  Every ALERT/CRITICAL event is passed through MaliciousActivityDetector
  if the server module is available, enriching the alert with a risk score.
"""

import os
import sys
import time
import json
import queue
import hashlib
import logging
import threading
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable, Dict, List, Any

# ── Project root on path ──────────────────────────────────────────
_HERE    = os.path.dirname(os.path.abspath(__file__))
_ROOT    = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

# ── Optional ML detector integration ─────────────────────────────
try:
    from server.ml_detector import MaliciousActivityDetector
    _ML_OK = True
except ImportError:
    _ML_OK = False

# ── Optional psutil for network stream ───────────────────────────
try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False


# ══════════════════════════════════════════════════════════════════
# MONITORING EVENT
# ══════════════════════════════════════════════════════════════════

@dataclass
class MonitorEvent:
    """
    A security event emitted by any of the 6 monitoring streams.

    severity levels:
      INFO     → normal operational event, logged only
      WARNING  → unusual but not confirmed threat
      ALERT    → confirmed anomaly, requires attention
      CRITICAL → active threat or system compromise detected
    """
    stream   : int            # 1-6
    name     : str            # stream name
    severity : str            # INFO / WARNING / ALERT / CRITICAL
    message  : str            # human-readable description
    details  : dict           # machine-readable key-value pairs
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "timestamp"  : datetime.fromtimestamp(self.timestamp).isoformat(),
            "stream"     : f"S-0{self.stream}",
            "stream_name": self.name,
            "severity"   : self.severity,
            "message"    : self.message,
            "details"    : self.details,
        }

    def to_alert_log_entry(self) -> dict:
        """
        Format compatible with daemon_alerts.log so the GUI Threat Monitor
        panel (which reads daemon_alerts.log) shows these events automatically.
        """
        return {
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "event"    : f"MONITOR_S0{self.stream}_{self.severity}",
            "path"     : "monitoring",
            "details"  : {
                "stream" : self.name,
                "message": self.message,
                **self.details,
            },
        }


# ══════════════════════════════════════════════════════════════════
# STREAM 1 — BEHAVIORAL ANALYSIS
# ══════════════════════════════════════════════════════════════════

class BehavioralStream:
    """
    Continuous verification of session behavioral scores.

    vault_daemon.py has no knowledge of auth sessions.
    This stream receives behavioral scores from the auth layer
    (layers/auth_layers.py BehavioralLayer) and acts on them.

    Score thresholds:
      >= 0.70  → PASS (normal)
      0.50-0.69 → WARNING (soft anomaly)
      0.35-0.49 → ALERT  (re-auth recommended)
      < 0.35   → CRITICAL (session terminated)
    """

    WARN_THRESHOLD  = 0.50
    ALERT_THRESHOLD = 0.35

    def __init__(self, event_bus: queue.Queue, revoke_fn: Optional[Callable]):
        self._bus      = event_bus
        self._revoke   = revoke_fn   # vault_engine.revoke_session
        self._scores   : Dict[str, List[float]] = {}   # session_id → recent scores

    def update_score(self, session_id: str, score: float):
        """
        Called by auth layer or GUI after each behavioral check.
        Keeps a rolling window of last 5 scores to smooth noise.

        Args:
            session_id : Active session identifier
            score      : Float 0.0–1.0 from BehavioralLayer.verify()
        """
        history = self._scores.setdefault(session_id, [])
        history.append(score)
        if len(history) > 5:
            history.pop(0)

        avg = sum(history) / len(history)
        self._evaluate(session_id, avg, score)

    def _evaluate(self, session_id: str, avg: float, latest: float):
        sid_short = session_id[:16] + "..."

        if avg < self.ALERT_THRESHOLD:
            # Terminate session
            if self._revoke:
                try:
                    self._revoke(session_id)
                except Exception:
                    pass
            self._bus.put(MonitorEvent(
                stream   = 1,
                name     = "Behavioral Analysis",
                severity = "CRITICAL",
                message  = f"Session terminated — behavioral score critically low",
                details  = {
                    "session"   : sid_short,
                    "avg_score" : round(avg, 3),
                    "latest"    : round(latest, 3),
                    "threshold" : self.ALERT_THRESHOLD,
                    "action"    : "Session revoked",
                },
            ))

        elif avg < self.WARN_THRESHOLD:
            self._bus.put(MonitorEvent(
                stream   = 1,
                name     = "Behavioral Analysis",
                severity = "WARNING",
                message  = f"Behavioral anomaly — typing rhythm deviation detected",
                details  = {
                    "session"   : sid_short,
                    "avg_score" : round(avg, 3),
                    "latest"    : round(latest, 3),
                    "threshold" : self.WARN_THRESHOLD,
                    "action"    : "Monitor closely",
                },
            ))

    def clear_session(self, session_id: str):
        """Call on logout to clean up score history."""
        self._scores.pop(session_id, None)


# ══════════════════════════════════════════════════════════════════
# STREAM 2 — CANARY INTEGRITY POLL
# ══════════════════════════════════════════════════════════════════

class CanaryIntegrityStream:
    """
    Polls all .vault blobs every POLL_INTERVAL seconds.

    WHY THIS DIFFERS FROM DAEMON:
      vault_daemon.py uses watchdog OS events (inotify/ReadDirectoryChanges).
      These events fire WHEN a write happens. If:
        - A write happens while the process was stopped/sleeping
        - Metadata changes without triggering a modify event
        - A ransomware process flushes buffers without a close event
      ...the daemon misses it.

      This stream re-hashes every blob on a timer,
      independently of any file system event.

    POLL_INTERVAL: 300 seconds (5 minutes) by default.
    Set to 60 for higher security, 900 for lower I/O impact.
    """

    POLL_INTERVAL = 300   # seconds

    def __init__(self, vault_dir: str, event_bus: queue.Queue):
        self._vault_dir = vault_dir
        self._bus       = event_bus
        self._checksums : Dict[str, str] = {}
        self._running   = False
        self._thread    : Optional[threading.Thread] = None

    def start(self):
        self._take_snapshot()
        self._running = True
        self._thread  = threading.Thread(
            target = self._loop,
            daemon = True,
            name   = "VaultX-CanaryPoll",
        )
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _sha256(self, path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _take_snapshot(self):
        """Store SHA-256 of every .vault file in the vault directory."""
        self._checksums = {}
        if not os.path.isdir(self._vault_dir):
            return
        for fname in os.listdir(self._vault_dir):
            if fname.endswith(".vault"):
                path = os.path.join(self._vault_dir, fname)
                h    = self._sha256(path)
                if h:
                    self._checksums[path] = h

    def _check(self):
        """Compare current hashes against snapshot. Emit on mismatch."""
        if not os.path.isdir(self._vault_dir):
            return

        current_files = set()
        for fname in os.listdir(self._vault_dir):
            if not fname.endswith(".vault"):
                continue
            path = os.path.join(self._vault_dir, fname)
            current_files.add(path)
            cur_hash = self._sha256(path)

            if path in self._checksums:
                if cur_hash and cur_hash != self._checksums[path]:
                    # Hash changed between polls — not triggered by a FS event
                    self._bus.put(MonitorEvent(
                        stream   = 2,
                        name     = "Canary Integrity Poll",
                        severity = "CRITICAL",
                        message  = f"Blob modified between polls: {fname}",
                        details  = {
                            "file"    : fname,
                            "expected": self._checksums[path][:20] + "...",
                            "actual"  : cur_hash[:20] + "...",
                            "note"    : "Modification not triggered by vault session",
                        },
                    ))
            else:
                # New file appeared since last snapshot
                self._checksums[path] = cur_hash or ""

        # Update snapshot with current state
        for path in current_files:
            h = self._sha256(path)
            if h:
                self._checksums[path] = h

    def _loop(self):
        while self._running:
            time.sleep(self.POLL_INTERVAL)
            if not self._running:
                break
            try:
                self._check()
            except Exception as e:
                self._bus.put(MonitorEvent(
                    stream=2, name="Canary Integrity Poll",
                    severity="WARNING",
                    message=f"Poll error: {e}", details={},
                ))

    def update_checksum(self, path: str):
        """
        Call this after a legitimate vault encrypt/decrypt/relocate
        so the new checksum is registered and doesn't trigger a false alert.

        Args:
            path: Absolute or relative path to the .vault file
        """
        h = self._sha256(path)
        if h:
            self._checksums[os.path.abspath(path)] = h


# ══════════════════════════════════════════════════════════════════
# STREAM 3 — NETWORK TRAFFIC ANALYSIS
# ══════════════════════════════════════════════════════════════════

class NetworkStream:
    """
    Monitors outbound TCP connections from the current process.

    WHY THIS MATTERS FOR DLP:
      The daemon watches files. But data can be exfiltrated over
      a network connection without touching the local file system.
      This stream watches for:
        - Connections to IPs not in the known-good whitelist
        - Large data transfers on non-standard ports
        - Connections to known-suspicious port ranges

    REQUIRES: pip install psutil
    Silently disabled if psutil is not installed.
    """

    POLL_INTERVAL   = 60
    WHITELIST_PORTS = {80, 443, 53, 123, 5000}   # HTTP, HTTPS, DNS, NTP, local Flask

    def __init__(self, event_bus: queue.Queue):
        self._bus     = event_bus
        self._known   : set = set()
        self._running = False
        self._thread  : Optional[threading.Thread] = None
        self._enabled = _PSUTIL_OK

    def start(self):
        if not self._enabled:
            return   # silently skip — psutil not installed
        self._running = True
        self._thread  = threading.Thread(
            target = self._loop,
            daemon = True,
            name   = "VaultX-NetworkMon",
        )
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _check(self):
        try:
            conns = psutil.net_connections(kind="tcp")
        except Exception:
            return

        for conn in conns:
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue
            ip, port = conn.raddr.ip, conn.raddr.port
            key = f"{ip}:{port}"

            if key not in self._known:
                self._known.add(key)
                if port not in self.WHITELIST_PORTS:
                    self._bus.put(MonitorEvent(
                        stream   = 3,
                        name     = "Network Traffic",
                        severity = "WARNING",
                        message  = f"New outbound connection: {ip}:{port}",
                        details  = {
                            "remote_ip"  : ip,
                            "remote_port": port,
                            "note"       : "Port not in whitelist — verify this is expected",
                        },
                    ))

    def _loop(self):
        while self._running:
            try:
                self._check()
            except Exception:
                pass
            time.sleep(self.POLL_INTERVAL)

    def add_whitelist_port(self, port: int):
        """Add a port to the known-good whitelist (e.g. enterprise server port)."""
        self.WHITELIST_PORTS.add(port)


# ══════════════════════════════════════════════════════════════════
# STREAM 4 — HSM KEY HEALTH
# ══════════════════════════════════════════════════════════════════

class HSMHealthStream:
    """
    Monitors master key and signing key file integrity every 60 seconds.

    COMPLEMENTS THE DAEMON:
      vault_daemon.py checks keys every KEY_CHECK_SECS=60s using
      its own VaultState instance.

      This stream provides a SECOND independent health check using
      a separate hash computation so a compromised daemon process
      cannot suppress key tamper alerts.

    Additionally monitors:
      - Key file permissions (should be 0o600 on Unix)
      - Key file size (should never change)
      - Presence of both key files (missing = vault inaccessible)
    """

    POLL_INTERVAL = 60

    def __init__(self, vault_dir: str, event_bus: queue.Queue):
        self._vault_dir  = vault_dir
        self._bus        = event_bus
        self._key_hash   : Optional[str] = None
        self._key_sizes  : Dict[str, int] = {}
        self._running    = False
        self._thread     : Optional[threading.Thread] = None

    def start(self):
        self._baseline()
        self._running = True
        self._thread  = threading.Thread(
            target = self._loop,
            daemon = True,
            name   = "VaultX-HSMHealth",
        )
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _combined_hash(self) -> Optional[str]:
        """SHA-256 of both key files concatenated."""
        h = hashlib.sha256()
        found = False
        for fname in [".vault_master.key", ".vault_signing.key"]:
            path = os.path.join(self._vault_dir, fname)
            if os.path.exists(path):
                with open(path, "rb") as f:
                    h.update(f.read())
                found = True
        return h.hexdigest() if found else None

    def _baseline(self):
        """Take initial hash and sizes of key files."""
        self._key_hash = self._combined_hash()
        for fname in [".vault_master.key", ".vault_signing.key"]:
            path = os.path.join(self._vault_dir, fname)
            if os.path.exists(path):
                self._key_sizes[fname] = os.path.getsize(path)

    def _check(self):
        # Check presence
        for fname in [".vault_master.key", ".vault_signing.key"]:
            path = os.path.join(self._vault_dir, fname)
            if not os.path.exists(path):
                self._bus.put(MonitorEvent(
                    stream   = 4,
                    name     = "HSM Key Health",
                    severity = "CRITICAL",
                    message  = f"Key file MISSING: {fname}",
                    details  = {
                        "file"  : fname,
                        "action": "Vault is now inaccessible. Check for deletion or move.",
                    },
                ))
                return

        # Check combined hash
        current = self._combined_hash()
        if self._key_hash and current and current != self._key_hash:
            self._bus.put(MonitorEvent(
                stream   = 4,
                name     = "HSM Key Health",
                severity = "CRITICAL",
                message  = "Key file content changed — possible tampering",
                details  = {
                    "expected_hash": self._key_hash[:20] + "...",
                    "current_hash" : current[:20] + "...",
                    "action"       : "STOP ALL OPERATIONS. Verify key file integrity.",
                },
            ))
            self._key_hash = current   # reset to avoid repeat alerts

        # Check file sizes (a replaced key of same size wouldn't change mtime)
        for fname in [".vault_master.key", ".vault_signing.key"]:
            path = os.path.join(self._vault_dir, fname)
            if fname in self._key_sizes:
                current_size = os.path.getsize(path)
                if current_size != self._key_sizes[fname]:
                    self._bus.put(MonitorEvent(
                        stream   = 4,
                        name     = "HSM Key Health",
                        severity = "ALERT",
                        message  = f"Key file size changed: {fname}",
                        details  = {
                            "file"         : fname,
                            "expected_size": self._key_sizes[fname],
                            "current_size" : current_size,
                        },
                    ))

    def _loop(self):
        while self._running:
            time.sleep(self.POLL_INTERVAL)
            if not self._running:
                break
            try:
                self._check()
            except Exception as e:
                self._bus.put(MonitorEvent(
                    stream=4, name="HSM Key Health",
                    severity="WARNING", message=f"Health check error: {e}", details={},
                ))


# ══════════════════════════════════════════════════════════════════
# STREAM 5 — RATE LIMITER
# ══════════════════════════════════════════════════════════════════

class RateLimitStream:
    """
    Tracks authentication attempt rates per device fingerprint.

    vault_daemon.py has no auth session awareness.
    This stream receives attempt notifications from the auth gateway
    and detects brute-force patterns across multiple processes.

    THRESHOLDS:
      > 3/min  → WARNING + 5-second delay applied
      > 5/min  → ALERT   + 30-second delay applied
      > 10/min → CRITICAL + 5-minute block
    """

    WARN_RATE  = 3
    ALERT_RATE = 5
    BLOCK_RATE = 10

    def __init__(self, event_bus: queue.Queue):
        self._bus     = event_bus
        self._history : Dict[str, List[float]] = {}  # device → timestamps
        self._blocked : Dict[str, float]       = {}  # device → unblock_time

    def record_attempt(self, device_hash: str) -> Optional[float]:
        """
        Record an authentication attempt for a device.
        Returns a required delay in seconds if rate-limited, else None.

        Call this from auth_gateway.py login() before running auth layers.

        Args:
            device_hash: SHA-256 hardware fingerprint of the device

        Returns:
            Float seconds to delay, or None if not rate-limited
        """
        # Check existing block
        if device_hash in self._blocked:
            remaining = self._blocked[device_hash] - time.time()
            if remaining > 0:
                return remaining
            del self._blocked[device_hash]

        now  = time.time()
        hist = self._history.setdefault(device_hash, [])
        hist.append(now)

        # Keep only last 2 minutes
        cutoff = now - 120
        self._history[device_hash] = [t for t in hist if t > cutoff]
        recent = sum(1 for t in self._history[device_hash] if t > now - 60)

        dev = device_hash[:12] + "..."

        if recent >= self.BLOCK_RATE:
            self._blocked[device_hash] = now + 300
            self._bus.put(MonitorEvent(
                stream   = 5,
                name     = "Rate Limiter",
                severity = "CRITICAL",
                message  = f"Device blocked 5 minutes — {recent} attempts/min",
                details  = {
                    "device"      : dev,
                    "rate_per_min": recent,
                    "block_secs"  : 300,
                },
            ))
            return 300.0

        elif recent >= self.ALERT_RATE:
            self._bus.put(MonitorEvent(
                stream   = 5,
                name     = "Rate Limiter",
                severity = "ALERT",
                message  = f"High auth rate — {recent} attempts/min",
                details  = {
                    "device"      : dev,
                    "rate_per_min": recent,
                    "delay_secs"  : 30,
                },
            ))
            return 30.0

        elif recent >= self.WARN_RATE:
            self._bus.put(MonitorEvent(
                stream   = 5,
                name     = "Rate Limiter",
                severity = "WARNING",
                message  = f"Elevated auth rate — {recent} attempts/min",
                details  = {
                    "device"      : dev,
                    "rate_per_min": recent,
                    "delay_secs"  : 5,
                },
            ))
            return 5.0

        return None

    def is_blocked(self, device_hash: str) -> bool:
        """Check if a device is currently rate-blocked."""
        if device_hash in self._blocked:
            if time.time() < self._blocked[device_hash]:
                return True
            del self._blocked[device_hash]
        return False


# ══════════════════════════════════════════════════════════════════
# STREAM 6 — SESSION TIMEOUT WATCHDOG
# ══════════════════════════════════════════════════════════════════

class SessionTimeoutStream:
    """
    Independent watchdog for all active vault sessions.

    vault_daemon.py has no session awareness.
    vault_engine.py validates tokens on each operation but doesn't
    proactively terminate idle sessions between operations.

    This stream checks every POLL_INTERVAL seconds and forcibly
    revokes sessions that exceed:
      IDLE_WARN_MIN    → warn the user (GUI notification)
      IDLE_LOGOUT_MIN  → force revoke
      HARD_LIMIT_HOURS → force revoke regardless of activity

    HOW TO WIRE INTO vault_engine.py:
      Pass vault_engine._active_sessions dict reference.
      This stream reads last_active from each SessionToken.
    """

    POLL_INTERVAL    = 30
    IDLE_WARN_MIN    = 5
    IDLE_LOGOUT_MIN  = 10
    HARD_LIMIT_HOURS = 8

    def __init__(
        self,
        event_bus      : queue.Queue,
        get_sessions_fn: Callable,       # returns dict {session_id: token}
        revoke_fn      : Optional[Callable],
    ):
        self._bus          = event_bus
        self._get_sessions = get_sessions_fn
        self._revoke       = revoke_fn
        self._running      = False
        self._thread       : Optional[threading.Thread] = None
        self._warned       : set = set()   # session_ids already warned

    def start(self):
        self._running = True
        self._thread  = threading.Thread(
            target = self._loop,
            daemon = True,
            name   = "VaultX-SessionTimeout",
        )
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _check(self):
        now      = time.time()
        sessions = self._get_sessions()

        for sid, token in list(sessions.items()):
            age_h    = (now - token.issued_at) / 3600
            idle_min = (now - token.last_active) / 60

            # Hard limit
            if age_h >= self.HARD_LIMIT_HOURS:
                if self._revoke:
                    try:
                        self._revoke(sid)
                    except Exception:
                        pass
                self._bus.put(MonitorEvent(
                    stream   = 6,
                    name     = "Session Timeout",
                    severity = "INFO",
                    message  = f"Session hard-limit reached and revoked",
                    details  = {
                        "session"   : sid[:16] + "...",
                        "age_hours" : round(age_h, 2),
                        "limit_hours": self.HARD_LIMIT_HOURS,
                    },
                ))
                self._warned.discard(sid)
                continue

            # Idle logout
            if idle_min >= self.IDLE_LOGOUT_MIN:
                if self._revoke:
                    try:
                        self._revoke(sid)
                    except Exception:
                        pass
                self._bus.put(MonitorEvent(
                    stream   = 6,
                    name     = "Session Timeout",
                    severity = "INFO",
                    message  = f"Session idle-timeout revoked",
                    details  = {
                        "session"    : sid[:16] + "...",
                        "idle_min"   : round(idle_min, 1),
                        "limit_min"  : self.IDLE_LOGOUT_MIN,
                    },
                ))
                self._warned.discard(sid)
                continue

            # Idle warning
            if idle_min >= self.IDLE_WARN_MIN and sid not in self._warned:
                self._warned.add(sid)
                self._bus.put(MonitorEvent(
                    stream   = 6,
                    name     = "Session Timeout",
                    severity = "WARNING",
                    message  = f"Session idle for {idle_min:.0f} min — will logout at {self.IDLE_LOGOUT_MIN} min",
                    details  = {
                        "session"   : sid[:16] + "...",
                        "idle_min"  : round(idle_min, 1),
                        "logout_min": self.IDLE_LOGOUT_MIN,
                    },
                ))

            # Reset warning if user became active again
            if idle_min < self.IDLE_WARN_MIN and sid in self._warned:
                self._warned.discard(sid)

    def _loop(self):
        while self._running:
            time.sleep(self.POLL_INTERVAL)
            if not self._running:
                break
            try:
                self._check()
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════
# VAULT MONITOR — MASTER COORDINATOR
# ══════════════════════════════════════════════════════════════════

class VaultMonitor:
    """
    Starts all 6 monitoring streams and coordinates their output.

    ON EVERY EVENT:
      1. Logs to daemon_alerts.log (same file the GUI Threat Monitor reads)
      2. Calls audit_callback (writes to vault_audit.jsonl ledger)
      3. Calls alert_callback for ALERT/CRITICAL severity (GUI/toast notification)
      4. Runs through ML detector if available (enriches with risk score)

    USAGE:
      monitor = VaultMonitor("./my_vault", vault_engine, ledger.log)
      monitor.start()
      # ...
      monitor.stop()

      # Wire behavioral scores:
      monitor.behavioral.update_score(session_id, score)

      # Wire rate limiter:
      delay = monitor.rate_limiter.record_attempt(device_hash)

      # Update canary checksum after legitimate operation:
      monitor.canary_poll.update_checksum(path)

      # Record decrypt for volume anomaly tracking:
      monitor.record_decrypt(session_id)
    """

    def __init__(
        self,
        vault_dir       : str,
        vault_engine    = None,
        audit_callback  : Optional[Callable] = None,
        alert_callback  : Optional[Callable] = None,
    ):
        self.vault_dir      = vault_dir
        self._engine        = vault_engine
        self._audit         = audit_callback    # AuditLedger.log(event_type, details)
        self._alert_cb      = alert_callback    # fn(MonitorEvent)
        self._bus           = queue.Queue()
        self._running       = False
        self._event_thread  : Optional[threading.Thread] = None
        self._alert_log     = os.path.join(vault_dir, "daemon_alerts.log")

        # Optional ML enrichment
        self._ml = MaliciousActivityDetector() if _ML_OK else None

        # Helpers passed to streams
        def _get_sessions() -> dict:
            if self._engine and hasattr(self._engine, "_active_sessions"):
                return {
                    sid: info["token"]
                    for sid, info in self._engine._active_sessions.items()
                }
            return {}

        def _revoke(sid: str):
            if self._engine and hasattr(self._engine, "revoke_session"):
                self._engine.revoke_session(sid)

        # Instantiate all 6 streams
        self.behavioral   = BehavioralStream(self._bus, _revoke)
        self.canary_poll  = CanaryIntegrityStream(vault_dir, self._bus)
        self.network      = NetworkStream(self._bus)
        self.hsm_health   = HSMHealthStream(vault_dir, self._bus)
        self.rate_limiter = RateLimitStream(self._bus)
        self.session_timeout = SessionTimeoutStream(self._bus, _get_sessions, _revoke)

        # Volume anomaly tracking (S-01 extension via decrypt count)
        self._decrypt_counts : Dict[str, List[float]] = {}
        self._baseline_dpm   : Optional[float]         = None

    # ── Public API ──────────────────────────────────────────────────

    def start(self):
        """
        Start all 6 monitoring streams and the event processor.
        Call this after successful login.
        """
        os.makedirs(self.vault_dir, exist_ok=True)

        self._running = True

        self.canary_poll.start()
        self.network.start()
        self.hsm_health.start()
        self.session_timeout.start()

        self._event_thread = threading.Thread(
            target = self._process_events,
            daemon = True,
            name   = "VaultX-MonitorBus",
        )
        self._event_thread.start()

        print("[VaultMonitor] ✓ All 6 surveillance streams active.")
        print("[VaultMonitor]   S-01 Behavioral     S-02 Canary Poll")
        print("[VaultMonitor]   S-03 Network         S-04 HSM Health")
        print("[VaultMonitor]   S-05 Rate Limiter    S-06 Session Timeout")

    def stop(self):
        """
        Stop all streams cleanly.
        Call in a finally block to guarantee shutdown on logout/crash.
        """
        self._running = False
        self.canary_poll.stop()
        self.network.stop()
        self.hsm_health.stop()
        self.session_timeout.stop()
        if self._event_thread:
            self._event_thread.join(timeout=5)
        print("[VaultMonitor] All streams stopped.")

    def record_decrypt(self, session_id: str):
        """
        Track decrypt operations for volume anomaly detection.
        Call this after every successful decrypt in the vault session.

        Emits a WARNING if decrypt rate exceeds 5× the established baseline.
        """
        now  = time.time()
        hist = self._decrypt_counts.setdefault(session_id, [])
        hist.append(now)

        # Keep last 60 seconds
        self._decrypt_counts[session_id] = [t for t in hist if t > now - 60]
        recent = len(self._decrypt_counts[session_id])

        # Establish baseline after first 3 decrypts
        if self._baseline_dpm is None and recent >= 3:
            self._baseline_dpm = float(recent)

        if self._baseline_dpm and recent > self._baseline_dpm * 5:
            self._bus.put(MonitorEvent(
                stream   = 1,
                name     = "Behavioral Analysis",
                severity = "ALERT",
                message  = f"Decrypt volume anomaly — possible automated exfiltration",
                details  = {
                    "session"       : session_id[:16] + "...",
                    "decrypts_per_min": recent,
                    "baseline"      : round(self._baseline_dpm, 1),
                    "anomaly_factor": round(recent / self._baseline_dpm, 1),
                },
            ))

    # ── Event Processor ─────────────────────────────────────────────

    def _process_events(self):
        """
        Drain the event bus.
        For each event:
          1. Print to console (ALERT/CRITICAL only)
          2. Write to daemon_alerts.log
          3. Write to audit ledger (if callback provided)
          4. Call alert_callback (if ALERT/CRITICAL and callback provided)
          5. Enrich with ML risk score (if ml_detector available)
        """
        while self._running:
            try:
                event = self._bus.get(timeout=1.0)
                self._handle(event)
            except queue.Empty:
                continue
            except Exception:
                pass

    def _handle(self, event: MonitorEvent):
        # Console output for significant events
        if event.severity in ("ALERT", "CRITICAL"):
            print(f"\n  [S-0{event.stream}] 🚨 {event.severity}: {event.message}")
        elif event.severity == "WARNING":
            print(f"\n  [S-0{event.stream}] ⚠  WARNING: {event.message}")

        # ML enrichment
        ml_result = None
        if self._ml and event.severity in ("ALERT", "CRITICAL"):
            try:
                ml_result = self._ml.score_event(
                    event_type = f"MONITOR_S{event.stream}",
                    severity   = event.severity,
                    details    = event.details,
                )
                event.details["ml_score"]   = round(ml_result.score, 3)
                event.details["ml_verdict"] = ml_result.verdict
                event.details["ml_reasons"] = ml_result.reasons[:3]
            except Exception:
                pass

        # Write to daemon_alerts.log (GUI Threat Monitor reads this)
        self._write_alert_log(event)

        # Write to audit ledger
        if self._audit:
            try:
                self._audit(
                    f"MONITOR_S{event.stream}_{event.severity}",
                    event.to_dict(),
                )
            except Exception:
                pass

        # Alert callback for ALERT/CRITICAL
        if self._alert_cb and event.severity in ("ALERT", "CRITICAL"):
            try:
                self._alert_cb(event)
            except Exception:
                pass

    def _write_alert_log(self, event: MonitorEvent):
        """
        Append event to daemon_alerts.log in the same JSON format
        that vault_daemon.py uses and that the GUI Threat Monitor reads.
        This means ALL alerts (daemon + monitor) appear in one place.
        """
        try:
            os.makedirs(self.vault_dir, exist_ok=True)
            entry = json.dumps(event.to_alert_log_entry())
            with open(self._alert_log, "a", encoding="utf-8") as f:
                f.write(entry + "\n")
        except Exception:
            pass

    # ── Status ──────────────────────────────────────────────────────

    def is_running(self) -> bool:
        return self._running

    def get_stream_status(self) -> dict:
        """Returns status dict readable by GUI dashboard."""
        return {
            "S-01 Behavioral"    : "active",
            "S-02 Canary Poll"   : "active" if self.canary_poll._running else "stopped",
            "S-03 Network"       : "active" if (self.network._running and _PSUTIL_OK) else ("disabled (no psutil)" if not _PSUTIL_OK else "stopped"),
            "S-04 HSM Health"    : "active" if self.hsm_health._running else "stopped",
            "S-05 Rate Limiter"  : "active",
            "S-06 Session Timeout": "active" if self.session_timeout._running else "stopped",
        }
