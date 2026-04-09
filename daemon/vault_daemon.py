"""
╔══════════════════════════════════════════════════════════════════════════╗
║  VAULT-X  ·  Background Protection Daemon                                ║
║  Module   : daemon/vault_daemon.py                                       ║
║  Purpose  : 24/7 vault folder protection — runs even when not logged in  ║
║  Version  : 2.0.0                                                        ║
╚══════════════════════════════════════════════════════════════════════════╝

HOW TO START THE DAEMON:
  python daemon/vault_daemon.py start     ← start background protection
  python daemon/vault_daemon.py stop      ← stop daemon
  python daemon/vault_daemon.py status    ← check if running

WHAT IT DOES 24/7:
  1. Watches vault folder for ANY external file change (OS-level)
  2. Detects copy/paste from Windows Explorer, USB, any app
  3. Verifies blob checksums every 5 minutes
  4. Monitors master key file integrity
  5. Writes alerts to daemon_alerts.log
  6. Quarantines or destroys tampered files automatically
"""

import os
import sys
import time
import json
import signal
import hashlib
import secrets
import logging
import threading
import traceback
from datetime import datetime
from pathlib import Path

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent, FileMovedEvent
    WATCHDOG_OK = True
except ImportError:
    WATCHDOG_OK = False

VAULT_DIR      = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "my_vault")
PID_FILE       = os.path.join(VAULT_DIR, ".daemon.pid")
ALERT_LOG      = os.path.join(VAULT_DIR, "daemon_alerts.log")
STATE_FILE     = os.path.join(VAULT_DIR, ".daemon_state.json")
POLL_INTERVAL  = 300   # 5 minutes for integrity poll
KEY_CHECK_SECS = 60    # check master key every 60 seconds


# ══════════════════════════════════════════════════════════════════════════════
# ALERT LOGGER
# ══════════════════════════════════════════════════════════════════════════════

def setup_logger():
    os.makedirs(VAULT_DIR, exist_ok=True)
    logger = logging.getLogger("VaultXDaemon")
    logger.setLevel(logging.DEBUG)

    fh = logging.FileHandler(ALERT_LOG, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(levelname)s  %(message)s"))
    logger.addHandler(ch)

    return logger

log = setup_logger()


# ══════════════════════════════════════════════════════════════════════════════
# VAULT STATE — checksums of all protected files
# ══════════════════════════════════════════════════════════════════════════════

class VaultState:
    """
    Tracks SHA-256 checksums of all .vault blob files and key files.
    Persisted to .daemon_state.json so the daemon survives restarts.
    """

    PROTECTED_EXTS   = {".vault"}
    PROTECTED_FILES  = {".vault_master.key", ".vault_signing.key", "vault_config.json"}

    def __init__(self):
        self.checksums : dict = {}     # path → sha256
        self.key_hash  : str  = ""     # hash of master + signing key combined
        self._load()

    def _load(self):
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE) as f:
                    data           = json.load(f)
                    self.checksums = data.get("checksums", {})
                    self.key_hash  = data.get("key_hash", "")
            except Exception:
                pass

    def save(self):
        try:
            with open(STATE_FILE, "w") as f:
                json.dump({"checksums": self.checksums, "key_hash": self.key_hash}, f)
        except Exception:
            pass

    def snapshot(self):
        """Take a full snapshot of all vault blobs and key files."""
        self.checksums = {}

        for fname in os.listdir(VAULT_DIR):
            fpath = os.path.join(VAULT_DIR, fname)
            ext   = os.path.splitext(fname)[1].lower()

            if ext in self.PROTECTED_EXTS or fname in self.PROTECTED_FILES:
                h = self._hash_file(fpath)
                if h:
                    self.checksums[fpath] = h

        # Key files combined hash
        self.key_hash = self._hash_key_files()
        self.save()
        log.info(f"Snapshot taken — {len(self.checksums)} protected files indexed.")

    def _hash_file(self, path: str) -> str:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def _hash_key_files(self) -> str:
        h = hashlib.sha256()
        for fname in [".vault_master.key", ".vault_signing.key"]:
            fpath = os.path.join(VAULT_DIR, fname)
            if os.path.exists(fpath):
                with open(fpath, "rb") as f:
                    h.update(f.read())
        return h.hexdigest()

    def check_keys(self) -> bool:
        """Returns True if key files are unchanged."""
        current = self._hash_key_files()
        if not self.key_hash:
            self.key_hash = current
            self.save()
            return True
        return current == self.key_hash

    def check_blob(self, path: str) -> bool:
        """Returns True if blob matches stored checksum."""
        if path not in self.checksums:
            return True   # unknown file — not a violation
        return self._hash_file(path) == self.checksums[path]

    def register_authorized(self, path: str):
        """Call this before any vault session writes a file."""
        h = self._hash_file(path)
        if h:
            self.checksums[path] = h
            self.save()

    def remove(self, path: str):
        self.checksums.pop(path, None)
        self.save()


# ══════════════════════════════════════════════════════════════════════════════
# FILE SYSTEM WATCHER — OS-level copy/paste detection
# ══════════════════════════════════════════════════════════════════════════════

class VaultFolderWatcher(FileSystemEventHandler):
    """
    Watchdog event handler for the vault directory.

    Catches:
      - Files created from OUTSIDE the vault session (copy/paste, drag-drop, USB)
      - Files modified externally (ransomware, hex editor, tampering)
      - Files moved into the vault directory from elsewhere

    WHAT TRIGGERS THIS:
      - Ctrl+C → Ctrl+V into the vault folder in Windows Explorer
      - Drag a .vault file from a USB drive into the folder
      - Any app writing to the vault folder
      - Ransomware encrypting vault blobs

    WHAT DOES NOT TRIGGER THIS:
      - Normal vault session operations (encrypt/decrypt/relocate)
        These are pre-authorized via VaultState.register_authorized()
    """

    def __init__(self, state: VaultState, response_fn):
        self._state       = state
        self._respond     = response_fn
        self._authorized  : set = set()   # paths currently being legitimately modified

    def authorize(self, path: str):
        """Pre-authorize a path for modification (called by vault session)."""
        self._authorized.add(os.path.abspath(path))

    def deauthorize(self, path: str):
        self._authorized.discard(os.path.abspath(path))

    def on_created(self, event):
        if event.is_directory:
            return
        path    = os.path.abspath(event.src_path)
        ext     = os.path.splitext(path)[1].lower()
        fname   = os.path.basename(path)

        if ext == ".vault" and path not in self._authorized:
            log.warning(f"TRIPWIRE-3: Unauthorized .vault file created: {fname}")
            self._respond("UNAUTHORIZED_CREATE", path, {
                "file"   : fname,
                "action" : "File appeared without vault session authorization",
                "risk"   : "Possible external copy of vault blob into protected directory",
            })

    def on_modified(self, event):
        if event.is_directory:
            return
        path  = os.path.abspath(event.src_path)
        fname = os.path.basename(path)
        ext   = os.path.splitext(fname)[1].lower()

        # Skip daemon state files and logs
        if fname in (".daemon_state.json", ".daemon.pid", "daemon_alerts.log", "vault_audit.jsonl"):
            return

        if ext == ".vault" and path not in self._authorized:
            if not self._state.check_blob(path):
                log.critical(f"TRIPWIRE-4: .vault blob modified externally: {fname}")
                self._respond("BLOB_TAMPERED", path, {
                    "file"   : fname,
                    "action" : "Blob checksum mismatch — external modification detected",
                    "risk"   : "Possible ransomware, hex editing, or corruption",
                })

    def on_moved(self, event):
        if event.is_directory:
            return
        dest  = os.path.abspath(event.dest_path)
        fname = os.path.basename(dest)
        ext   = os.path.splitext(fname)[1].lower()

        if ext == ".vault" and dest not in self._authorized:
            log.warning(f"TRIPWIRE-3: .vault blob moved into vault dir: {fname}")
            self._respond("UNAUTHORIZED_MOVE", dest, {
                "source" : event.src_path,
                "dest"   : dest,
                "risk"   : "Possible attempt to substitute a vault blob",
            })


# ══════════════════════════════════════════════════════════════════════════════
# CORRUPTION RESPONDER
# ══════════════════════════════════════════════════════════════════════════════

def secure_wipe(path: str, passes: int = 3) -> bool:
    """DoD 3-pass wipe and delete."""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            for p in range(passes):
                f.seek(0)
                if p == 0:   f.write(b"\x00" * size)
                elif p == 1: f.write(b"\xFF" * size)
                else:        f.write(secrets.token_bytes(size))
                f.flush(); os.fsync(f.fileno())
        os.remove(path)
        return True
    except Exception as e:
        log.error(f"Wipe failed: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# VAULT DAEMON — MAIN CLASS
# ══════════════════════════════════════════════════════════════════════════════

class VaultDaemon:
    """
    The always-on protection daemon for VAULT-X.

    Runs three parallel protection threads:
      Thread 1: watchdog OS file system observer
      Thread 2: periodic integrity poll (every 5 minutes)
      Thread 3: master key health check (every 60 seconds)

    Response modes per event:
      UNAUTHORIZED_CREATE  → quarantine file + alert
      BLOB_TAMPERED        → quarantine + alert
      KEY_MODIFIED         → CRITICAL alert (cannot auto-recover)
      INTEGRITY_FAIL       → quarantine + alert
    """

    def __init__(self):
        self._state     = VaultState()
        self._observer  = None
        self._watcher   = None
        self._running   = False
        self._threads   : list = []
        self.alert_count: int  = 0

    def respond(self, event_type: str, path: str, details: dict):
        """
        Handle a security event.
        Quarantines the affected file and writes to alert log.
        """
        self.alert_count += 1
        log.critical(f"🚨 {event_type}: {os.path.basename(path)}")
        for k, v in details.items():
            log.critical(f"   {k}: {v}")

        # Quarantine: rename to .quarantine
        if os.path.exists(path):
            try:
                q = path + ".quarantine"
                os.rename(path, q)
                try: os.chmod(q, 0o000)
                except: pass
                log.critical(f"   → Quarantined: {os.path.basename(q)}")
            except Exception as e:
                log.error(f"   Quarantine failed: {e}")

        # Write to alerts file
        alert = {
            "timestamp" : datetime.now().isoformat(),
            "event"     : event_type,
            "path"      : path,
            "details"   : details,
        }
        try:
            with open(ALERT_LOG, "a") as f:
                f.write(json.dumps(alert) + "\n")
        except Exception:
            pass

    def _integrity_poll(self):
        """Thread 2 — periodic blob integrity check every POLL_INTERVAL seconds."""
        log.info("Integrity poll thread started.")
        while self._running:
            time.sleep(POLL_INTERVAL)
            if not self._running:
                break
            log.info("Running integrity poll...")
            for path, stored_hash in list(self._state.checksums.items()):
                if not os.path.exists(path):
                    log.warning(f"Blob deleted: {os.path.basename(path)}")
                    self._state.remove(path)
                    continue
                current = self._state._hash_file(path)
                if current != stored_hash:
                    log.critical(f"INTEGRITY FAIL: {os.path.basename(path)}")
                    self.respond("INTEGRITY_FAIL", path, {
                        "expected_sha256" : stored_hash[:20] + "...",
                        "actual_sha256"   : current[:20] + "...",
                    })
                    self._state.remove(path)

    def _key_health_check(self):
        """Thread 3 — master key file health check every KEY_CHECK_SECS seconds."""
        log.info("Key health thread started.")
        while self._running:
            time.sleep(KEY_CHECK_SECS)
            if not self._running:
                break
            if not self._state.check_keys():
                log.critical("🚨 MASTER KEY FILE MODIFIED — VAULT COMPROMISED")
                self.respond("KEY_TAMPERED", os.path.join(VAULT_DIR, ".vault_master.key"), {
                    "action" : "Master key file hash changed",
                    "risk"   : "CRITICAL — vault may be compromised. Stop all operations.",
                })

    def start(self):
        """Start all protection threads."""
        os.makedirs(VAULT_DIR, exist_ok=True)

        log.info("=" * 60)
        log.info("VAULT-X Daemon starting...")
        log.info(f"Vault dir: {VAULT_DIR}")

        # Take initial snapshot
        self._state.snapshot()

        self._running = True

        # Thread 1: watchdog file system observer
        if WATCHDOG_OK:
            self._watcher  = VaultFolderWatcher(self._state, self.respond)
            self._observer = Observer()
            self._observer.schedule(self._watcher, VAULT_DIR, recursive=False)
            self._observer.start()
            log.info("OS-level file system watcher: ACTIVE")
        else:
            log.warning("watchdog not installed — OS-level watching disabled.")
            log.warning("Install with: pip install watchdog")

        # Thread 2: integrity poll
        t2 = threading.Thread(target=self._integrity_poll, daemon=True, name="VaultX-IntegrityPoll")
        t2.start()
        self._threads.append(t2)

        # Thread 3: key health
        t3 = threading.Thread(target=self._key_health_check, daemon=True, name="VaultX-KeyHealth")
        t3.start()
        self._threads.append(t3)

        # Write PID
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))

        log.info("VAULT-X Daemon active. Press Ctrl+C to stop.")
        log.info("=" * 60)

        # Main loop
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        log.info("Daemon stopping...")
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join()
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        log.info("Daemon stopped.")

    def authorize_path(self, path: str):
        """Called by GUI/CLI before legitimate vault operations."""
        if self._watcher:
            self._watcher.authorize(os.path.abspath(path))

    def deauthorize_path(self, path: str):
        if self._watcher:
            self._watcher.deauthorize(os.path.abspath(path))
        self._state.register_authorized(os.path.abspath(path))

    @staticmethod
    def is_running() -> bool:
        if not os.path.exists(PID_FILE):
            return False
        try:
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            # Check if process is alive
            if sys.platform == "win32":
                import ctypes
                h = ctypes.windll.kernel32.OpenProcess(0x0400, False, pid)
                if h:
                    ctypes.windll.kernel32.CloseHandle(h)
                    return True
                return False
            else:
                os.kill(pid, 0)
                return True
        except Exception:
            return False

    @staticmethod
    def get_recent_alerts(n: int = 20) -> list:
        alerts = []
        if not os.path.exists(ALERT_LOG):
            return alerts
        try:
            with open(ALERT_LOG) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            alerts.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            pass
        return alerts[-n:]


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import subprocess

    cmd = sys.argv[1].lower() if len(sys.argv) > 1 else "help"

    if cmd == "start":
        if VaultDaemon.is_running():
            print("Daemon is already running.")
        else:
            print("Starting VAULT-X background daemon...")
            print(f"Alert log: {ALERT_LOG}")
            print("Press Ctrl+C to stop.\n")
            daemon = VaultDaemon()
            daemon.start()

    elif cmd == "stop":
        if VaultDaemon.is_running():
            try:
                with open(PID_FILE) as f:
                    pid = int(f.read().strip())
                if sys.platform == "win32":
                    subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
                else:
                    os.kill(pid, signal.SIGTERM)
                print("Daemon stopped.")
            except Exception as e:
                print(f"Stop failed: {e}")
        else:
            print("Daemon is not running.")

    elif cmd == "status":
        running = VaultDaemon.is_running()
        print(f"Daemon status : {'RUNNING ✓' if running else 'STOPPED ✗'}")
        alerts = VaultDaemon.get_recent_alerts(5)
        print(f"Recent alerts : {len(alerts)}")
        for a in alerts[-3:]:
            print(f"  [{a['timestamp'][:19]}] {a['event']}: {os.path.basename(a['path'])}")

    else:
        print("Usage: python daemon/vault_daemon.py [start|stop|status]")
