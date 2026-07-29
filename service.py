"""
╔══════════════════════════════════════════════════════════════════════════╗
║  VAULT-X  ·  Windows Background Service                                  ║
║  File     : service.py                                                   ║
║  Version  : 1.0.0                                                        ║
╚══════════════════════════════════════════════════════════════════════════╝

WHAT THIS FILE DOES:
  Registers VAULT-X as a proper Windows Service named VaultXProtection.
  The service starts automatically on Windows boot, before any user logs in,
  and coordinates all three 24/7 components:

    Component 1 — VaultDaemon (daemon/vault_daemon.py)
      Reactive file watcher: watchdog OS events for copy/move/modify.
      Responds to file system events in real time.

    Component 2 — VaultHTTPServer (server/vault_server.py)
      The enterprise HTTP API on host:port (default 127.0.0.1:8765).
      Serves the admin console, agent enrollment, and vault operations.
      Requires VAULTX_API_KEY environment variable.

    Component 3 — VaultMonitor (monitoring/continuous_monitor.py)
      Proactive 6-stream surveillance daemon.
      Runs canary polls, HSM health checks, rate limiting, session timeouts.

  All three run in separate daemon threads so any crash in one
  does not bring down the others. Each is restarted automatically
  by the service watchdog loop every WATCHDOG_INTERVAL seconds.

HOW TO INSTALL AND MANAGE (run all as Administrator):
  python service.py install          ← register as Windows Service
  python service.py start            ← start the service
  python service.py stop             ← stop the service
  python service.py restart          ← restart the service
  python service.py remove           ← uninstall the service
  python service.py status           ← check if running
  python service.py debug            ← run interactively (no service)

ONE-CLICK INSTALLER:
  Right-click install_service.bat → Run as administrator

CONFIGURATION (environment variables):
  VAULTX_API_KEY        REQUIRED  API key for the HTTP server
  VAULTX_HOST           Optional  HTTP server host (default: 127.0.0.1)
  VAULTX_PORT           Optional  HTTP server port (default: 8765)
  VAULTX_VAULT_DIR      Optional  Vault directory   (default: ./my_vault)
  VAULTX_DATA_ROOT      Optional  Data root directory (default: project root)
  VAULTX_LOG_LEVEL      Optional  Logging level     (default: INFO)
  VAULTX_ENABLE_SERVER  Optional  Set to "0" to disable HTTP server (default: 1)
  VAULTX_ENABLE_MONITOR Optional  Set to "0" to disable continuous monitor

REQUIREMENTS:
  pip install pywin32 cryptography watchdog
  python Scripts/pywin32_postinstall.py -install   (run once after pywin32)
"""

import os
import sys
import time
import json
import logging
import threading
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

# ── Project root on path ──────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# ── pywin32 availability ──────────────────────────────────────────
try:
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
    WIN32_OK = True
except ImportError:
    WIN32_OK = False


# ══════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════

SERVICE_NAME        = "VaultXProtection"
SERVICE_DISPLAY     = "VAULT-X Protection Service"
SERVICE_DESC        = (
    "VAULT-X 24/7 Data Loss Prevention service. "
    "Runs file watcher, HTTP server, and continuous monitoring "
    "for the VAULT-X personal data vault."
)

VAULT_DIR           = Path(os.getenv("VAULTX_VAULT_DIR",
                        str(BASE_DIR / "my_vault")))
LOG_FILE            = VAULT_DIR / "service.log"
STATE_FILE          = VAULT_DIR / ".service_state.json"

WATCHDOG_INTERVAL   = 30    # seconds between component health checks
LOG_MAX_BYTES       = 5 * 1024 * 1024   # 5 MB per log file
LOG_BACKUP_COUNT    = 3


# ══════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════

def build_logger(name: str = "VaultXService") -> logging.Logger:
    """
    Create a rotating file logger that writes to service.log.
    Safe to call multiple times — returns the same logger instance.
    """
    VAULT_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Rotating file handler
    fh = RotatingFileHandler(
        str(LOG_FILE),
        maxBytes     = LOG_MAX_BYTES,
        backupCount  = LOG_BACKUP_COUNT,
        encoding     = "utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    # Console handler (visible in debug/interactive mode)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    return logger


log = build_logger()


# ══════════════════════════════════════════════════════════════════
# STATE FILE  (read by tray.py and dashboard)
# ══════════════════════════════════════════════════════════════════

def write_state(extra: dict = None):
    """
    Write current service state to .service_state.json.
    The tray icon and web dashboard read this file to display status.
    """
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    state = {
        "service_name"   : SERVICE_NAME,
        "running"        : True,
        "updated_at"     : datetime.now().isoformat(),
        "vault_dir"      : str(VAULT_DIR),
        "components"     : {
            "daemon" : "unknown",
            "server" : "unknown",
            "monitor": "unknown",
        },
    }
    if extra:
        state.update(extra)
    try:
        with open(str(STATE_FILE), "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        log.warning("Could not write state file: %s", e)


def clear_state():
    """Mark the service as stopped in the state file."""
    try:
        with open(str(STATE_FILE), "w") as f:
            json.dump({"running": False, "stopped_at": datetime.now().isoformat()}, f)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════
# COMPONENT WRAPPERS
# ══════════════════════════════════════════════════════════════════

class ComponentRunner:
    """
    Base class for a restartable service component.
    Each component runs in its own daemon thread.
    If the thread dies, the watchdog restarts it automatically.
    """

    name: str = "component"

    def __init__(self):
        self._thread  : threading.Thread = None
        self._stop_ev : threading.Event  = threading.Event()
        self.status   : str              = "stopped"

    def _run(self):
        """Override in subclass — the component's main loop."""
        raise NotImplementedError

    def start(self):
        self._stop_ev.clear()
        self._thread = threading.Thread(
            target = self._safe_run,
            daemon = True,
            name   = f"VaultX-{self.name}",
        )
        self._thread.start()
        self.status = "running"
        log.info("[%s] Started.", self.name)

    def _safe_run(self):
        try:
            self._run()
        except Exception as e:
            log.error("[%s] Crashed: %s", self.name, e, exc_info=True)
            self.status = "crashed"

    def stop(self):
        self._stop_ev.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)
        self.status = "stopped"
        log.info("[%s] Stopped.", self.name)

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def restart(self):
        log.warning("[%s] Restarting...", self.name)
        self.stop()
        time.sleep(2)
        self.start()


class DaemonRunner(ComponentRunner):
    """
    Wraps vault_daemon.py VaultDaemon.
    The daemon watches the vault directory for unauthorized file changes.

    VaultDaemon.start() contains its own blocking while loop.
    We hold a reference so stop() can call daemon.stop() directly,
    which sets daemon._running = False and breaks the inner loop.
    """

    name = "VaultDaemon"

    def __init__(self):
        super().__init__()
        self._daemon_instance = None   # holds the VaultDaemon for stop()

    def _run(self):
        try:
            from daemon.vault_daemon import VaultDaemon
            self._daemon_instance = VaultDaemon()
            self._daemon_instance.start()
            # VaultDaemon.start() blocks here until daemon._running = False
        except ImportError as e:
            log.error("[DaemonRunner] Cannot import VaultDaemon: %s", e)
            self.status = "unavailable"
        except Exception as e:
            log.error("[DaemonRunner] Error: %s", e, exc_info=True)
            self.status = "crashed"
            raise

    def stop(self):
        """Stop the inner VaultDaemon loop before joining the thread."""
        self._stop_ev.set()
        if self._daemon_instance:
            try:
                self._daemon_instance.stop()   # sets daemon._running = False
            except Exception as e:
                log.warning("[DaemonRunner] Error stopping inner daemon: %s", e)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)
        self.status = "stopped"
        log.info("[%s] Stopped.", self.name)


class ServerRunner(ComponentRunner):
    """
    Wraps vault_server.py HTTP server.
    Serves the enterprise API and admin console on port 8765.
    Requires VAULTX_API_KEY environment variable.
    """

    name = "VaultServer"

    def _run(self):
        api_key = os.getenv("VAULTX_API_KEY")
        if not api_key:
            log.warning(
                "[ServerRunner] VAULTX_API_KEY not set — HTTP server disabled. "
                "Set this environment variable to enable the admin console."
            )
            self.status = "disabled"
            return

        try:
            from server.vault_server import VaultService, VaultHTTPServer, VaultRequestHandler

            host      = os.getenv("VAULTX_HOST",      "127.0.0.1")
            port      = int(os.getenv("VAULTX_PORT",  "8765"))
            vault_dir = Path(os.getenv("VAULTX_VAULT_DIR", str(VAULT_DIR)))
            data_root = Path(os.getenv("VAULTX_DATA_ROOT", str(BASE_DIR)))

            service = VaultService(vault_dir, data_root, api_key)
            server  = VaultHTTPServer((host, port), VaultRequestHandler, service)

            log.info("[ServerRunner] HTTP server listening on %s:%s", host, port)
            self.status = "running"

            # serve_forever blocks until server.shutdown() is called
            server.serve_forever()

        except OSError as e:
            log.error(
                "[ServerRunner] Cannot bind to port — is another instance running? %s", e
            )
            self.status = "port_conflict"
        except ImportError as e:
            log.error("[ServerRunner] Cannot import vault_server: %s", e)
            self.status = "unavailable"
        except Exception as e:
            log.error("[ServerRunner] Error: %s", e, exc_info=True)
            self.status = "crashed"
            raise


class MonitorRunner(ComponentRunner):
    """
    Wraps monitoring/continuous_monitor.py VaultMonitor.
    Runs 6 proactive surveillance streams.
    Integrates with VaultEngine for session-aware monitoring.
    """

    name = "VaultMonitor"

    def _run(self):
        try:
            from monitoring.continuous_monitor import VaultMonitor
            from core.vault_engine import VaultEngine
            from core.audit_ledger import AuditLedger

            engine = VaultEngine(str(VAULT_DIR))

            def _sign(entry):
                import json as _json, base64 as _b64
                raw = _json.dumps(entry, sort_keys=True).encode()
                sig = engine._signing_key.sign(raw)
                return _b64.b64encode(sig).decode()

            ledger = AuditLedger(str(VAULT_DIR), sign_fn=_sign)

            def _on_alert(event):
                log.warning(
                    "[Monitor] %s: %s | details=%s",
                    event.severity, event.message, event.details,
                )

            monitor = VaultMonitor(
                vault_dir      = str(VAULT_DIR),
                vault_engine   = engine,
                audit_callback = ledger.log,
                alert_callback = _on_alert,
            )
            monitor.start()
            self.status = "running"

            # Block until stop event
            while not self._stop_ev.is_set():
                time.sleep(5)

            monitor.stop()

        except ImportError as e:
            log.error("[MonitorRunner] Cannot import VaultMonitor: %s", e)
            self.status = "unavailable"
        except Exception as e:
            log.error("[MonitorRunner] Error: %s", e, exc_info=True)
            self.status = "crashed"
            raise


# ══════════════════════════════════════════════════════════════════
# SERVICE COORDINATOR
# ══════════════════════════════════════════════════════════════════

class VaultXCoordinator:
    """
    Starts and supervises all three VAULT-X components.
    Runs a watchdog loop that detects crashes and restarts components.

    START ORDER:
      1. VaultDaemon    — file protection first (no dependencies)
      2. VaultMonitor   — proactive surveillance (needs vault engine)
      3. VaultServer    — HTTP API last (needs vault state stable)

    STOP ORDER (reverse of start):
      3. VaultServer → 2. VaultMonitor → 1. VaultDaemon
    """

    def __init__(self):
        enable_server  = os.getenv("VAULTX_ENABLE_SERVER",  "1") != "0"
        enable_monitor = os.getenv("VAULTX_ENABLE_MONITOR", "1") != "0"

        self.daemon  = DaemonRunner()
        self.monitor = MonitorRunner()  if enable_monitor else None
        self.server  = ServerRunner()   if enable_server  else None

        self._running = False

    def start(self):
        log.info("=" * 60)
        log.info("VAULT-X Protection Service starting")
        log.info("  Vault dir : %s", VAULT_DIR)
        log.info("  Components: daemon=%s  monitor=%s  server=%s",
                 "on", "on" if self.monitor else "off",
                 "on" if self.server else "off")
        log.info("=" * 60)

        VAULT_DIR.mkdir(parents=True, exist_ok=True)

        # Start in dependency order
        self.daemon.start()
        time.sleep(1)   # let daemon settle

        if self.monitor:
            self.monitor.start()
            time.sleep(1)

        if self.server:
            self.server.start()
            time.sleep(1)

        self._running = True
        write_state(self._component_states())
        log.info("VAULT-X Protection Service fully operational.")

    def stop(self):
        log.info("VAULT-X Protection Service stopping...")
        self._running = False

        # Stop in reverse order
        if self.server:
            self.server.stop()
        if self.monitor:
            self.monitor.stop()
        self.daemon.stop()

        clear_state()
        log.info("VAULT-X Protection Service stopped.")

    def watchdog_tick(self):
        """
        Called every WATCHDOG_INTERVAL seconds.
        Restarts any component that has crashed.
        """
        for component in self._active_components():
            if not component.is_alive() and component.status == "crashed":
                log.warning("[Watchdog] %s crashed — restarting.", component.name)
                component.restart()

        write_state(self._component_states())

    def _active_components(self) -> list:
        return [c for c in (self.daemon, self.monitor, self.server) if c]

    def _component_states(self) -> dict:
        return {
            "components": {
                "daemon" : self.daemon.status,
                "monitor": self.monitor.status if self.monitor else "disabled",
                "server" : self.server.status  if self.server  else "disabled",
            }
        }


# ══════════════════════════════════════════════════════════════════
# WINDOWS SERVICE CLASS
# ══════════════════════════════════════════════════════════════════

if WIN32_OK:

    class VaultXWindowsService(win32serviceutil.ServiceFramework):
        """
        Windows Service implementation using pywin32.

        Windows Service Control Manager (SCM) calls:
          SvcDoRun()  — when the service is started
          SvcStop()   — when the service is stopped via SCM, net stop, or shutdown

        The coordinator runs all three components in daemon threads.
        The main thread blocks on a win32 Event, waking every
        WATCHDOG_INTERVAL ms to run the watchdog and write state.

        IMPORTANT: SvcStop() must return quickly or Windows will
        kill the process. Long cleanup runs in the coordinator.stop()
        call before setting the stop event.
        """

        _svc_name_         = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_  = SERVICE_DESC

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event  = win32event.CreateEvent(None, 0, 0, None)
            self._coordinator = VaultXCoordinator()

        def SvcStop(self):
            """Called by Windows SCM when stopping the service."""
            log.info("SvcStop received — shutting down.")
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._coordinator.stop()
            win32event.SetEvent(self._stop_event)

        def SvcDoRun(self):
            """
            Main service loop.
            Runs until SvcStop() sets the stop event.
            """
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            log.info("SvcDoRun started for %s", SERVICE_NAME)

            # Start all components
            try:
                self._coordinator.start()
            except Exception as e:
                log.error("Failed to start coordinator: %s", e, exc_info=True)
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_ERROR_TYPE,
                    servicemanager.PYS_SERVICE_STOPPED,
                    (self._svc_name_, str(e)),
                )
                return

            # Watchdog loop
            while True:
                rc = win32event.WaitForSingleObject(
                    self._stop_event,
                    WATCHDOG_INTERVAL * 1000,   # milliseconds
                )
                if rc == win32event.WAIT_OBJECT_0:
                    # Stop event received
                    break
                # Timeout — run watchdog
                try:
                    self._coordinator.watchdog_tick()
                except Exception as e:
                    log.error("Watchdog error: %s", e)

            log.info("SvcDoRun exiting.")


# ══════════════════════════════════════════════════════════════════
# DEBUG / INTERACTIVE MODE  (no Windows Service needed)
# ══════════════════════════════════════════════════════════════════

def run_interactive():
    """
    Run all components interactively (not as a Windows Service).
    Useful for:
      - Testing on Windows without admin rights
      - Testing on Linux/macOS (CI/CD, development)
      - Running: python service.py debug

    Press Ctrl+C to stop.
    """
    import signal

    coordinator = VaultXCoordinator()
    coordinator.start()

    log.info("Running in interactive mode. Press Ctrl+C to stop.")

    stop_flag = threading.Event()

    def _handle_signal(sig, frame):
        log.info("Signal %s received — stopping.", sig)
        stop_flag.set()

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        while not stop_flag.is_set():
            coordinator.watchdog_tick()
            stop_flag.wait(timeout=WATCHDOG_INTERVAL)
    finally:
        coordinator.stop()


def print_status():
    """Print current service status from the state file."""
    if STATE_FILE.exists():
        try:
            with open(str(STATE_FILE)) as f:
                state = json.load(f)
            running = state.get("running", False)
            print(f"\nVAULT-X Protection Service")
            print(f"  Status    : {'RUNNING' if running else 'STOPPED'}")
            print(f"  Updated   : {state.get('updated_at', 'N/A')}")
            print(f"  Vault dir : {state.get('vault_dir', 'N/A')}")
            comps = state.get("components", {})
            for name, status in comps.items():
                print(f"  {name:10}: {status}")
            print()
            return
        except Exception:
            pass
    print("\nVAULT-X Protection Service: state file not found (service may not be running)\n")


# ══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def main():
    """
    Entry point for all service management commands.

    When called with no arguments by Windows SCM: runs as service.
    When called with arguments: routes to win32serviceutil or interactive mode.

    Usage:
      python service.py install   ← register Windows Service
      python service.py start     ← start service
      python service.py stop      ← stop service
      python service.py restart   ← restart service
      python service.py remove    ← uninstall service
      python service.py status    ← show status from state file
      python service.py debug     ← run interactively (Ctrl+C to stop)
    """
    if len(sys.argv) >= 2:
        cmd = sys.argv[1].lower()

        if cmd == "status":
            print_status()
            return

        if cmd == "debug":
            run_interactive()
            return

        if cmd in ("install", "start", "stop", "restart", "remove", "update"):
            if not WIN32_OK:
                print(
                    "\n[VAULT-X] pywin32 is required for Windows Service management.\n"
                    "Run: pip install pywin32\n"
                    "Then: python Scripts/pywin32_postinstall.py -install\n"
                    "\nAlternatively, run in debug mode:\n"
                    "  python service.py debug\n"
                )
                sys.exit(1)
            win32serviceutil.HandleCommandLine(VaultXWindowsService)
            return

    # No arguments OR called by Windows SCM
    if WIN32_OK:
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(VaultXWindowsService)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception as e:
            # Not running as a service — fall back to interactive
            log.info("Not running as Windows Service (%s). Use 'debug' for interactive mode.", e)
            print(f"Usage: python service.py [install|start|stop|restart|remove|status|debug]")
    else:
        # Non-Windows: always run interactively
        log.info("pywin32 not available — running in interactive mode.")
        run_interactive()


if __name__ == "__main__":
    main()
