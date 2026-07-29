"""
╔══════════════════════════════════════════════════════════════════════════╗
║  VAULT-X  ·  System Tray Application                                     ║
║  File     : tray.py                                                      ║
║  Version  : 1.0.0                                                        ║
╚══════════════════════════════════════════════════════════════════════════╝

WHAT THIS FILE DOES:
  Shows a VAULT-X shield icon in the Windows system tray (bottom-right).
  The icon changes colour based on live security status read from the
  state files written by service.py and vault_daemon.py.

  ICON COLOURS:
    🟢 Green  → Service running, no unread alerts
    🟡 Yellow → Service running, warnings detected
    🔴 Red    → Critical alert OR service not running

  RIGHT-CLICK MENU:
    VAULT-X  v1.0.0
    ───────────────────────────────
    ✓ Service: running              ← live status from .service_state.json
    Daemon: running                 ← live status from .daemon_state.json
    3 unread alerts                 ← unread count from daemon_alerts.log
    ───────────────────────────────
    🖥  Open Desktop GUI            ← launches gui/vault_gui.py
    🌐  Open Admin Console          ← opens http://127.0.0.1:8765 in browser
    🔔  View Alerts                 ← opens daemon_alerts.log in Notepad
    📋  View Audit Log              ← opens vault_audit.jsonl in Notepad
    ───────────────────────────────
    ▶  Start Service               ← python service.py start  (if stopped)
    ⏹  Stop Service               ← python service.py stop   (if running)
    ───────────────────────────────
    ✖  Exit Tray                   ← removes icon (service keeps running)

  TOAST NOTIFICATIONS:
    Fires a Windows pop-up when a new CRITICAL alert appears in
    daemon_alerts.log. Tracks the last-seen line count so it only
    notifies on genuinely new entries.

HOW TO RUN:
  python tray.py           ← start the tray icon
  pythonw tray.py          ← start silently (no console window)

ADD TO WINDOWS STARTUP:
  Put a shortcut to "pythonw tray.py" in:
  %%APPDATA%%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup

REQUIREMENTS:
  pip install pystray Pillow
  pip install win10toast        (optional — for toast notifications)

FILES READ (never written):
  my_vault/.service_state.json  ← written by service.py every 30s
  my_vault/.daemon_state.json   ← written by vault_daemon.py
  my_vault/daemon_alerts.log    ← written by daemon + monitor (JSONL)
  my_vault/vault_audit.jsonl    ← written by AuditLedger (JSONL)
"""

import os
import sys
import json
import time
import threading
import subprocess
import webbrowser
from datetime import datetime
from pathlib import Path

# ── Project root on path ──────────────────────────────────────────
BASE_DIR  = Path(__file__).resolve().parent
VAULT_DIR = Path(os.getenv("VAULTX_VAULT_DIR", str(BASE_DIR / "my_vault")))
sys.path.insert(0, str(BASE_DIR))

# ── pystray + Pillow ──────────────────────────────────────────────
try:
    import pystray
    from pystray import MenuItem as Item, Menu
    PYSTRAY_OK = True
except ImportError:
    PYSTRAY_OK = False
    print("[Tray] pystray not installed.  Run: pip install pystray")

try:
    from PIL import Image, ImageDraw, ImageFont
    PILLOW_OK = True
except ImportError:
    PILLOW_OK = False
    print("[Tray] Pillow not installed.  Run: pip install Pillow")

# ── Toast notifications (optional) ───────────────────────────────
try:
    from win10toast import ToastNotifier
    _toaster  = ToastNotifier()
    TOAST_OK  = True
except ImportError:
    TOAST_OK  = False


# ══════════════════════════════════════════════════════════════════
# FILE PATHS
# ══════════════════════════════════════════════════════════════════

SERVICE_STATE_FILE = VAULT_DIR / ".service_state.json"
DAEMON_STATE_FILE  = VAULT_DIR / ".daemon_state.json"
ALERT_LOG          = VAULT_DIR / "daemon_alerts.log"
AUDIT_LOG          = VAULT_DIR / "vault_audit.jsonl"

SERVER_URL         = f"http://{os.getenv('VAULTX_HOST','127.0.0.1')}:{os.getenv('VAULTX_PORT','8765')}"

POLL_INTERVAL      = 10    # seconds between state polls
VERSION            = "1.0.0"

# Severity keywords that trigger a RED icon and toast
CRITICAL_KEYWORDS  = frozenset({
    "CRITICAL", "TRIPWIRE", "TAMPER", "BREACH", "KEY_MISSING",
    "CORRUPTED", "UNAUTHORISED", "UNAUTHORIZED", "ATTACK",
})


# ══════════════════════════════════════════════════════════════════
# STATE READER
# ══════════════════════════════════════════════════════════════════

def _read_json(path: Path) -> dict:
    """Read a JSON file safely. Returns {} on any error."""
    try:
        with open(str(path), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def read_service_state() -> dict:
    """Read service.py's state file."""
    return _read_json(SERVICE_STATE_FILE)


def read_daemon_state() -> dict:
    """Read vault_daemon.py's state file."""
    return _read_json(DAEMON_STATE_FILE)


def count_alerts() -> tuple:
    """
    Return (total_alerts, critical_count, last_event_str).
    Reads daemon_alerts.log — JSONL format:
      {"timestamp":..., "event":..., "path":..., "details":...}
    Also includes entries from continuous_monitor.py which writes
    the same format via _write_alert_log().
    """
    if not ALERT_LOG.exists():
        return 0, 0, "None"

    total    = 0
    critical = 0
    last_ev  = "None"

    try:
        with open(str(ALERT_LOG), encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    entry = json.loads(line)
                    ev    = entry.get("event", "")
                    if any(kw in ev.upper() for kw in CRITICAL_KEYWORDS):
                        critical += 1
                    last_ev = ev
                except Exception:
                    pass
    except Exception:
        pass

    return total, critical, last_ev


def get_icon_status() -> tuple:
    """
    Determine icon colour and tooltip text from current system state.

    Returns:
        (colour: str "green"|"yellow"|"red",
         tooltip: str,
         svc_running: bool,
         unread_critical: int)
    """
    svc    = read_service_state()
    daemon = read_daemon_state()
    total, critical, last_ev = count_alerts()

    svc_running    = svc.get("running", False)
    daemon_running = len(daemon.get("checksums", {})) >= 0   # file exists = daemon ran

    if not svc_running:
        return "red", "VAULT-X — Service not running", False, critical

    comps  = svc.get("components", {})
    daemon_status  = comps.get("daemon",  "unknown")
    monitor_status = comps.get("monitor", "unknown")

    if critical > 0 or daemon_status == "crashed":
        colour  = "red"
        tooltip = f"VAULT-X — {critical} CRITICAL alert(s)"
    elif total > 0 or monitor_status in ("crashed", "unavailable"):
        colour  = "yellow"
        tooltip = f"VAULT-X — {total} alert(s) logged"
    else:
        colour  = "green"
        tooltip = "VAULT-X — All clear, vault protected"

    return colour, tooltip, svc_running, critical


# ══════════════════════════════════════════════════════════════════
# ICON GENERATOR
# ══════════════════════════════════════════════════════════════════

_COLOURS = {
    "green" : ("#00C851", "#145C30"),
    "yellow": ("#FFD700", "#8B6914"),
    "red"   : ("#E74C3C", "#7B241C"),
}

_ICON_CACHE: dict = {}


def make_icon(colour: str = "green") -> "Image":
    """
    Draw a 64×64 shield icon using Pillow.
    Cached — only redraws when colour changes.
    No external image file needed.

    Shield shape: hexagonal top + pointed bottom
    Inner fill  : status colour
    Outer ring  : dark navy
    Text        : "VX" in white
    """
    if colour in _ICON_CACHE:
        return _ICON_CACHE[colour]

    fill, shadow = _COLOURS.get(colour, _COLOURS["green"])
    NAVY         = "#1B2A4A"
    WHITE        = "#FFFFFF"
    SIZE         = 64

    img  = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Outer shield — navy background
    outer = [
        (SIZE * 0.50, SIZE * 0.03),   # top centre
        (SIZE * 0.97, SIZE * 0.22),   # top right
        (SIZE * 0.97, SIZE * 0.58),   # right
        (SIZE * 0.50, SIZE * 0.97),   # bottom tip
        (SIZE * 0.03, SIZE * 0.58),   # left
        (SIZE * 0.03, SIZE * 0.22),   # top left
    ]
    draw.polygon(outer, fill=NAVY)

    # Inner shield — status colour
    m = 5
    inner = [
        (SIZE * 0.50,     SIZE * 0.03 + m * 1.5),
        (SIZE * 0.97 - m, SIZE * 0.22 + m * 0.8),
        (SIZE * 0.97 - m, SIZE * 0.58),
        (SIZE * 0.50,     SIZE * 0.97 - m),
        (SIZE * 0.03 + m, SIZE * 0.58),
        (SIZE * 0.03 + m, SIZE * 0.22 + m * 0.8),
    ]
    draw.polygon(inner, fill=fill)

    # "VX" text centred on the shield
    try:
        font = ImageFont.truetype("arialbd.ttf", 18)
    except Exception:
        try:
            font = ImageFont.truetype("arial.ttf", 16)
        except Exception:
            font = ImageFont.load_default()

    text = "VX"
    try:
        bbox = draw.textbbox((0, 0), text, font=font)
        tw   = bbox[2] - bbox[0]
        th   = bbox[3] - bbox[1]
    except AttributeError:
        tw, th = draw.textsize(text, font=font)

    tx = (SIZE - tw) // 2
    ty = (SIZE - th) // 2 - 2
    # Shadow
    draw.text((tx + 1, ty + 1), text, fill=shadow, font=font)
    # Main text
    draw.text((tx, ty), text, fill=WHITE, font=font)

    _ICON_CACHE[colour] = img
    return img


# ══════════════════════════════════════════════════════════════════
# TOAST NOTIFICATIONS
# ══════════════════════════════════════════════════════════════════

def toast(title: str, message: str):
    """Send a Windows toast notification. Falls back to print."""
    if TOAST_OK:
        try:
            _toaster.show_toast(title, message, duration=6, threaded=True)
            return
        except Exception:
            pass
    print(f"[VAULT-X] {title}: {message}")


# ══════════════════════════════════════════════════════════════════
# TRAY ACTIONS
# ══════════════════════════════════════════════════════════════════

def _run(cmd: list, **kwargs):
    """Run a subprocess without blocking the tray."""
    try:
        subprocess.Popen(cmd, **kwargs)
    except Exception as e:
        toast("VAULT-X Error", f"Could not run command: {e}")


def action_open_gui(icon, item):
    """Launch the VAULT-X desktop GUI in a new window."""
    gui_path = str(BASE_DIR / "gui" / "vault_gui.py")
    if os.path.exists(gui_path):
        _run(
            [sys.executable, gui_path],
            creationflags = subprocess.CREATE_NEW_CONSOLE
            if sys.platform == "win32" else 0,
        )
    else:
        toast("VAULT-X", "GUI not found: gui/vault_gui.py")


def action_open_admin(icon, item):
    """Open the admin console in the default browser."""
    webbrowser.open(SERVER_URL)


def action_view_alerts(icon, item):
    """Open daemon_alerts.log in Notepad (Windows) or default text editor."""
    if not ALERT_LOG.exists():
        toast("VAULT-X", "No alert log found yet — vault is clean.")
        return
    _open_file(str(ALERT_LOG))


def action_view_audit(icon, item):
    """Open vault_audit.jsonl in Notepad."""
    if not AUDIT_LOG.exists():
        toast("VAULT-X", "No audit log found. Login to the vault first.")
        return
    _open_file(str(AUDIT_LOG))


def action_start_service(icon, item):
    """Start the Windows service."""
    _run(
        ["python", str(BASE_DIR / "service.py"), "start"],
        creationflags = subprocess.CREATE_NO_WINDOW
        if sys.platform == "win32" else 0,
    )
    time.sleep(2)
    toast("VAULT-X", "Service start requested.")


def action_stop_service(icon, item):
    """Stop the Windows service."""
    _run(
        ["python", str(BASE_DIR / "service.py"), "stop"],
        creationflags = subprocess.CREATE_NO_WINDOW
        if sys.platform == "win32" else 0,
    )
    time.sleep(2)
    toast("VAULT-X", "Service stop requested.")


def action_exit(icon, item):
    """Remove tray icon. Service keeps running."""
    icon.stop()


def _open_file(path: str):
    """Open a file in the default text viewer."""
    try:
        if sys.platform == "win32":
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception as e:
        toast("VAULT-X", f"Could not open file: {e}")


# ══════════════════════════════════════════════════════════════════
# MENU BUILDER
# ══════════════════════════════════════════════════════════════════

def build_menu(svc_running: bool, total_alerts: int, critical: int,
               daemon_status: str, monitor_status: str) -> Menu:
    """
    Build the right-click context menu with live status values.
    Called every POLL_INTERVAL seconds so the menu always shows
    current data without needing the user to close and reopen it.
    """
    # Status lines (non-clickable)
    svc_line    = f"{'✓' if svc_running else '✗'} Service: {'running' if svc_running else 'STOPPED'}"
    daemon_line = f"  Daemon : {daemon_status}"
    monitor_line= f"  Monitor: {monitor_status}"
    alert_line  = (
        f"  {'🔴' if critical > 0 else '🟡' if total_alerts > 0 else '🟢'} "
        f"{critical} critical  /  {total_alerts} total alerts"
    )

    return Menu(
        Item(f"VAULT-X  v{VERSION}",   None, enabled=False),
        Menu.SEPARATOR,
        Item(svc_line,                 None, enabled=False),
        Item(daemon_line,              None, enabled=False),
        Item(monitor_line,             None, enabled=False),
        Item(alert_line,               None, enabled=False),
        Menu.SEPARATOR,
        Item("🖥  Open Desktop GUI",   action_open_gui),
        Item("🌐  Open Admin Console", action_open_admin),
        Item("🔔  View Alerts",        action_view_alerts),
        Item("📋  View Audit Log",     action_view_audit),
        Menu.SEPARATOR,
        Item("▶  Start Service",       action_start_service, enabled=not svc_running),
        Item("⏹  Stop Service",       action_stop_service,  enabled=svc_running),
        Menu.SEPARATOR,
        Item("✖  Exit Tray",          action_exit),
    )


# ══════════════════════════════════════════════════════════════════
# ALERT WATCHER — toast on new critical entries
# ══════════════════════════════════════════════════════════════════

class AlertWatcher:
    """
    Watches daemon_alerts.log for new lines.
    When a new entry with a CRITICAL severity keyword appears,
    fires a Windows toast notification.

    Tracks the last-seen line count so it only notifies on
    genuinely new entries — not on every poll.
    """

    def __init__(self):
        self._last_line_count = 0
        self._initialised     = False

    def check(self):
        """
        Call every POLL_INTERVAL seconds.
        Returns list of new critical event strings (empty if none).
        """
        if not ALERT_LOG.exists():
            return []

        new_critical = []
        try:
            with open(str(ALERT_LOG), encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            current_count = len(lines)

            if not self._initialised:
                # First run — set baseline without notifying
                self._last_line_count = current_count
                self._initialised     = True
                return []

            if current_count > self._last_line_count:
                new_lines = lines[self._last_line_count:]
                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        ev    = entry.get("event", "")
                        if any(kw in ev.upper() for kw in CRITICAL_KEYWORDS):
                            new_critical.append(ev)
                    except Exception:
                        pass
                self._last_line_count = current_count

        except Exception:
            pass

        return new_critical


# ══════════════════════════════════════════════════════════════════
# TRAY MANAGER
# ══════════════════════════════════════════════════════════════════

class TrayManager:
    """
    Manages the pystray icon lifecycle.

    Runs a background poll thread every POLL_INTERVAL seconds:
      1. Reads .service_state.json and .daemon_state.json
      2. Counts alerts in daemon_alerts.log
      3. Updates icon colour and tooltip
      4. Rebuilds the right-click menu with fresh data
      5. Fires toast notifications for new CRITICAL events

    The pystray icon.run() call blocks the main thread.
    All updates happen from the background thread via
    icon.icon = ... and icon.menu = ...
    """

    def __init__(self):
        self._icon         = None
        self._running      = False
        self._poll_thread  = None
        self._watcher      = AlertWatcher()
        self._last_colour  = None

    def start(self):
        if not PYSTRAY_OK or not PILLOW_OK:
            print("[Tray] Cannot start: pystray and Pillow are required.")
            print("  pip install pystray Pillow")
            sys.exit(1)

        colour, tooltip, svc_running, critical = get_icon_status()
        total, _, _ = count_alerts()
        svc   = read_service_state()
        comps = svc.get("components", {})

        self._icon = pystray.Icon(
            name    = "VAULT-X",
            icon    = make_icon(colour),
            title   = tooltip,
            menu    = build_menu(
                svc_running    = svc_running,
                total_alerts   = total,
                critical       = critical,
                daemon_status  = comps.get("daemon",  "unknown"),
                monitor_status = comps.get("monitor", "unknown"),
            ),
        )
        self._last_colour = colour

        self._running     = True
        self._poll_thread = threading.Thread(
            target = self._poll_loop,
            daemon = True,
            name   = "VaultX-TrayPoll",
        )
        self._poll_thread.start()

        toast(
            "VAULT-X Protection",
            "System tray active. Right-click the shield icon for options.",
        )

        print("[Tray] VAULT-X system tray icon active.")
        print("[Tray] Right-click the shield icon in the taskbar.")
        print("[Tray] Close this window or press Ctrl+C to exit.")

        # Blocks until action_exit() calls icon.stop()
        self._icon.run()

    def _poll_loop(self):
        """Background thread: update icon and menu every POLL_INTERVAL seconds."""
        while self._running and self._icon:
            try:
                self._update()
            except Exception as e:
                print(f"[Tray] Poll error: {e}")
            time.sleep(POLL_INTERVAL)

    def _update(self):
        """Refresh icon colour, tooltip, and menu from current state files."""
        if not self._icon:
            return

        colour, tooltip, svc_running, critical = get_icon_status()
        total, _, last_ev = count_alerts()
        svc   = read_service_state()
        comps = svc.get("components", {})

        # Update icon image only if colour changed (avoids flicker)
        if colour != self._last_colour:
            self._icon.icon  = make_icon(colour)
            self._last_colour = colour

        # Always update tooltip and menu (menu has live counts)
        self._icon.title = tooltip
        self._icon.menu  = build_menu(
            svc_running    = svc_running,
            total_alerts   = total,
            critical       = critical,
            daemon_status  = comps.get("daemon",  "unknown"),
            monitor_status = comps.get("monitor", "unknown"),
        )

        # Check for new critical alerts → toast
        new_crits = self._watcher.check()
        for ev in new_crits:
            toast("🚨 VAULT-X Security Alert", ev)

    def stop(self):
        self._running = False
        if self._icon:
            self._icon.stop()


# ══════════════════════════════════════════════════════════════════
# STARTUP SHORTCUT HELPER
# ══════════════════════════════════════════════════════════════════

def add_to_startup():
    """
    Add tray.py to Windows startup so it launches on login.
    Creates a .bat launcher in the Startup folder.
    Only works on Windows.
    """
    if sys.platform != "win32":
        print("[Tray] Startup registration only supported on Windows.")
        return

    startup_dir = Path(os.getenv("APPDATA", "")) / \
        "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"

    bat_path = startup_dir / "VaultX_Tray.bat"
    bat_content = (
        f'@echo off\n'
        f'start "" /b pythonw "{BASE_DIR / "tray.py"}"\n'
    )
    try:
        bat_path.write_text(bat_content, encoding="utf-8")
        print(f"[Tray] Added to startup: {bat_path}")
    except Exception as e:
        print(f"[Tray] Could not add to startup: {e}")


def remove_from_startup():
    """Remove tray.py from Windows startup."""
    if sys.platform != "win32":
        return
    startup_dir = Path(os.getenv("APPDATA", "")) / \
        "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    bat_path = startup_dir / "VaultX_Tray.bat"
    try:
        bat_path.unlink(missing_ok=True)
        print(f"[Tray] Removed from startup: {bat_path}")
    except Exception as e:
        print(f"[Tray] Could not remove from startup: {e}")


# ══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def main():
    """
    Entry point for tray.py.

    Usage:
      python tray.py              ← start the tray icon
      python tray.py --startup    ← add to Windows startup
      python tray.py --no-startup ← remove from Windows startup
    """
    if len(sys.argv) >= 2:
        arg = sys.argv[1].lower()
        if arg == "--startup":
            add_to_startup()
            return
        if arg in ("--no-startup", "--remove-startup"):
            remove_from_startup()
            return
        if arg in ("-h", "--help"):
            print(__doc__)
            return

    if not PYSTRAY_OK:
        print("\n[Tray] ERROR: pystray is not installed.")
        print("  Run: pip install pystray Pillow")
        sys.exit(1)

    if not PILLOW_OK:
        print("\n[Tray] ERROR: Pillow is not installed.")
        print("  Run: pip install Pillow")
        sys.exit(1)

    tray = TrayManager()
    try:
        tray.start()
    except KeyboardInterrupt:
        print("\n[Tray] Exiting.")
        tray.stop()


if __name__ == "__main__":
    main()
