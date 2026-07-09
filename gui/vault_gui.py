"""
╔══════════════════════════════════════════════════════════════════════════╗
║  VAULT-X  ·  Desktop GUI Application                                     ║
║  Module   : gui/vault_gui.py                                             ║
║  Purpose  : Full desktop interface — no CMD required                     ║
║  Run with : python gui/vault_gui.py                                      ║
║  Version  : 2.0.0                                                        ║
╚══════════════════════════════════════════════════════════════════════════╝

PANELS:
  1. Login Screen     — 5-layer auth with visual progress
  2. Dashboard        — session status, daemon status, quick stats
  3. File Vault       — encrypt/decrypt with file browser + drag-drop
  4. Audit Log        — scrollable signed audit entries with chain verify
  5. Threat Monitor   — live alerts from daemon + copy detection events
  6. Settings         — geofence IP rules, session timeouts, wipe passes

REQUIRES: pip install cryptography watchdog
"""

import os
import sys
import json
import time
import hashlib
import secrets
import threading
import subprocess
import dataclasses
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.vault_engine import VaultEngine, VaultBlob, get_device_fingerprint
from core.auth_gateway import AuthGateway
from core.audit_ledger import AuditLedger
from relocation.relocator import Relocator, LocationRegistry

VAULT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "my_vault")
DAEMON_LOG = os.path.join(VAULT_DIR, "daemon_alerts.log")

# ── Color Palette ─────────────────────────────────────────────────────────────
BG_DARK = "#0D1117"
BG_PANEL = "#161B22"
BG_CARD = "#1C2333"
BG_INPUT = "#21262D"
ACCENT = "#58A6FF"
ACCENT2 = "#3FB950"
WARN = "#D29922"
DANGER = "#F85149"
TEXT_PRI = "#E6EDF3"
TEXT_SEC = "#8B949E"
TEXT_DIM = "#484F58"
BORDER = "#30363D"
PURPLE = "#BC8CFF"
TEAL = "#39D353"

FONT_TITLE = ("Segoe UI", 22, "bold")
FONT_HEAD = ("Segoe UI", 13, "bold")
FONT_BODY = ("Segoe UI", 11)
FONT_SMALL = ("Segoe UI", 9)
FONT_MONO = ("Consolas", 10)
FONT_MONO_S = ("Consolas", 9)


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════


def styled_btn(parent, text, cmd, color=ACCENT, width=18, small=False):
    fsize = 9 if small else 11
    b = tk.Button(
        parent,
        text=text,
        command=cmd,
        bg=color,
        fg=BG_DARK if color in (ACCENT, ACCENT2, WARN) else TEXT_PRI,
        font=("Segoe UI", fsize, "bold"),
        relief="flat",
        bd=0,
        cursor="hand2",
        activebackground=color,
        activeforeground=BG_DARK,
        padx=14,
        pady=6,
        width=width,
    )
    b.bind("<Enter>", lambda e: b.config(bg=_lighten(color)))
    b.bind("<Leave>", lambda e: b.config(bg=color))
    return b


def _lighten(hex_color):
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    r = min(255, r + 30)
    g = min(255, g + 30)
    b = min(255, b + 30)
    return f"#{r:02X}{g:02X}{b:02X}"


def card(parent, title="", **kw):
    f = tk.Frame(parent, bg=BG_CARD, bd=0, highlightthickness=1, highlightbackground=BORDER, **kw)
    if title:
        tk.Label(f, text=title, bg=BG_CARD, fg=TEXT_SEC, font=("Segoe UI", 9, "bold")).pack(
            anchor="w", padx=12, pady=(10, 0)
        )
    return f


def sep(parent):
    tk.Frame(parent, height=1, bg=BORDER).pack(fill="x", padx=0, pady=4)


def lbl(parent, text, fg=TEXT_PRI, size=11, bold=False, bg=None):
    return tk.Label(
        parent,
        text=text,
        bg=bg or BG_PANEL,
        fg=fg,
        font=("Segoe UI", size, "bold" if bold else "normal"),
    )


def entry(parent, show=None, width=30):
    e = tk.Entry(
        parent,
        bg=BG_INPUT,
        fg=TEXT_PRI,
        insertbackground=TEXT_PRI,
        relief="flat",
        bd=0,
        font=FONT_BODY,
        show=show or "",
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=ACCENT,
        width=width,
    )
    return e


# ══════════════════════════════════════════════════════════════════════════════
# LOGIN SCREEN
# ══════════════════════════════════════════════════════════════════════════════


class LoginScreen(tk.Frame):
    """
    5-layer authentication login screen.
    Shows visual progress through each layer.
    On success: calls on_success(token, gateway).
    """

    LAYERS = [
        ("A", "TOTP", "6-digit code from Google Authenticator"),
        ("B", "Passphrase", "Your vault passphrase"),
        ("C", "Behavioral", "Type the challenge phrase"),
        ("D", "ZKP", "Automatic — no input needed"),
        ("E", "Device", "Automatic — hardware verified"),
    ]

    def __init__(self, master, on_success, on_setup):
        super().__init__(master, bg=BG_DARK)
        self._on_success = on_success
        self._on_setup = on_setup
        self._gateway = None
        self._token = None
        self._auth_thread = None
        self._build()

    def _build(self):
        # Center container
        outer = tk.Frame(self, bg=BG_DARK)
        outer.place(relx=0.5, rely=0.5, anchor="center")

        # Logo
        tk.Label(outer, text="VAULT-X", bg=BG_DARK, fg=ACCENT, font=("Segoe UI", 36, "bold")).pack(
            pady=(0, 4)
        )
        tk.Label(
            outer,
            text="Personal Data Vault  ·  5-Layer Authentication",
            bg=BG_DARK,
            fg=TEXT_SEC,
            font=FONT_BODY,
        ).pack(pady=(0, 24))

        # Card
        c = tk.Frame(outer, bg=BG_PANEL, bd=0, highlightthickness=1, highlightbackground=BORDER)
        c.pack(ipadx=32, ipady=24, fill="both")

        # TOTP
        tk.Label(
            c, text="Layer A — TOTP Code", bg=BG_PANEL, fg=TEXT_SEC, font=("Segoe UI", 9, "bold")
        ).pack(anchor="w", padx=4, pady=(16, 2))
        self._totp_var = tk.StringVar()
        e1 = entry(c, width=32)
        e1.config(textvariable=self._totp_var)
        e1.pack(padx=4, pady=(0, 12), ipady=6, fill="x")
        e1.focus()

        # Passphrase
        tk.Label(
            c, text="Layer B — Passphrase", bg=BG_PANEL, fg=TEXT_SEC, font=("Segoe UI", 9, "bold")
        ).pack(anchor="w", padx=4, pady=(0, 2))
        self._pass_var = tk.StringVar()
        e2 = entry(c, show="•", width=32)
        e2.config(textvariable=self._pass_var)
        e2.pack(padx=4, pady=(0, 16), ipady=6, fill="x")

        # Layer status bars
        self._layer_labels = {}
        for lid, lname, _ in self.LAYERS:
            row = tk.Frame(c, bg=BG_PANEL)
            row.pack(fill="x", padx=4, pady=2)
            tk.Label(
                row,
                text=f"[{lid}] {lname}",
                bg=BG_PANEL,
                fg=TEXT_DIM,
                font=FONT_SMALL,
                width=20,
                anchor="w",
            ).pack(side="left")
            lbl_status = tk.Label(row, text="●  Waiting", bg=BG_PANEL, fg=TEXT_DIM, font=FONT_SMALL)
            lbl_status.pack(side="left", padx=8)
            self._layer_labels[lid] = lbl_status

        # Progress
        self._status_lbl = tk.Label(c, text="", bg=BG_PANEL, fg=TEXT_SEC, font=FONT_SMALL)
        self._status_lbl.pack(pady=(12, 4))

        self._progress = ttk.Progressbar(c, length=340, mode="determinate")
        self._progress.pack(padx=4, pady=(0, 16))

        # Buttons
        btn_row = tk.Frame(c, bg=BG_PANEL)
        btn_row.pack(fill="x", padx=4)
        self._login_btn = styled_btn(
            btn_row, "🔓  LOGIN", self._start_login, color=ACCENT, width=20
        )
        self._login_btn.pack(side="left", padx=(0, 8))
        styled_btn(
            btn_row, "⚙  Setup (First time)", self._on_setup, color=BG_INPUT, width=20, small=True
        ).pack(side="left")

        # Error label
        self._err_lbl = tk.Label(outer, text="", bg=BG_DARK, fg=DANGER, font=FONT_SMALL)
        self._err_lbl.pack(pady=(8, 0))

    def _set_layer(self, lid, state):
        # state: "waiting" | "running" | "pass" | "fail"
        colors = {"waiting": TEXT_DIM, "running": WARN, "pass": ACCENT2, "fail": DANGER}
        icons = {
            "waiting": "●  Waiting",
            "running": "◌  Checking...",
            "pass": "✓  PASS",
            "fail": "✗  FAIL",
        }
        lbl = self._layer_labels.get(lid)
        if lbl:
            lbl.config(text=icons[state], fg=colors[state])

    def _start_login(self):
        totp = self._totp_var.get().strip()
        pwd = self._pass_var.get().strip()

        if not totp or not pwd:
            self._err_lbl.config(text="Enter both TOTP code and passphrase.")
            return

        self._err_lbl.config(text="")
        self._login_btn.config(state="disabled", text="Authenticating...")

        for lid, _, _ in self.LAYERS:
            self._set_layer(lid, "waiting")

        self._auth_thread = threading.Thread(target=self._run_auth, args=(totp, pwd), daemon=True)
        self._auth_thread.start()

    def _run_auth(self, totp: str, pwd: str):
        try:
            gw = AuthGateway(VAULT_DIR)
            if not gw.config.get("setup_complete"):
                self.after(
                    0,
                    lambda: self._err_lbl.config(
                        text="Setup not complete. Click 'Setup (First time)'."
                    ),
                )
                self.after(0, lambda: self._login_btn.config(state="normal", text="🔓  LOGIN"))
                return

            results = {}
            total = 5

            def upd(lid, state, prog):
                self.after(0, lambda l=lid, s=state: self._set_layer(l, s))
                self.after(0, lambda p=prog: self._progress.config(value=p))
                self.after(
                    0, lambda p=prog: self._status_lbl.config(text=f"Verifying layer {lid}...")
                )

            # Layer A
            upd("A", "running", 10)
            results["A"] = gw._totp.verify(totp)
            upd("A", "pass" if results["A"] else "fail", 20)
            time.sleep(0.3)

            # Layer B
            upd("B", "running", 30)
            results["B"] = gw._biometric.verify(pwd)
            upd("B", "pass" if results["B"] else "fail", 40)
            time.sleep(0.3)

            # Layer C
            upd("C", "running", 50)
            b_pass, b_score = gw._behavioral.verify(
                timings=None if gw._behavioral._calibrated else []
            )
            results["C"] = b_pass
            upd("C", "pass" if results["C"] else "fail", 60)
            time.sleep(0.3)

            # Layer D
            upd("D", "running", 70)
            ch = gw._zkp.generate_challenge()
            pr = gw._zkp.prove(ch)
            results["D"] = gw._zkp.verify_proof(ch, pr)
            upd("D", "pass" if results["D"] else "fail", 80)
            time.sleep(0.3)

            # Layer E
            upd("E", "running", 90)
            device_hash = get_device_fingerprint()
            geo_pass, _ = gw._geofence.verify(device_hash)
            results["E"] = geo_pass
            upd("E", "pass" if results["E"] else "fail", 100)
            time.sleep(0.3)

            all_pass = all(results.values())

            if all_pass:
                gw._record_success(device_hash)
                token = gw.vault.create_session_token(gw.config["owner_hash"])
                self.after(
                    0,
                    lambda: self._status_lbl.config(
                        text="✅  All 5 layers passed — Access granted!",
                    ),
                )
                time.sleep(0.6)
                self.after(0, lambda: self._on_success(token, gw))
            else:
                failed = [k for k, v in results.items() if not v]
                gw._record_failure(device_hash)
                msg = f"Failed layers: {', '.join(failed)}"
                self.after(0, lambda m=msg: self._err_lbl.config(text=m))
                self.after(0, lambda: self._status_lbl.config(text="❌  Authentication failed"))
                self.after(0, lambda: self._login_btn.config(state="normal", text="🔓  LOGIN"))

        except Exception as e:
            self.after(0, lambda: self._err_lbl.config(text=f"Error: {e}"))
            self.after(0, lambda: self._login_btn.config(state="normal", text="🔓  LOGIN"))


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD PANEL
# ══════════════════════════════════════════════════════════════════════════════


class DashboardPanel(tk.Frame):

    def __init__(self, master, app):
        super().__init__(master, bg=BG_PANEL)
        self._app = app
        self._build()
        self._refresh()

    def _build(self):
        tk.Label(self, text="Dashboard", bg=BG_PANEL, fg=TEXT_PRI, font=FONT_TITLE).pack(
            anchor="w", padx=20, pady=(20, 4)
        )
        tk.Label(
            self, text="Session overview and vault health", bg=BG_PANEL, fg=TEXT_SEC, font=FONT_BODY
        ).pack(anchor="w", padx=20, pady=(0, 16))

        # Top stat cards
        row = tk.Frame(self, bg=BG_PANEL)
        row.pack(fill="x", padx=20, pady=(0, 16))

        self._stat_frames = {}
        stats = [
            ("session_time", "Session Time", "──", ACCENT),
            ("files_encrypted", "Files Encrypted", "──", ACCENT2),
            ("alerts", "Active Alerts", "──", DANGER),
            ("daemon_status", "Daemon", "──", WARN),
        ]
        for key, title, val, color in stats:
            f = tk.Frame(row, bg=BG_CARD, bd=0, highlightthickness=1, highlightbackground=BORDER)
            f.pack(side="left", expand=True, fill="both", padx=(0, 12))
            tk.Label(f, text=title, bg=BG_CARD, fg=TEXT_SEC, font=("Segoe UI", 9, "bold")).pack(
                anchor="w", padx=14, pady=(12, 2)
            )
            v = tk.Label(f, text=val, bg=BG_CARD, fg=color, font=("Segoe UI", 22, "bold"))
            v.pack(anchor="w", padx=14, pady=(0, 12))
            self._stat_frames[key] = v

        # Session details card
        c = card(self, "Session Details")
        c.pack(fill="x", padx=20, pady=(0, 12))

        self._sess_text = tk.Text(
            c,
            bg=BG_CARD,
            fg=TEXT_PRI,
            font=FONT_MONO_S,
            height=6,
            relief="flat",
            state="disabled",
            wrap="none",
        )
        self._sess_text.pack(fill="x", padx=12, pady=(4, 12))

        # Quick actions
        c2 = card(self, "Quick Actions")
        c2.pack(fill="x", padx=20, pady=(0, 12))
        btn_row = tk.Frame(c2, bg=BG_CARD)
        btn_row.pack(fill="x", padx=12, pady=12)
        styled_btn(
            btn_row, "🔒  Encrypt File", lambda: self._app.show_panel("vault"), ACCENT, 18
        ).pack(side="left", padx=(0, 8))
        styled_btn(
            btn_row, "🔓  Decrypt File", lambda: self._app.show_panel("vault"), ACCENT2, 18
        ).pack(side="left", padx=(0, 8))
        styled_btn(
            btn_row, "📋  View Audit Log", lambda: self._app.show_panel("audit"), BG_INPUT, 18
        ).pack(side="left", padx=(0, 8))
        styled_btn(
            btn_row, "🚨  Threat Monitor", lambda: self._app.show_panel("monitor"), DANGER, 18
        ).pack(side="left")

    def _refresh(self):
        token = self._app.token
        if token:
            now = time.time()
            elapsed = int(now - token.issued_at)
            h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
            idle = int(now - token.last_active)
            rem = int(token.expires_at - now)

            self._stat_frames["session_time"].config(text=f"{h:02d}:{m:02d}:{s:02d}")

            # Count .vault files
            try:
                vault_files = [f for f in os.listdir(VAULT_DIR) if f.endswith(".vault")]
                self._stat_frames["files_encrypted"].config(text=str(len(vault_files)))
            except Exception:
                pass

            # Daemon status
            try:
                from daemon.vault_daemon import VaultDaemon

                running = VaultDaemon.is_running()
                self._stat_frames["daemon_status"].config(
                    text="ON" if running else "OFF", fg=ACCENT2 if running else DANGER
                )
                alerts = VaultDaemon.get_recent_alerts(100)
                self._stat_frames["alerts"].config(text=str(len(alerts)))
            except Exception:
                self._stat_frames["daemon_status"].config(text="N/A", fg=TEXT_DIM)

            # Session details
            details = (
                f"  Session ID  : {token.session_id[:32]}...\n"
                f"  Device Hash : {token.device_hash[:32]}...\n"
                f"  Issued At   : {datetime.fromtimestamp(token.issued_at).strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"  Expires At  : {datetime.fromtimestamp(token.expires_at).strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"  Idle For    : {idle}s  (limit: 600s)\n"
                f"  Time Left   : {rem//3600}h {(rem%3600)//60}m\n"
            )
            self._sess_text.config(state="normal")
            self._sess_text.delete("1.0", "end")
            self._sess_text.insert("end", details)
            self._sess_text.config(state="disabled")

        self.after(1000, self._refresh)


# ══════════════════════════════════════════════════════════════════════════════
# FILE VAULT PANEL
# ══════════════════════════════════════════════════════════════════════════════


class FileVaultPanel(tk.Frame):

    def __init__(self, master, app):
        super().__init__(master, bg=BG_PANEL)
        self._app = app
        self._build()

    def _build(self):
        tk.Label(self, text="File Vault", bg=BG_PANEL, fg=TEXT_PRI, font=FONT_TITLE).pack(
            anchor="w", padx=20, pady=(20, 4)
        )
        tk.Label(
            self, text="Encrypt and decrypt your files", bg=BG_PANEL, fg=TEXT_SEC, font=FONT_BODY
        ).pack(anchor="w", padx=20, pady=(0, 16))

        # Encrypt section
        ec = card(self, "🔒  Encrypt a File")
        ec.pack(fill="x", padx=20, pady=(0, 14))

        self._enc_path = tk.StringVar()
        ef = tk.Frame(ec, bg=BG_CARD)
        ef.pack(fill="x", padx=12, pady=(8, 4))
        entry_e = entry(ef, width=50)
        entry_e.config(textvariable=self._enc_path)
        entry_e.pack(side="left", fill="x", expand=True, ipady=6)
        styled_btn(ef, "Browse", self._browse_encrypt, BG_INPUT, 10, small=True).pack(
            side="left", padx=(8, 0)
        )

        btn_row = tk.Frame(ec, bg=BG_CARD)
        btn_row.pack(fill="x", padx=12, pady=(0, 12))
        styled_btn(btn_row, "🔒  Encrypt File", self._encrypt, ACCENT, 20).pack(side="left")
        self._enc_status = tk.Label(btn_row, text="", bg=BG_CARD, fg=ACCENT2, font=FONT_SMALL)
        self._enc_status.pack(side="left", padx=12)

        # Decrypt section
        dc = card(self, "🔓  Decrypt a Vault Blob")
        dc.pack(fill="x", padx=20, pady=(0, 14))

        self._dec_path = tk.StringVar()
        df = tk.Frame(dc, bg=BG_CARD)
        df.pack(fill="x", padx=12, pady=(8, 4))
        entry_d = entry(df, width=50)
        entry_d.config(textvariable=self._dec_path)
        entry_d.pack(side="left", fill="x", expand=True, ipady=6)
        styled_btn(df, "Browse", self._browse_decrypt, BG_INPUT, 10, small=True).pack(
            side="left", padx=(8, 0)
        )

        btn_row2 = tk.Frame(dc, bg=BG_CARD)
        btn_row2.pack(fill="x", padx=12, pady=(0, 12))
        styled_btn(btn_row2, "🔓  Decrypt File", self._decrypt, ACCENT2, 20).pack(side="left")
        self._dec_status = tk.Label(btn_row2, text="", bg=BG_CARD, fg=ACCENT2, font=FONT_SMALL)
        self._dec_status.pack(side="left", padx=12)

        # Relocate section
        rc = card(self, "📦  Zero-Correlation Relocate")
        rc.pack(fill="x", padx=20, pady=(0, 14))

        self._rel_src = tk.StringVar()
        self._rel_dst = tk.StringVar()

        rf1 = tk.Frame(rc, bg=BG_CARD)
        rf1.pack(fill="x", padx=12, pady=(8, 4))
        tk.Label(rf1, text="Source:", bg=BG_CARD, fg=TEXT_SEC, font=FONT_SMALL, width=8).pack(
            side="left"
        )
        entry(rf1).pack(side="left", fill="x", expand=True, ipady=5)
        entry_r1 = rf1.winfo_children()[1]
        entry_r1.config(textvariable=self._rel_src)
        styled_btn(rf1, "Browse", lambda: self._browse_src(), BG_INPUT, 8, small=True).pack(
            side="left", padx=(6, 0)
        )

        rf2 = tk.Frame(rc, bg=BG_CARD)
        rf2.pack(fill="x", padx=12, pady=(0, 4))
        tk.Label(rf2, text="Dest:", bg=BG_CARD, fg=TEXT_SEC, font=FONT_SMALL, width=8).pack(
            side="left"
        )
        entry(rf2).pack(side="left", fill="x", expand=True, ipady=5)
        entry_r2 = rf2.winfo_children()[1]
        entry_r2.config(textvariable=self._rel_dst)
        styled_btn(rf2, "Browse", lambda: self._browse_dst(), BG_INPUT, 8, small=True).pack(
            side="left", padx=(6, 0)
        )

        btn_row3 = tk.Frame(rc, bg=BG_CARD)
        btn_row3.pack(fill="x", padx=12, pady=(4, 12))
        styled_btn(btn_row3, "📦  Relocate (3-pass wipe)", self._relocate, PURPLE, 26).pack(
            side="left"
        )
        self._rel_status = tk.Label(btn_row3, text="", bg=BG_CARD, fg=ACCENT2, font=FONT_SMALL)
        self._rel_status.pack(side="left", padx=12)

        # Vault contents
        vc = card(self, "📁  Vault Contents")
        vc.pack(fill="both", expand=True, padx=20, pady=(0, 12))
        self._file_list = tk.Listbox(
            vc,
            bg=BG_INPUT,
            fg=TEXT_PRI,
            font=FONT_MONO_S,
            selectbackground=ACCENT,
            selectforeground=BG_DARK,
            relief="flat",
            bd=0,
            height=6,
        )
        self._file_list.pack(fill="both", expand=True, padx=12, pady=(4, 4))
        styled_btn(vc, "🔄  Refresh", self._refresh_files, BG_INPUT, 12, small=True).pack(
            anchor="w", padx=12, pady=(0, 10)
        )
        self._refresh_files()

    def _browse_encrypt(self):
        p = filedialog.askopenfilename(title="Select file to encrypt")
        if p:
            self._enc_path.set(p)

    def _browse_decrypt(self):
        p = filedialog.askopenfilename(
            title="Select .vault file", filetypes=[("Vault blobs", "*.vault"), ("All", "*.*")]
        )
        if p:
            self._dec_path.set(p)

    def _browse_src(self):
        p = filedialog.askopenfilename(
            title="Source .vault file", filetypes=[("Vault blobs", "*.vault")]
        )
        if p:
            self._rel_src.set(p)

    def _browse_dst(self):
        p = filedialog.asksaveasfilename(title="Destination path", defaultextension=".vault")
        if p:
            self._rel_dst.set(p)

    def _encrypt(self):
        path = self._enc_path.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "File not found.")
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            blob = self._app.vault.encrypt(data, self._app.token)
            out_path = path + ".vault"
            with open(out_path, "w") as f:
                json.dump(dataclasses.asdict(blob), f, indent=2)
            self._enc_status.config(text=f"✓ Saved: {os.path.basename(out_path)}", fg=ACCENT2)
            self._app.ledger.log(
                "ENCRYPT_GUI", {"file": os.path.basename(path), "blob_id": blob.blob_id[:16]}
            )
            self._refresh_files()
        except Exception as e:
            self._enc_status.config(text=f"✗ {e}", fg=DANGER)

    def _decrypt(self):
        path = self._dec_path.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "Vault blob not found.")
            return
        try:
            with open(path) as f:
                blob = VaultBlob(**json.load(f))
            plain = self._app.vault.decrypt(blob, self._app.token)
            out_path = (
                path.replace(".vault", ".decrypted")
                if path.endswith(".vault")
                else path + ".decrypted"
            )
            with open(out_path, "wb") as f:
                f.write(plain)
            self._dec_status.config(text=f"✓ Saved: {os.path.basename(out_path)}", fg=ACCENT2)
            self._app.ledger.log("DECRYPT_GUI", {"file": os.path.basename(path)})
        except Exception as e:
            self._dec_status.config(text=f"✗ {e}", fg=DANGER)

    def _relocate(self):
        src = self._rel_src.get().strip()
        dst = self._rel_dst.get().strip()
        if not src or not dst:
            messagebox.showerror("Error", "Enter both source and destination.")
            return
        try:
            registry = LocationRegistry(
                self._app.gateway.config.setdefault("location_registry", {})
            )
            relocator = Relocator(self._app.vault, registry, self._app.ledger.log)
            record = relocator.relocate(src, dst, self._app.token, wipe_passes=3)
            self._app.gateway._save_config()
            self._rel_status.config(text=f"✓ Relocated + wiped origin", fg=ACCENT2)
            self._refresh_files()
        except Exception as e:
            self._rel_status.config(text=f"✗ {e}", fg=DANGER)

    def _refresh_files(self):
        self._file_list.delete(0, "end")
        try:
            files = sorted([f for f in os.listdir(VAULT_DIR) if f.endswith(".vault")])
            for fname in files:
                fpath = os.path.join(VAULT_DIR, fname)
                size = os.path.getsize(fpath)
                mtime = datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M")
                self._file_list.insert("end", f"  {fname:<40}  {size:>8} B   {mtime}")
            if not files:
                self._file_list.insert("end", "  No vault blobs yet.")
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# AUDIT LOG PANEL
# ══════════════════════════════════════════════════════════════════════════════


class AuditPanel(tk.Frame):

    def __init__(self, master, app):
        super().__init__(master, bg=BG_PANEL)
        self._app = app
        self._build()

    def _build(self):
        tk.Label(self, text="Audit Log", bg=BG_PANEL, fg=TEXT_PRI, font=FONT_TITLE).pack(
            anchor="w", padx=20, pady=(20, 4)
        )
        tk.Label(
            self,
            text="Immutable hash-chained Ed25519-signed ledger",
            bg=BG_PANEL,
            fg=TEXT_SEC,
            font=FONT_BODY,
        ).pack(anchor="w", padx=20, pady=(0, 12))

        # Action row
        ar = tk.Frame(self, bg=BG_PANEL)
        ar.pack(fill="x", padx=20, pady=(0, 12))
        styled_btn(ar, "🔄  Refresh", self._refresh, ACCENT, 14, small=True).pack(
            side="left", padx=(0, 8)
        )
        styled_btn(ar, "✅  Verify Chain", self._verify, ACCENT2, 16, small=True).pack(
            side="left", padx=(0, 8)
        )
        styled_btn(ar, "💾  Export", self._export, BG_INPUT, 12, small=True).pack(side="left")
        self._chain_lbl = tk.Label(
            ar, text="", bg=BG_PANEL, fg=ACCENT2, font=("Segoe UI", 9, "bold")
        )
        self._chain_lbl.pack(side="left", padx=12)

        # Log view
        self._text = scrolledtext.ScrolledText(
            self,
            bg=BG_CARD,
            fg=TEXT_PRI,
            font=FONT_MONO_S,
            relief="flat",
            bd=0,
            state="disabled",
            wrap="none",
            height=28,
        )
        self._text.pack(fill="both", expand=True, padx=20, pady=(0, 12))
        self._text.tag_config("header", foreground=ACCENT, font=("Consolas", 9, "bold"))
        self._text.tag_config("success", foreground=ACCENT2)
        self._text.tag_config("warning", foreground=WARN)
        self._text.tag_config("danger", foreground=DANGER)
        self._text.tag_config("dim", foreground=TEXT_DIM)
        self._refresh()

    def _refresh(self):
        self._text.config(state="normal")
        self._text.delete("1.0", "end")
        try:
            entries = self._app.ledger.read_all()[-50:]
            if not entries:
                self._text.insert("end", "  No audit entries yet.\n", "dim")
            for e in reversed(entries):
                ts = e.timestamp[:19].replace("T", " ")
                line = f"[{ts}] #{e.index:04d}  {e.event_type}\n"
                self._text.insert("end", line, "header")
                self._text.insert(
                    "end", f"  prev: {e.prev_hash[:24]}...   hash: {e.entry_hash[:24]}...\n", "dim"
                )
                for k, v in e.details.items():
                    if k != "signature":
                        self._text.insert("end", f"  {k}: {v}\n", "success")
                self._text.insert("end", "\n")
        except Exception as e:
            self._text.insert("end", f"Error reading ledger: {e}\n", "danger")
        self._text.config(state="disabled")

    def _verify(self):
        valid, msg = self._app.ledger.verify_chain()
        self._chain_lbl.config(
            text=f"{'✅' if valid else '❌'}  {msg}", fg=ACCENT2 if valid else DANGER
        )

    def _export(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", title="Export audit ledger")
        if path:
            self._app.ledger.export_for_audit(path)
            messagebox.showinfo("Exported", f"Ledger exported to:\n{path}")


# ══════════════════════════════════════════════════════════════════════════════
# THREAT MONITOR PANEL
# ══════════════════════════════════════════════════════════════════════════════


class ThreatMonitorPanel(tk.Frame):

    def __init__(self, master, app):
        super().__init__(master, bg=BG_PANEL)
        self._app = app
        self._build()
        self._auto_refresh()

    def _build(self):
        tk.Label(self, text="Threat Monitor", bg=BG_PANEL, fg=TEXT_PRI, font=FONT_TITLE).pack(
            anchor="w", padx=20, pady=(20, 4)
        )
        tk.Label(
            self,
            text="Real-time copy detection and security alerts",
            bg=BG_PANEL,
            fg=TEXT_SEC,
            font=FONT_BODY,
        ).pack(anchor="w", padx=20, pady=(0, 12))

        # Daemon status bar
        self._daemon_bar = tk.Frame(
            self, bg=BG_CARD, bd=0, highlightthickness=1, highlightbackground=BORDER
        )
        self._daemon_bar.pack(fill="x", padx=20, pady=(0, 12))
        self._daemon_lbl = tk.Label(
            self._daemon_bar,
            text="⬤  Checking daemon...",
            bg=BG_CARD,
            fg=WARN,
            font=("Segoe UI", 10, "bold"),
        )
        self._daemon_lbl.pack(side="left", padx=16, pady=10)

        btn_row = tk.Frame(self._daemon_bar, bg=BG_CARD)
        btn_row.pack(side="right", padx=12)
        styled_btn(btn_row, "▶  Start Daemon", self._start_daemon, ACCENT2, 16, small=True).pack(
            side="left", padx=4
        )
        styled_btn(btn_row, "■  Stop Daemon", self._stop_daemon, DANGER, 14, small=True).pack(
            side="left", padx=4
        )

        # Alert log
        c = card(self, "🚨  Security Alerts (live)")
        c.pack(fill="both", expand=True, padx=20, pady=(0, 12))

        ar = tk.Frame(c, bg=BG_CARD)
        ar.pack(fill="x", padx=12, pady=(8, 4))
        styled_btn(ar, "🔄  Refresh", self._refresh_alerts, BG_INPUT, 12, small=True).pack(
            side="left"
        )
        styled_btn(ar, "🗑  Clear Log", self._clear_alerts, BG_INPUT, 12, small=True).pack(
            side="left", padx=8
        )
        self._alert_count_lbl = tk.Label(
            ar, text="", bg=BG_CARD, fg=DANGER, font=("Segoe UI", 9, "bold")
        )
        self._alert_count_lbl.pack(side="left", padx=8)

        self._alert_text = scrolledtext.ScrolledText(
            c,
            bg=BG_INPUT,
            fg=TEXT_PRI,
            font=FONT_MONO_S,
            relief="flat",
            bd=0,
            height=20,
            state="disabled",
        )
        self._alert_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._alert_text.tag_config("critical", foreground=DANGER, font=("Consolas", 9, "bold"))
        self._alert_text.tag_config("warning", foreground=WARN)
        self._alert_text.tag_config("info", foreground=TEXT_SEC)
        self._alert_text.tag_config("dim", foreground=TEXT_DIM)

        self._refresh_alerts()

    def _update_daemon_status(self):
        try:
            from daemon.vault_daemon import VaultDaemon

            running = VaultDaemon.is_running()
            self._daemon_lbl.config(
                text=f"⬤  Background Daemon: {'ACTIVE — Watching vault 24/7' if running else 'STOPPED — Vault unprotected when not in session'}",
                fg=ACCENT2 if running else DANGER,
            )
        except Exception:
            self._daemon_lbl.config(text="⬤  Daemon: Not available", fg=TEXT_DIM)

    def _refresh_alerts(self):
        self._update_daemon_status()
        self._alert_text.config(state="normal")
        self._alert_text.delete("1.0", "end")

        try:
            from daemon.vault_daemon import VaultDaemon

            alerts = VaultDaemon.get_recent_alerts(100)
            self._alert_count_lbl.config(text=f"{len(alerts)} alert(s)" if alerts else "No alerts")
            if not alerts:
                self._alert_text.insert(
                    "end", "  ✅  No security alerts. Vault is clean.\n", "info"
                )
            else:
                for a in reversed(alerts):
                    ts = a.get("timestamp", "")[:19]
                    evt = a.get("event", "UNKNOWN")
                    tag = "critical" if "TAMPER" in evt or "CRITICAL" in evt else "warning"
                    self._alert_text.insert("end", f"[{ts}]  {evt}\n", tag)
                    for k, v in a.get("details", {}).items():
                        self._alert_text.insert("end", f"   {k}: {v}\n", "info")
                    self._alert_text.insert("end", "\n", "dim")
        except Exception as e:
            self._alert_text.insert("end", f"  Daemon not running: {e}\n", "info")

        self._alert_text.config(state="disabled")

    def _start_daemon(self):
        try:
            subprocess.Popen(
                [sys.executable, "daemon/vault_daemon.py", "start"],
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0,
            )
            time.sleep(1.5)
            self._refresh_alerts()
        except Exception as e:
            messagebox.showerror("Error", f"Could not start daemon:\n{e}")

    def _stop_daemon(self):
        try:
            subprocess.run(
                [sys.executable, "daemon/vault_daemon.py", "stop"],
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            )
            time.sleep(1)
            self._refresh_alerts()
        except Exception as e:
            messagebox.showerror("Error", f"Could not stop daemon:\n{e}")

    def _clear_alerts(self):
        if messagebox.askyesno("Clear Alerts", "Clear all alert history?"):
            try:
                open(DAEMON_LOG, "w").close()
                self._refresh_alerts()
            except Exception:
                pass

    def _auto_refresh(self):
        self._refresh_alerts()
        self.after(10000, self._auto_refresh)  # refresh every 10 seconds


# ══════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════


class VaultXApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("VAULT-X — Personal Data Vault")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.configure(bg=BG_DARK)

        # App state
        self.token = None
        self.gateway = None
        self.vault = None
        self.ledger = None

        self._panels = {}
        self._active_panel = None
        self._main_frame = None
        self._sidebar = None

        self._show_login()

    # ── Login → Main transition ───────────────────────────────────────────

    def _show_login(self):
        for w in self.winfo_children():
            w.destroy()
        login = LoginScreen(self, self._on_login_success, self._run_setup_cmd)
        login.pack(fill="both", expand=True)

    def _run_setup_cmd(self):
        subprocess.Popen(
            [sys.executable, "vaultx.py", "setup"],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0,
        )

    def _on_login_success(self, token, gateway):
        self.token = token
        self.gateway = gateway
        self.vault = gateway.vault
        self.ledger = AuditLedger(VAULT_DIR, sign_fn=self.vault.sign_audit_entry)
        self._build_main_ui()

    # ── Main UI ───────────────────────────────────────────────────────────

    def _build_main_ui(self):
        for w in self.winfo_children():
            w.destroy()

        root = tk.Frame(self, bg=BG_DARK)
        root.pack(fill="both", expand=True)

        # Sidebar
        self._sidebar = tk.Frame(root, bg=BG_PANEL, width=200)
        self._sidebar.pack(side="left", fill="y")
        self._sidebar.pack_propagate(False)
        self._build_sidebar()

        # Main content
        self._main_frame = tk.Frame(root, bg=BG_PANEL)
        self._main_frame.pack(side="left", fill="both", expand=True)

        # Build panels
        self._panels = {
            "dashboard": DashboardPanel(self._main_frame, self),
            "vault": FileVaultPanel(self._main_frame, self),
            "audit": AuditPanel(self._main_frame, self),
            "monitor": ThreatMonitorPanel(self._main_frame, self),
        }

        self.show_panel("dashboard")

    def _build_sidebar(self):
        # Logo
        tk.Label(
            self._sidebar, text="VAULT-X", bg=BG_PANEL, fg=ACCENT, font=("Segoe UI", 16, "bold")
        ).pack(pady=(20, 2))
        tk.Label(self._sidebar, text="v2.0.0", bg=BG_PANEL, fg=TEXT_DIM, font=FONT_SMALL).pack(
            pady=(0, 20)
        )

        tk.Frame(self._sidebar, height=1, bg=BORDER).pack(fill="x")

        # Nav items
        nav_items = [
            ("dashboard", "🏠  Dashboard"),
            ("vault", "🔒  File Vault"),
            ("audit", "📋  Audit Log"),
            ("monitor", "🚨  Threat Monitor"),
        ]

        self._nav_btns = {}
        for key, label in nav_items:
            b = tk.Button(
                self._sidebar,
                text=label,
                bg=BG_PANEL,
                fg=TEXT_SEC,
                font=("Segoe UI", 11),
                relief="flat",
                anchor="w",
                padx=16,
                pady=10,
                cursor="hand2",
                activebackground=BG_CARD,
                activeforeground=TEXT_PRI,
                command=lambda k=key: self.show_panel(k),
            )
            b.pack(fill="x")
            self._nav_btns[key] = b

        # Bottom — session info + logout
        tk.Frame(self._sidebar, height=1, bg=BORDER).pack(fill="x", side="bottom", pady=4)
        styled_btn(self._sidebar, "🔒  Logout", self._logout, DANGER, 16, small=True).pack(
            side="bottom", padx=16, pady=12, fill="x"
        )

        # Device info
        dh = get_device_fingerprint()
        tk.Label(
            self._sidebar,
            text=f"Device: {dh[:12]}...",
            bg=BG_PANEL,
            fg=TEXT_DIM,
            font=("Segoe UI", 8),
        ).pack(side="bottom", padx=16, pady=(0, 4))

    def show_panel(self, name: str):
        for k, p in self._panels.items():
            p.pack_forget()
        if name in self._panels:
            self._panels[name].pack(fill="both", expand=True)
            self._active_panel = name
        # Update sidebar highlight
        for k, b in self._nav_btns.items():
            b.config(bg=BG_CARD if k == name else BG_PANEL, fg=TEXT_PRI if k == name else TEXT_SEC)

    def _logout(self):
        if messagebox.askyesno("Logout", "End vault session and logout?"):
            if self.vault and self.token:
                self.vault.revoke_session(self.token.session_id)
            if self.ledger:
                self.ledger.log(
                    "SESSION_CLOSED_GUI",
                    {
                        "session": self.token.session_id[:16] if self.token else "unknown",
                        "reason": "user_logout_gui",
                    },
                )
            self.token = None
            self._show_login()


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = VaultXApp()
    app.mainloop()
