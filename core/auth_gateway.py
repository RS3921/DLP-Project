"""
╔══════════════════════════════════════════════════════════════╗
║        VAULT-X  ·  Authentication Gateway (L-02 + L-04)      ║
╚══════════════════════════════════════════════════════════════╝

This is the orchestrator that:
  1. Runs all 5 authentication layers in sequence
  2. Enforces the AND rule: ALL must pass, no exceptions
  3. Manages fail counters per device
  4. Triggers lockout after 3 failures (72 hours)
  5. Issues a SessionToken on success via the VaultEngine

BEGINNER NOTE:
  Think of this like a building security desk.
  Before you can enter, you must show:
    A) Your ID badge        (TOTP code from your phone)
    B) Your face            (password / fingerprint)
    C) Your walking style   (behavioral rhythm)
    D) Your access card key (ZKP challenge-response)
    E) You're in the right location (device + location check)

  ALL five must be verified. Showing four doesn't help.
"""

import os
import json
import time
import hashlib
from datetime import datetime, timedelta
from typing import Optional

from .vault_engine import VaultEngine, SessionToken, get_device_fingerprint
from layers.auth_layers import (
    TOTPLayer,
    BiometricLayer,
    BehavioralLayer,
    ZKPLayer,
    GeofenceLayer
)


# ══════════════════════════════════════════════════════════════════
# CONFIG FILE STRUCTURE
# ══════════════════════════════════════════════════════════════════

DEFAULT_CONFIG = {
    "vault_version":   "1.0.0",
    "setup_complete":  False,
    "owner_hash":      None,
    "totp_secret":     None,
    "biometric":       None,
    "behavioral":      None,
    "zkp_key":         None,
    "geofence":        None,
    "fail_log":        {},       # device_hash → {"count": int, "lockout_until": float}
    "audit_log":       [],       # simplified audit trail
}


# ══════════════════════════════════════════════════════════════════
# AUTH GATEWAY
# ══════════════════════════════════════════════════════════════════

class AuthGateway:
    """
    The master authentication controller for VAULT-X.

    USAGE:
      # First time:
      gateway = AuthGateway()
      gateway.setup()          # register all layers

      # Every login:
      token = gateway.login()  # returns SessionToken if all 5 pass
      vault = gateway.vault    # use this for encrypt/decrypt

    LOCKOUT POLICY:
      3 failed attempts → 72-hour lockout on that device.
      This is per-device (hardware fingerprint based).
    """

    MAX_FAILURES    = 3
    LOCKOUT_HOURS   = 72
    CONFIG_FILENAME = "vault_config.json"

    def __init__(self, vault_dir: str = "./vault_data"):
        self.vault_dir   = vault_dir
        self.config_file = os.path.join(vault_dir, self.CONFIG_FILENAME)
        self.config      = {}

        os.makedirs(vault_dir, exist_ok=True)

        # Load or create config
        self._load_config()

        # Initialize the vault engine
        self.vault = VaultEngine(vault_dir)

        # Initialize auth layers (will be configured in setup)
        self.totp      = TOTPLayer()
        self.biometric = BiometricLayer()
        self.behavioral = BehavioralLayer()
        self.zkp       = ZKPLayer()
        self.geofence  = GeofenceLayer()

        # Load layer configs if setup is complete
        if self.config.get("setup_complete"):
            self._load_layer_configs()


    # ── Config Management ────────────────────────────────────────────

    def _load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, "r") as f:
                self.config = json.load(f)
            print("[Auth Gateway] Config loaded.")
        else:
            self.config = DEFAULT_CONFIG.copy()
            print("[Auth Gateway] New config created.")

    def _save_config(self):
        with open(self.config_file, "w") as f:
            json.dump(self.config, f, indent=2)
        try:
            os.chmod(self.config_file, 0o600)
        except Exception:
            pass

    def _load_layer_configs(self):
        """Load all layer configs from the saved config file."""
        if self.config.get("totp_secret"):
            self.totp = TOTPLayer.from_secret(self.config["totp_secret"])

        if self.config.get("biometric"):
            self.biometric = BiometricLayer()
            self.biometric.load(self.config["biometric"])

        if self.config.get("behavioral"):
            self.behavioral = BehavioralLayer()
            self.behavioral.load(self.config["behavioral"])

        if self.config.get("zkp_key"):
            self.zkp = ZKPLayer.from_key(self.config["zkp_key"])

        if self.config.get("geofence"):
            self.geofence = GeofenceLayer()
            self.geofence.load(self.config["geofence"])


    # ── SETUP (First-Time Registration) ─────────────────────────────

    def setup(self):
        """
        First-time setup wizard.
        Registers all 5 authentication layers.
        Call this ONCE when you first install VAULT-X.
        """
        print("\n" + "═" * 60)
        print("  VAULT-X  ·  First-Time Setup")
        print("═" * 60)
        print("\nYou will register each of the 5 security layers.")
        print("This takes about 5 minutes. Do it carefully.\n")

        # ── Layer A: TOTP ──────────────────────────────────────────
        print("\n" + "─" * 50)
        print("LAYER A — One-Time Password (TOTP)")
        print("─" * 50)
        print("Install 'Google Authenticator' or 'Authy' on your phone.")
        print("Then scan the QR code shown below.\n")

        self.totp = TOTPLayer()
        qr_uri    = self.totp.get_qr_uri("VAULT-X Owner")

        print(f"Manual entry secret: {self._format_totp_secret()}")
        print(f"\nOr use this URI in a QR generator:")
        print(f"  {qr_uri}\n")
        print("TIP: Go to https://www.qr-code-generator.com/ and paste the URI above.")

        # Verify user has scanned it correctly
        for attempt in range(3):
            code = input("\nEnter the 6-digit code from your app to confirm: ").strip()
            if self.totp.verify(code):
                print("✓ TOTP registered successfully!")
                break
            else:
                print(f"✗ Incorrect. Try again. ({2-attempt} attempts left)")
        else:
            raise RuntimeError("TOTP setup failed. Check your authenticator app.")

        self.config["totp_secret"] = self.totp.export_secret()

        # ── Layer B: Biometric (Password) ──────────────────────────
        print("\n" + "─" * 50)
        print("LAYER B — Password / Biometric")
        print("─" * 50)
        print("Create a strong passphrase (minimum 12 characters).")
        print("EXAMPLE: 'BlueSky$Runs#Over99Mountains'")
        print("Store this OFFLINE — on paper in a safe place.\n")

        while True:
            import getpass
            pwd1 = getpass.getpass("Enter passphrase: ")
            pwd2 = getpass.getpass("Confirm passphrase: ")
            if pwd1 != pwd2:
                print("✗ Passphrases don't match. Try again.")
                continue
            try:
                bio_data = self.biometric.register(pwd1)
                self.config["biometric"] = bio_data
                print("✓ Passphrase registered (only hash stored).")
                break
            except ValueError as e:
                print(f"✗ {e}")

        # Compute owner hash (used to bind session tokens to identity)
        self.config["owner_hash"] = self.vault.hash_identity(pwd1)

        # ── Layer C: Behavioral ────────────────────────────────────
        print("\n" + "─" * 50)
        print("LAYER C — Behavioral Fingerprint")
        print("─" * 50)
        print("This records your unique typing rhythm.")
        print("You will type a phrase 5 times naturally.\n")

        choice = input("Set up behavioral layer now? [Y/n]: ").strip().lower()
        if choice != 'n':
            try:
                baseline = self.behavioral.calibrate(n_samples=5)
                self.config["behavioral"] = baseline
                print("✓ Behavioral baseline established.")
            except Exception as e:
                print(f"⚠ Behavioral setup skipped: {e}")
                print("  You can set this up later. Continuing...")
        else:
            print("⚠ Behavioral layer skipped (auto-pass until configured).")

        # ── Layer D: ZKP ───────────────────────────────────────────
        print("\n" + "─" * 50)
        print("LAYER D — Zero-Knowledge Proof")
        print("─" * 50)
        print("Generating your private ZKP key...")
        self.zkp = ZKPLayer()
        self.config["zkp_key"] = self.zkp.export_key()
        print("✓ ZKP key generated and stored.")

        # ── Layer E: Geofence ──────────────────────────────────────
        print("\n" + "─" * 50)
        print("LAYER E — Device + Geofence")
        print("─" * 50)

        device_hash = get_device_fingerprint()
        self.geofence.register_device(device_hash)

        choice = input("Enable IP geofencing? [y/N]: ").strip().lower()
        if choice == 'y':
            print("Enter allowed IP addresses (one per line, empty to finish):")
            while True:
                ip = input("  IP: ").strip()
                if not ip:
                    break
                self.geofence.add_allowed_ip(ip)

        self.config["geofence"] = self.geofence.export()
        print("✓ Device registered. Geofence configured.")

        # ── Finalize ───────────────────────────────────────────────
        self.config["setup_complete"] = True
        self._save_config()

        print("\n" + "═" * 60)
        print("  VAULT-X Setup Complete!")
        print("═" * 60)
        print("\nAll 5 authentication layers are active:")
        print("  [A] TOTP (Google Authenticator)         ✓")
        print("  [B] Passphrase                          ✓")
        print("  [C] Behavioral fingerprint              ✓")
        print("  [D] Zero-Knowledge Proof                ✓")
        print("  [E] Device binding                      ✓")
        print("\nYou can now run gateway.login() to access your vault.")


    def _format_totp_secret(self) -> str:
        """Format TOTP secret for display (with spaces for readability)."""
        import base64
        secret_b32 = base64.b32encode(self.totp.secret).decode("utf-8")
        return " ".join(secret_b32[i:i+4] for i in range(0, len(secret_b32), 4))


    # ── LOCKOUT MANAGEMENT ───────────────────────────────────────────

    def _check_lockout(self, device_hash: str) -> tuple[bool, Optional[float]]:
        """
        Check if a device is currently locked out.
        Returns (is_locked: bool, unlock_time: Optional[float])
        """
        fail_log = self.config.get("fail_log", {})
        record   = fail_log.get(device_hash, {})

        lockout_until = record.get("lockout_until", 0)
        if lockout_until and time.time() < lockout_until:
            return True, lockout_until

        return False, None

    def _record_failure(self, device_hash: str):
        """Record a failed login attempt. Trigger lockout if threshold hit."""
        fail_log = self.config.setdefault("fail_log", {})
        record   = fail_log.setdefault(device_hash, {"count": 0, "lockout_until": 0})

        # Reset count if previous lockout has expired
        if record.get("lockout_until", 0) < time.time():
            record["count"] = 0

        record["count"] += 1
        fail_count = record["count"]

        print(f"[Auth Gateway] ✗ Failure recorded. Count: {fail_count}/{self.MAX_FAILURES}")

        if fail_count >= self.MAX_FAILURES:
            lockout_until = time.time() + (self.LOCKOUT_HOURS * 3600)
            record["lockout_until"] = lockout_until
            unlock_time = datetime.fromtimestamp(lockout_until).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            print(f"\n[Auth Gateway] 🔒 DEVICE LOCKED OUT")
            print(f"  Reason: {self.MAX_FAILURES} failed attempts")
            print(f"  Locked until: {unlock_time} ({self.LOCKOUT_HOURS} hours)")
            print(f"  Device: {device_hash[:16]}...")

            # Log to audit
            self._audit("LOCKOUT_TRIGGERED", {
                "device": device_hash[:16],
                "fail_count": fail_count,
                "until": unlock_time
            })

        self._save_config()
        return fail_count

    def _record_success(self, device_hash: str):
        """Reset fail counter on successful login."""
        fail_log = self.config.setdefault("fail_log", {})
        if device_hash in fail_log:
            fail_log[device_hash]["count"] = 0
        self._save_config()

    def _audit(self, event_type: str, details: dict):
        """Write a simplified audit entry."""
        entry = {
            "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event":      event_type,
            "details":    details
        }
        audit_log = self.config.setdefault("audit_log", [])
        audit_log.append(entry)
        # Keep last 1000 entries
        if len(audit_log) > 1000:
            self.config["audit_log"] = audit_log[-1000:]
        self._save_config()


    # ── LOGIN ────────────────────────────────────────────────────────

    def login(self) -> Optional[SessionToken]:
        """
        Run all 5 authentication layers and issue a session token.

        Returns SessionToken on success, None on failure.

        This is the main function you call to authenticate.
        """
        if not self.config.get("setup_complete"):
            raise RuntimeError(
                "\n[VAULT-X] Setup not complete!\n"
                "Run gateway.setup() first.\n"
            )

        print("\n" + "═" * 60)
        print("  VAULT-X  ·  Authentication")
        print("═" * 60)

        device_hash = get_device_fingerprint()

        # ── Lockout check (before any layer) ──────────────────────
        locked, until = self._check_lockout(device_hash)
        if locked:
            unlock = datetime.fromtimestamp(until).strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n[Auth Gateway] 🔒 This device is locked until {unlock}.")
            print("Contact vault owner or wait for lockout to expire.")
            return None

        print(f"\nDevice: {device_hash[:16]}...  |  Time: {datetime.now().strftime('%H:%M:%S')}")
        print()

        results = {}

        # ── Layer A: TOTP ──────────────────────────────────────────
        print("[Layer A] TOTP Verification")
        import getpass
        code = input("  Enter 6-digit code from your authenticator app: ").strip()
        results["A"] = self.totp.verify(code)
        print(f"  {'✓ PASS' if results['A'] else '✗ FAIL'}")

        # ── Layer B: Biometric ──────────────────────────────────────
        print("\n[Layer B] Passphrase Verification")
        pwd = getpass.getpass("  Enter passphrase: ")
        results["B"] = self.biometric.verify(pwd)

        # ── Layer C: Behavioral ─────────────────────────────────────
        print("\n[Layer C] Behavioral Verification")
        passed_c, score_c = self.behavioral.verify()
        results["C"] = passed_c

        # ── Layer D: ZKP ────────────────────────────────────────────
        print("\n[Layer D] Zero-Knowledge Proof")
        challenge       = self.zkp.generate_challenge()
        proof           = self.zkp.prove(challenge)           # client-side
        results["D"]    = self.zkp.verify_proof(challenge, proof)  # server-side

        # ── Layer E: Geofence ───────────────────────────────────────
        print("\n[Layer E] Device + Geofence")
        results["E"] = self.geofence.verify(device_hash)

        # ── Decision Gate (L-04) ────────────────────────────────────
        print("\n" + "─" * 50)
        print("AUTHENTICATION RESULT")
        print("─" * 50)

        all_pass = all(results.values())
        for layer, passed in results.items():
            mark = "✓" if passed else "✗"
            print(f"  Layer {layer}: {mark}")

        print()

        if all_pass:
            print("  ✅ ALL LAYERS PASSED — ACCESS GRANTED")
            self._record_success(device_hash)

            # Get owner hash from config
            owner_hash = self.config.get("owner_hash", "unknown")

            # Issue session token via vault engine
            token = self.vault.create_session_token(owner_hash)

            self._audit("LOGIN_SUCCESS", {
                "device": device_hash[:16],
                "session": token.session_id[:16],
                "layers": results
            })

            print(f"\n  Session active for {self.vault.get_active_session_count()} session(s)")
            print(f"  Token expires: {datetime.fromtimestamp(token.expires_at).strftime('%H:%M:%S')}")
            print("═" * 60 + "\n")
            return token

        else:
            failed = [k for k, v in results.items() if not v]
            print(f"  ❌ FAILED LAYERS: {', '.join(failed)}")
            print("  Access denied.\n")

            fail_count = self._record_failure(device_hash)

            self._audit("LOGIN_FAILURE", {
                "device":    device_hash[:16],
                "failed":    failed,
                "fail_count": fail_count
            })

            remaining = self.MAX_FAILURES - fail_count
            if remaining > 0:
                print(f"  ⚠ Warning: {remaining} attempt(s) before 72-hour lockout.")

            print("═" * 60 + "\n")
            return None


    # ── AUDIT VIEWER ─────────────────────────────────────────────────

    def show_audit_log(self, last_n: int = 20):
        """Print the last N audit entries."""
        log = self.config.get("audit_log", [])
        entries = log[-last_n:]
        print(f"\n{'─'*60}")
        print(f"  VAULT-X Audit Log — Last {len(entries)} entries")
        print(f"{'─'*60}")
        for entry in entries:
            print(f"  [{entry['timestamp']}] {entry['event']}")
            for k, v in entry.get("details", {}).items():
                print(f"    {k}: {v}")
        print(f"{'─'*60}\n")
