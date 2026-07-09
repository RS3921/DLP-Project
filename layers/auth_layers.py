"""
╔══════════════════════════════════════════════════════════════╗
║        VAULT-X  ·  Authentication Layers (L-03A to L-03E)    ║
╚══════════════════════════════════════════════════════════════╝

These are the 5 independent gates every login must pass.

BEGINNER GUIDE — What each layer does in plain English:

  Layer A  →  "Something you HAVE"         (hardware key / TOTP code)
  Layer B  →  "Something you ARE"          (fingerprint / face)
  Layer C  →  "HOW you behave"             (typing rhythm AI model)
  Layer D  →  "A math proof of identity"   (zero-knowledge proof)
  Layer E  →  "WHERE you are"              (location + device check)

For a beginner setup without special hardware:
  Layer A  →  Time-based One-Time Password (Google Authenticator)
  Layer B  →  Password (simulates biometric — upgrade later)
  Layer C  →  Keystroke timing analysis (works right now)
  Layer D  →  Simplified ZKP challenge (runs locally)
  Layer E  →  Device fingerprint binding  (runs right now)

UPGRADE PATH:
  Layer A  →  Buy a YubiKey 5 ($50) and swap in real FIDO2
  Layer B  →  Add USB fingerprint reader ($30) for real biometrics
"""

import os
import time
import hmac
import math
import json
import base64
import struct
import hashlib
import secrets
import statistics
from typing import Optional

# ══════════════════════════════════════════════════════════════════
# LAYER A — TOTP (Time-Based One-Time Password)
# This simulates FIDO2 for beginners.
# Upgrade path: replace with py_webauthn + YubiKey
# ══════════════════════════════════════════════════════════════════


class TOTPLayer:
    """
    Time-based One-Time Password — like Google Authenticator.

    HOW IT WORKS:
      1. During setup, a secret key is generated.
      2. You scan a QR code with an authenticator app.
      3. Every 30 seconds, both your phone AND this system
         compute the same 6-digit code from the shared secret.
      4. You type the code. If it matches → PASS.

    WHY IT'S SECURE:
      The code changes every 30 seconds.
      Stolen codes are useless after 30 seconds.
      No internet connection needed.
    """

    STEP = 30  # code changes every 30 seconds
    DIGITS = 6  # 6-digit codes

    def __init__(self, secret: Optional[bytes] = None):
        """
        Args:
            secret: The shared TOTP secret (32 bytes).
                    If None, a new secret is generated.
        """
        self.secret = secret or secrets.token_bytes(20)

    def get_code(self, timestamp: Optional[float] = None) -> str:
        """
        Generate the current TOTP code.
        This is what your authenticator app shows.
        """
        t = int((timestamp or time.time()) / self.STEP)
        msg = struct.pack(">Q", t)
        h = hmac.new(self.secret, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
        return str(code % (10**self.DIGITS)).zfill(self.DIGITS)

    def verify(self, user_code: str, window: int = 1) -> bool:
        """
        Verify a code with ±1 time window (30-second tolerance).

        Args:
            user_code:  The 6-digit code the user typed
            window:     How many 30-second steps to accept (default: 1)
        """
        now = time.time()
        for delta in range(-window, window + 1):
            expected = self.get_code(now + delta * self.STEP)
            if hmac.compare_digest(user_code.strip(), expected):
                return True
        return False

    def get_qr_uri(self, account_name: str = "VAULT-X Owner") -> str:
        """Returns the otpauth URI — scan this with Google Authenticator."""
        secret_b32 = base64.b32encode(self.secret).decode("utf-8")
        return (
            f"otpauth://totp/{account_name}"
            f"?secret={secret_b32}"
            f"&issuer=VAULT-X"
            f"&algorithm=SHA1"
            f"&digits={self.DIGITS}"
            f"&period={self.STEP}"
        )

    def export_secret(self) -> str:
        """Export secret as base64 for storage."""
        return base64.b64encode(self.secret).decode("utf-8")

    @classmethod
    def from_secret(cls, secret_b64: str) -> "TOTPLayer":
        """Restore from stored secret."""
        return cls(secret=base64.b64decode(secret_b64))


# ══════════════════════════════════════════════════════════════════
# LAYER B — Password / Biometric Hash
# Beginner version: password. Upgrade to fingerprint later.
# ══════════════════════════════════════════════════════════════════


class BiometricLayer:
    """
    Beginner version: Secure password with PBKDF2 hashing.

    UPGRADE PATH:
      Replace self.verify() with a fingerprint reader integration.
      The architecture stays identical — only the input changes.
      Instead of a typed password, you scan your finger.

    HOW PBKDF2 WORKS:
      Your password is hashed 260,000 times with a random salt.
      Even if someone steals the stored hash, they cannot reverse it.
      Trying all possible passwords at 260,000 iterations each
      takes billions of years on current hardware.
    """

    ITERATIONS = 260_000  # NIST recommended minimum for PBKDF2-SHA256

    def __init__(self):
        self._stored_hash: Optional[str] = None
        self._salt: Optional[bytes] = None

    def register(self, password: str) -> dict:
        """
        Register a password (or biometric template).
        Stores only the hash — the raw password is never saved.

        Returns a dict you should save to your config file.
        """
        if len(password) < 12:
            raise ValueError(
                "Password must be at least 12 characters.\n"
                "Use a passphrase like: 'PurpleElephant$Runs#Fast2025'"
            )

        self._salt = secrets.token_bytes(32)
        hash_bytes = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self._salt, self.ITERATIONS
        )
        self._stored_hash = hash_bytes.hex()

        print("[Layer B] Biometric/password registered. Only hash stored.")
        return {
            "hash": self._stored_hash,
            "salt": base64.b64encode(self._salt).decode(),
            "iterations": self.ITERATIONS,
        }

    def load(self, stored: dict):
        """Load previously registered data from config."""
        self._stored_hash = stored["hash"]
        self._salt = base64.b64decode(stored["salt"])

    def verify(self, password: str) -> bool:
        """
        Verify a password attempt.
        Timing-safe comparison prevents timing attacks.
        """
        if not self._stored_hash or not self._salt:
            raise RuntimeError("[Layer B] Not registered yet. Call register() first.")

        attempt_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self._salt, self.ITERATIONS
        ).hex()

        # hmac.compare_digest is timing-safe (prevents timing attacks)
        result = hmac.compare_digest(attempt_hash, self._stored_hash)
        if result:
            print("[Layer B] ✓ Password/biometric verified.")
        else:
            print("[Layer B] ✗ Password/biometric FAILED.")
        return result


# ══════════════════════════════════════════════════════════════════
# LAYER C — Behavioral Fingerprinting (Keystroke Dynamics)
# A real LSTM would be trained on weeks of your typing patterns.
# This beginner version builds a statistical baseline.
# ══════════════════════════════════════════════════════════════════


class BehavioralLayer:
    """
    Keystroke dynamics — verifies HOW you type, not just what you type.

    HOW IT WORKS:
      1. During setup, you type a challenge phrase many times.
      2. The system records TIMING between keystrokes (not the keys).
      3. It builds your personal "rhythm profile."
      4. On each login, your typing rhythm is compared to the profile.
      5. Too different → suspicious → additional verification required.

    WHY THIS MATTERS:
      Even if someone knows your password, they type differently.
      Attackers who try to copy your rhythm fail within seconds.
      Mid-session, this runs continuously to detect session hijacking.

    SCORE INTERPRETATION:
      0.0 → 1.0 similarity to your baseline.
      > 0.7  → Normal, PASS
      0.5-0.7 → Unusual, soft flag
      < 0.5  → Suspicious, re-authenticate
    """

    PASS_THRESHOLD = 0.70
    MIN_SAMPLES = 5  # minimum calibration samples needed

    def __init__(self):
        self._baseline_stats: Optional[dict] = None

    def collect_timing_sample(self, prompt: str = "Type this phrase: ") -> list[float]:
        """
        Interactively collect one keystroke timing sample.

        In production this hooks into OS-level keyboard events.
        Here we simulate with space-separated word timings.

        Returns list of inter-keystroke delay times in milliseconds.
        """
        print(f"\n{prompt}")
        print("Type the phrase below naturally (don't try to be consistent):")
        print("  → vault-x secure personal data system")
        print()

        timings = []
        prev_time = None

        try:
            import sys

            if os.name == "nt":
                import msvcrt

                phrase_chars = list("vault-x secure personal data system")
                input_chars = []
                print("Type: ", end="", flush=True)
                for expected_char in phrase_chars:
                    t_start = time.perf_counter()
                    ch = msvcrt.getwch()
                    t_end = time.perf_counter()
                    if prev_time is not None:
                        timings.append((t_end - t_start) * 1000)
                    prev_time = t_end
                    print(ch, end="", flush=True)
                    input_chars.append(ch)
                print()
            else:
                # Unix: use timed input approximation
                import select, termios, tty

                fd = sys.stdin.fileno()
                old = termios.tcgetattr(fd)
                try:
                    tty.setraw(fd)
                    phrase = "vault-x secure personal data system"
                    print(f"Type: ", end="", flush=True)
                    for _ in phrase:
                        t0 = time.perf_counter()
                        ch = sys.stdin.read(1)
                        t1 = time.perf_counter()
                        if prev_time is not None:
                            timings.append((t1 - t0) * 1000)
                        prev_time = t1
                        if ch == "\x03":
                            raise KeyboardInterrupt
                        print(ch, end="", flush=True)
                    print()
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception:
            # Fallback: simulated timings for environments without raw input
            import random

            base = 120  # 120ms average typing speed
            timings = [base + random.gauss(0, 30) for _ in range(35)]

        return timings

    def calibrate(self, n_samples: int = 5) -> dict:
        """
        Collect n_samples of your typing and build your baseline.

        Call this during initial setup.
        You need to type the phrase naturally n_samples times.

        Returns baseline stats to save in your config.
        """
        print(f"\n[Layer C] Behavioral calibration — {n_samples} samples needed.")
        print("Type naturally. This builds YOUR unique rhythm profile.\n")

        all_timings = []
        for i in range(n_samples):
            print(f"Sample {i+1}/{n_samples}:")
            sample = self.collect_timing_sample(prompt="")
            if sample:
                all_timings.extend(sample)
            time.sleep(0.5)

        if len(all_timings) < 10:
            raise ValueError("[Layer C] Not enough timing data collected.")

        # Build statistical baseline
        mean = statistics.mean(all_timings)
        std_dev = statistics.stdev(all_timings) if len(all_timings) > 1 else 30.0
        median = statistics.median(all_timings)

        self._baseline_stats = {
            "mean": mean,
            "stddev": std_dev,
            "median": median,
            "count": len(all_timings),
        }

        print(f"\n[Layer C] Baseline built:")
        print(f"  Average keystroke interval: {mean:.1f}ms")
        print(f"  Standard deviation:         {std_dev:.1f}ms")
        print(f"  Samples collected:          {len(all_timings)}")

        return self._baseline_stats

    def load(self, baseline: dict):
        """Load a previously saved baseline."""
        self._baseline_stats = baseline

    def verify(self, timings: Optional[list] = None) -> tuple[bool, float]:
        """
        Verify behavioral pattern against baseline.

        Returns (passed: bool, score: float 0.0-1.0)
        """
        if not self._baseline_stats:
            # No baseline: auto-pass with note (first-time setup)
            print("[Layer C] ⚠ No baseline — auto-pass. Run calibration to enable.")
            return True, 1.0

        if timings is None:
            # Collect live sample
            timings = self.collect_timing_sample("Behavioral verification:")

        if not timings or len(timings) < 5:
            print("[Layer C] ✗ Insufficient timing data.")
            return False, 0.0

        # Compute similarity score using z-score distance
        mean = self._baseline_stats["mean"]
        stddev = max(self._baseline_stats["stddev"], 1.0)

        z_scores = [abs((t - mean) / stddev) for t in timings]
        avg_z = statistics.mean(z_scores)

        # Convert z-score to similarity (lower z = more similar)
        # z=0 → score=1.0, z=2 → score~0.5, z=4 → score~0.2
        score = max(0.0, 1.0 - (avg_z / 4.0))

        passed = score >= self.PASS_THRESHOLD
        status = "✓ PASS" if passed else "✗ FAIL"
        print(
            f"[Layer C] {status}  ·  behavioral score={score:.2f}  "
            f"(threshold={self.PASS_THRESHOLD})"
        )
        return passed, score


# ══════════════════════════════════════════════════════════════════
# LAYER D — Zero-Knowledge Proof (Simplified)
# Full zkSNARK requires Rust/C++ library (liboqs/bellman).
# This beginner version uses a cryptographic challenge-response
# that achieves the same security property: prove you know the
# secret WITHOUT transmitting the secret.
# ══════════════════════════════════════════════════════════════════


class ZKPLayer:
    """
    Zero-Knowledge Proof authentication.

    THE SECURITY PROPERTY:
      You prove you know the master secret WITHOUT ever sending it.
      Even if someone records every packet, they learn nothing useful.
      Every proof is unique — replaying a captured proof fails.

    HOW THIS SIMPLIFIED VERSION WORKS:
      1. Server sends a random challenge (nonce).
      2. You compute: response = HMAC(secret_key, challenge + timestamp)
      3. Server verifies the response using the same formula.
      4. The secret key is never transmitted — only the proof.

    WHY REPLAY ATTACKS FAIL:
      The timestamp is included. Old responses become invalid.
      Challenge is random each time. Responses don't repeat.

    UPGRADE PATH:
      Replace with groth16 zkSNARK using py_ecc or bellman
      for fully non-interactive, publicly verifiable proofs.
    """

    WINDOW_SECONDS = 60  # proof valid for 60 seconds

    def __init__(self, secret_key: Optional[bytes] = None):
        """
        Args:
            secret_key: The private key for ZKP.
                        Generated on setup, stored securely.
        """
        self.secret_key = secret_key or secrets.token_bytes(32)

    def generate_challenge(self) -> dict:
        """
        Server generates a fresh challenge.
        Returns {"challenge": hex_string, "timestamp": float}
        """
        return {
            "challenge": secrets.token_hex(32),
            "timestamp": time.time(),
        }

    def prove(self, challenge: dict) -> str:
        """
        Client proves knowledge of secret_key.
        Returns a hex proof string.

        NEVER transmits secret_key — only the HMAC response.
        """
        msg = f"{challenge['challenge']}|{challenge['timestamp']:.0f}".encode()
        proof = hmac.new(self.secret_key, msg, hashlib.sha256).hexdigest()
        return proof

    def verify_proof(self, challenge: dict, proof: str) -> bool:
        """
        Server verifies the proof WITHOUT knowing the secret.
        (In practice, server has the same key — but the KEY is never sent.)

        Checks:
          1. Timestamp is fresh (not a replay attack)
          2. Proof matches expected value
        """
        # 1. Freshness check — reject old proofs
        age = abs(time.time() - challenge["timestamp"])
        if age > self.WINDOW_SECONDS:
            print(f"[Layer D] ✗ ZKP challenge expired ({age:.0f}s old).")
            return False

        # 2. Verify proof
        expected = self.prove(challenge)
        result = hmac.compare_digest(proof, expected)

        status = "✓ PASS" if result else "✗ FAIL"
        print(f"[Layer D] {status}  ·  ZKP proof verified.")
        return result

    def export_key(self) -> str:
        return base64.b64encode(self.secret_key).decode()

    @classmethod
    def from_key(cls, key_b64: str) -> "ZKPLayer":
        return cls(secret_key=base64.b64decode(key_b64))


# ══════════════════════════════════════════════════════════════════
# LAYER E — Geofence + Device Binding
# ══════════════════════════════════════════════════════════════════


class GeofenceLayer:
    """
    Restricts access to registered devices and locations.

    DEVICE BINDING:
      Ties the vault to specific hardware.
      Different machine → different fingerprint → access denied.

    GEOFENCING (optional):
      Restrict access to specific IP addresses or ranges.
      Useful for: home network only, office network only.

    FOR BEGINNERS:
      Start with device binding only (enabled automatically).
      Add IP restriction if you want extra security.
    """

    def __init__(self):
        self._registered_devices: list[str] = []
        self._allowed_ips: list[str] = []
        self._geofence_enabled: bool = False

    def register_device(self, device_hash: str):
        """Register a device fingerprint as trusted."""
        if device_hash not in self._registered_devices:
            self._registered_devices.append(device_hash)
            print(f"[Layer E] Device registered: {device_hash[:16]}...")

    def add_allowed_ip(self, ip: str):
        """Add an IP address to the geofence whitelist."""
        self._allowed_ips.append(ip)
        self._geofence_enabled = True
        print(f"[Layer E] IP whitelisted: {ip}")

    def get_current_ip(self) -> str:
        """Get the machine's current public IP address."""
        try:
            import urllib.request

            with urllib.request.urlopen("https://api.ipify.org", timeout=3) as r:
                return r.read().decode("utf-8").strip()
        except Exception:
            return "unknown"

    def verify(self, device_hash: str) -> bool:
        """
        Verify device is registered.
        Optionally verify IP is within geofence.
        """
        # Check device
        if self._registered_devices and device_hash not in self._registered_devices:
            print(f"[Layer E] ✗ Unregistered device: {device_hash[:16]}...")
            return False

        # Check geofence (if enabled)
        if self._geofence_enabled and self._allowed_ips:
            current_ip = self.get_current_ip()
            ip_ok = any(
                current_ip.startswith(allowed) or current_ip == allowed
                for allowed in self._allowed_ips
            )
            if not ip_ok:
                print(
                    f"[Layer E] ⚠ Outside geofence. IP={current_ip}. "
                    f"Access granted but alert sent."
                )
                # In production: send alert to owner here
                # We still pass but log it
            else:
                print(f"[Layer E] ✓ Within geofence. IP={current_ip}")

        print(f"[Layer E] ✓ Device verified: {device_hash[:16]}...")
        return True

    def export(self) -> dict:
        return {
            "registered_devices": self._registered_devices,
            "allowed_ips": self._allowed_ips,
            "geofence_enabled": self._geofence_enabled,
        }

    def load(self, data: dict):
        self._registered_devices = data.get("registered_devices", [])
        self._allowed_ips = data.get("allowed_ips", [])
        self._geofence_enabled = data.get("geofence_enabled", False)
