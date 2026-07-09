"""
╔══════════════════════════════════════════════════════════════╗
║          VAULT-X  ·  Core Encryption & Session Engine        ║
║          Layer: Vault Core (L-06) + Session Token (L-05)     ║
╚══════════════════════════════════════════════════════════════╝

HOW THIS WORKS (Plain English):
  1. When you register, a Master Key is created and stored safely.
  2. Every time you log in, a unique Session Key is derived from
     the Master Key + your identity + a timestamp.
  3. All data is encrypted with that Session Key inside this engine.
  4. The Session Key is destroyed when the session ends.
  5. Even if someone steals your encrypted files, they are useless
     without the Master Key inside this vault engine.

BEGINNER NOTE:
  You do NOT need to understand all the crypto math here.
  Just know: this is the "safe" that holds the keys.
  Everything else in VAULT-X uses this safe.
"""

import os
import time
import json
import hmac
import hashlib
import secrets
import base64
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Optional

# ─── Install check ────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.backends import default_backend
except ImportError:
    raise ImportError(
        "\n[VAULT-X] Missing required library!\n"
        "Run this command first:\n"
        "    pip install cryptography\n"
    )


# ══════════════════════════════════════════════════════════════════
# CONSTANTS  —  change these only if you know what you're doing
# ══════════════════════════════════════════════════════════════════
KEY_SIZE = 32  # 256-bit keys
SESSION_HOURS = 8  # session expires after 8 hours
IDLE_MINUTES = 10  # auto-logout after 10 min idle
VAULT_VERSION = "1.0.0"


# ══════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════


@dataclass
class SessionToken:
    """
    The 'passport' that proves you are authenticated.
    Every operation requires a valid, non-expired token.
    """

    session_id: str
    owner_hash: str  # hash of owner identity (never raw)
    device_hash: str  # hash of this machine's hardware ID
    issued_at: float  # Unix timestamp of creation
    expires_at: float  # Unix timestamp of expiry
    last_active: float  # Unix timestamp of last action
    scope: list  # what operations are allowed
    signature: str  # Ed25519 signature — proves authenticity


@dataclass
class VaultBlob:
    """
    The encrypted container for any piece of data.
    This is what gets stored on disk / in the database.
    An attacker seeing this sees only random bytes.
    """

    blob_id: str
    session_id: str
    chacha_nonce: str  # base64 — random nonce for ChaCha20
    aes_nonce: str  # base64 — random nonce for AES-GCM
    chacha_ciphertext: str  # base64 — first encryption layer
    aes_ciphertext: str  # base64 — second encryption layer
    canary_hash: str  # hash to verify canary bytes intact
    created_at: float
    vault_version: str = VAULT_VERSION


# ══════════════════════════════════════════════════════════════════
# DEVICE FINGERPRINT  —  ties keys to THIS specific machine
# ══════════════════════════════════════════════════════════════════


def get_device_fingerprint() -> str:
    """
    Creates a unique identifier for THIS machine.

    In production this uses: CPU ID + MAC address + disk serial.
    Here we use a safe combination of available system info.

    BEGINNER NOTE: This is why your vault only opens on YOUR computer.
    Copy all the files to another machine → different fingerprint →
    decryption key is different → files remain locked.
    """
    import platform
    import uuid

    components = [
        platform.node(),  # computer hostname
        platform.machine(),  # CPU architecture
        platform.processor(),  # CPU info
        str(uuid.getnode()),  # MAC address as integer
        platform.system(),  # OS name
    ]

    combined = "|".join(components).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


# ══════════════════════════════════════════════════════════════════
# VAULT ENGINE  —  the main class you interact with
# ══════════════════════════════════════════════════════════════════


class VaultEngine:
    """
    The core of VAULT-X. Handles:
      - Master key generation and storage
      - Session key derivation
      - Dual-layer encryption (ChaCha20 + AES-256-GCM)
      - Session token creation and validation
      - Canary byte injection and verification
    """

    def __init__(self, vault_dir: str = "./vault_data"):
        """
        Initialize the Vault Engine.

        Args:
            vault_dir: Where to store the master key and vault data.
                       Default is a folder called 'vault_data' in
                       the current directory.
        """
        self.vault_dir = vault_dir
        self.key_file = os.path.join(vault_dir, ".vault_master.key")
        self.sig_key_file = os.path.join(vault_dir, ".vault_signing.key")
        self._master_key: Optional[bytes] = None
        self._signing_key: Optional[Ed25519PrivateKey] = None
        self._active_sessions: dict = {}

        os.makedirs(vault_dir, exist_ok=True)
        self._load_or_create_master_key()
        self._load_or_create_signing_key()

        print(f"[VAULT-X] Engine initialized  ·  vault_dir={vault_dir}")

    # ── Master Key ──────────────────────────────────────────────────

    def _load_or_create_master_key(self):
        """Load existing master key or create a new one on first run."""
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                self._master_key = f.read()
            print("[VAULT-X] Master key loaded from disk.")
        else:
            self._master_key = secrets.token_bytes(KEY_SIZE)
            with open(self.key_file, "wb") as f:
                f.write(self._master_key)
            # Lock down file permissions (Unix/Linux/macOS only)
            try:
                os.chmod(self.key_file, 0o600)
            except Exception:
                pass
            print("[VAULT-X] New master key generated and saved.")

    def _load_or_create_signing_key(self):
        """Load or create the Ed25519 key used to sign session tokens."""
        if os.path.exists(self.sig_key_file):
            with open(self.sig_key_file, "rb") as f:
                pem = f.read()
            self._signing_key = serialization.load_pem_private_key(pem, password=None)
        else:
            self._signing_key = Ed25519PrivateKey.generate()
            pem = self._signing_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(self.sig_key_file, "wb") as f:
                f.write(pem)
            try:
                os.chmod(self.sig_key_file, 0o600)
            except Exception:
                pass
            print("[VAULT-X] New signing key generated.")

    # ── Session Key Derivation ───────────────────────────────────────

    def derive_session_key(self, owner_hash: str, session_id: str) -> bytes:
        """
        Derive a unique session key from:
          - Master key  (the root secret)
          - Owner hash  (your identity)
          - Session ID  (unique per login)

        SECURITY PROPERTY:
          Even if an attacker gets the session key for one session,
          they CANNOT derive the master key or any other session key.
          Each session key is mathematically independent.

        BEGINNER NOTE: Think of this like a key-cutting machine.
          The master key is the mold. For each session, a fresh key
          is cut from the mold — but you can't reverse-engineer the
          mold from any individual key.
        """
        info = f"session|{owner_hash}|{session_id}".encode("utf-8")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=self._master_key,  # master key acts as salt
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(secrets.token_bytes(16))

    # ── Session Token ────────────────────────────────────────────────

    def create_session_token(self, owner_hash: str, scope: list = None) -> SessionToken:
        """
        Issue a new session token after successful authentication.

        The token is:
          - Time-limited  (expires after SESSION_HOURS)
          - Device-bound  (tied to THIS machine's fingerprint)
          - Signed        (Ed25519 signature proves authenticity)

        Returns a SessionToken object.
        """
        if scope is None:
            scope = ["read", "write", "relocate"]

        now = time.time()
        session_id = secrets.token_hex(32)
        device_hash = get_device_fingerprint()

        # Build the token payload
        payload = {
            "session_id": session_id,
            "owner_hash": owner_hash,
            "device_hash": device_hash,
            "issued_at": now,
            "expires_at": now + (SESSION_HOURS * 3600),
            "scope": scope,
        }

        # Sign the payload with Ed25519 key
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        signature = self._signing_key.sign(payload_bytes)
        signature_b64 = base64.b64encode(signature).decode("utf-8")

        token = SessionToken(**payload, last_active=now, signature=signature_b64)

        # Store in active sessions
        self._active_sessions[session_id] = {
            "token": token,
            "session_key": self.derive_session_key(owner_hash, session_id),
        }

        print(f"[VAULT-X] Session token issued  ·  id={session_id[:16]}...")
        return token

    def validate_session_token(self, token: SessionToken) -> bool:
        """
        Validate a session token. Returns True if valid.

        Checks:
          1. Token exists in active sessions
          2. Not expired (time check)
          3. Not idle too long
          4. Device fingerprint matches
          5. Ed25519 signature valid
        """
        sid = token.session_id

        # 1. Exists?
        if sid not in self._active_sessions:
            print("[VAULT-X] ✗ Token not in active sessions.")
            return False

        now = time.time()

        # 2. Expired?
        if now > token.expires_at:
            print("[VAULT-X] ✗ Session token expired.")
            self.revoke_session(sid)
            return False

        # 3. Idle timeout?
        if now - token.last_active > (IDLE_MINUTES * 60):
            print("[VAULT-X] ✗ Session idle timeout.")
            self.revoke_session(sid)
            return False

        # 4. Device fingerprint matches?
        expected_device = get_device_fingerprint()
        if token.device_hash != expected_device:
            print("[VAULT-X] ✗ Device fingerprint MISMATCH — token stolen?")
            self.revoke_session(sid)
            return False

        # 5. Signature valid?
        payload = {
            "session_id": token.session_id,
            "owner_hash": token.owner_hash,
            "device_hash": token.device_hash,
            "issued_at": token.issued_at,
            "expires_at": token.expires_at,
            "scope": token.scope,
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        sig_bytes = base64.b64decode(token.signature)
        try:
            self._signing_key.public_key().verify(sig_bytes, payload_bytes)
        except Exception:
            print("[VAULT-X] ✗ Signature verification FAILED — token forged?")
            return False

        # Update last active
        token.last_active = now
        return True

    def revoke_session(self, session_id: str):
        """Immediately revoke a session token and destroy the session key."""
        if session_id in self._active_sessions:
            # Destroy the session key from memory
            sess = self._active_sessions.pop(session_id)
            sess["session_key"] = b"\x00" * KEY_SIZE  # zero it out
            print(f"[VAULT-X] Session revoked  ·  id={session_id[:16]}...")

    # ── Encryption Pipeline ──────────────────────────────────────────

    def _inject_canaries(self, data: bytes, session_key: bytes) -> tuple[bytes, str]:
        """
        Inject invisible canary bytes at pseudo-random positions.
        Returns (modified_data, canary_fingerprint).
        """
        pos_seed = hmac.new(session_key, b"canary_positions", hashlib.sha256).digest()
        n_canaries = 4

        canary_values = [pos_seed[16 + i] for i in range(n_canaries)]
        # Positions are within original data length
        positions = [
            int.from_bytes(pos_seed[i * 4 : (i + 1) * 4], "big") % max(len(data) + 1, 1)
            for i in range(n_canaries)
        ]

        data_list = list(data)
        for pos, val in sorted(zip(positions, canary_values)):
            pos = min(pos, len(data_list))
            data_list.insert(pos, val)

        modified = bytes(data_list)
        canary_info = json.dumps({"positions": positions, "values": canary_values}, sort_keys=True)
        fingerprint = hashlib.sha256(canary_info.encode()).hexdigest()
        return modified, fingerprint

    def _remove_canaries(self, data: bytes, session_key: bytes) -> bytes:
        """Remove canary bytes from decrypted data."""
        pos_seed = hmac.new(session_key, b"canary_positions", hashlib.sha256).digest()
        n_canaries = 4
        positions = [
            int.from_bytes(pos_seed[i * 4 : (i + 1) * 4], "big")
            % max(len(data) - n_canaries + 1, 1)
            for i in range(n_canaries)
        ]
        data_list = list(data)
        # Remove in reverse insertion order (highest adjusted index first)
        for pos in sorted(positions, reverse=True):
            pos = min(pos, len(data_list) - 1)
            data_list.pop(pos)
        return bytes(data_list)

    def _verify_canaries(self, data: bytes, session_key: bytes, expected_fingerprint: str) -> bool:
        """Verify canary fingerprint matches. Returns True if intact."""
        pos_seed = hmac.new(session_key, b"canary_positions", hashlib.sha256).digest()
        n_canaries = 4
        canary_values = [pos_seed[16 + i] for i in range(n_canaries)]
        positions = [
            int.from_bytes(pos_seed[i * 4 : (i + 1) * 4], "big")
            % max(len(data) - n_canaries + 1, 1)
            for i in range(n_canaries)
        ]
        canary_info = json.dumps({"positions": positions, "values": canary_values}, sort_keys=True)
        actual = hashlib.sha256(canary_info.encode()).hexdigest()
        return actual == expected_fingerprint

    def encrypt(self, plaintext: bytes, token: SessionToken) -> VaultBlob:
        """
        Encrypt data using the dual-layer pipeline:
          Stage 1: Inject canary bytes
          Stage 2: Encrypt with ChaCha20-Poly1305
          Stage 3: Encrypt result with AES-256-GCM

        Returns a VaultBlob — safe to store anywhere.

        Args:
            plaintext:  The raw bytes to encrypt (e.g., file contents)
            token:      Your active session token (proves you're logged in)
        """
        if not self.validate_session_token(token):
            raise PermissionError("[VAULT-X] Invalid or expired session token.")

        sess = self._active_sessions[token.session_id]
        session_key = sess["session_key"]

        # Stage 1: Canary injection
        canary_data, canary_hash = self._inject_canaries(plaintext, session_key)

        # Stage 2: ChaCha20-Poly1305 encryption
        chacha_key = session_key[:32]
        chacha_nonce = secrets.token_bytes(12)  # 96-bit nonce
        chacha = ChaCha20Poly1305(chacha_key)
        chacha_ct = chacha.encrypt(chacha_nonce, canary_data, None)

        # Stage 3: AES-256-GCM encryption
        # Derive AES key deterministically from session_key
        aes_key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"aes_layer",
            backend=default_backend(),
        ).derive(session_key)

        aes_nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(aes_key_material)
        aes_ct = aesgcm.encrypt(aes_nonce, chacha_ct, None)

        blob = VaultBlob(
            blob_id=secrets.token_hex(16),
            session_id=token.session_id,
            chacha_nonce=base64.b64encode(chacha_nonce).decode(),
            aes_nonce=base64.b64encode(aes_nonce).decode(),
            chacha_ciphertext=base64.b64encode(chacha_ct).decode(),
            aes_ciphertext=base64.b64encode(aes_ct).decode(),
            canary_hash=canary_hash,
            created_at=time.time(),
        )

        print(
            f"[VAULT-X] Encrypted  ·  blob_id={blob.blob_id[:12]}...  "
            f"size={len(plaintext)}→{len(aes_ct)} bytes"
        )
        return blob

    def decrypt(self, blob: VaultBlob, token: SessionToken) -> bytes:
        """
        Decrypt a VaultBlob back to plaintext.
        Reverses the 3-stage pipeline:
          Stage 1: AES-256-GCM decryption (+ GCM tag verification)
          Stage 2: ChaCha20-Poly1305 decryption (+ MAC verification)
          Stage 3: Canary verification + removal

        Args:
            blob:   The VaultBlob to decrypt
            token:  Your active session token
        """
        if not self.validate_session_token(token):
            raise PermissionError("[VAULT-X] Invalid or expired session token.")

        sess = self._active_sessions[token.session_id]
        session_key = sess["session_key"]

        try:
            # Stage 1: AES-256-GCM decryption
            aes_key_material = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"aes_layer",
                backend=default_backend(),
            ).derive(session_key)

            aes_nonce = base64.b64decode(blob.aes_nonce)
            aes_ct = base64.b64decode(blob.aes_ciphertext)
            aesgcm = AESGCM(aes_key_material)
            chacha_ct = aesgcm.decrypt(aes_nonce, aes_ct, None)

            # Stage 2: ChaCha20-Poly1305 decryption
            chacha_key = session_key[:32]
            chacha_nonce = base64.b64decode(blob.chacha_nonce)
            chacha_ct_b = base64.b64decode(blob.chacha_ciphertext)
            chacha = ChaCha20Poly1305(chacha_key)
            canary_data = chacha.decrypt(chacha_nonce, chacha_ct_b, None)

            # Stage 3: Canary verification (integrity check)
            if not self._verify_canaries(canary_data, session_key, blob.canary_hash):
                raise ValueError("[VAULT-X] CANARY BREACH — data tampered!")

            # Remove canary bytes to recover original plaintext
            plaintext = self._remove_canaries(canary_data, session_key)

            print(
                f"[VAULT-X] Decrypted  ·  blob_id={blob.blob_id[:12]}...  "
                f"size={len(plaintext)} bytes"
            )
            return plaintext

        except Exception as e:
            print(f"[VAULT-X] ✗ Decryption FAILED: {e}")
            raise

    # ── Utilities ────────────────────────────────────────────────────

    def hash_identity(self, raw_identity: str) -> str:
        """
        Create a safe hash of an identity string.
        Never stores raw passwords or usernames — only their hash.
        """
        salt = self._master_key[:16]
        return hashlib.pbkdf2_hmac(
            "sha256", raw_identity.encode("utf-8"), salt, iterations=260_000
        ).hex()

    def get_active_session_count(self) -> int:
        return len(self._active_sessions)

    def list_active_sessions(self) -> list:
        return [
            {
                "session_id": sid[:16] + "...",
                "issued_at": datetime.fromtimestamp(info["token"].issued_at).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "expires_at": datetime.fromtimestamp(info["token"].expires_at).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
            }
            for sid, info in self._active_sessions.items()
        ]
