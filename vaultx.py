"""
╔══════════════════════════════════════════════════════════════╗
║             VAULT-X  ·  Personal Data Vault                  ║
║             Command-Line Interface                           ║
╚══════════════════════════════════════════════════════════════╝

HOW TO USE:
  First time:   python vaultx.py setup
  Login:        python vaultx.py login
  Encrypt file: python vaultx.py encrypt myfile.txt
  Decrypt file: python vaultx.py decrypt myfile.txt.vault
  Audit log:    python vaultx.py audit
  Help:         python vaultx.py help
"""

import os
import sys
import json
import base64

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from core.auth_gateway import AuthGateway
from core.vault_engine import VaultBlob

# ══════════════════════════════════════════════════════════════════
# VAULT-X CLI
# ══════════════════════════════════════════════════════════════════

VAULT_DIR = "./my_vault"
BANNER = """
╔══════════════════════════════════════════════════════╗
║                                                      ║
║    ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗         ║
║    ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝         ║
║    ██║   ██║███████║██║   ██║██║     ██║   ██╗       ║
║    ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ╚═╝       ║
║     ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║             ║
║      ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝             ║
║                                                      ║
║   Personal Data Vault  ·  5-Layer Auth  ·  v1.0.0   ║
╚══════════════════════════════════════════════════════╝
"""


def cmd_setup():
    """Run first-time setup."""
    print(BANNER)
    gateway = AuthGateway(VAULT_DIR)
    gateway.setup()


def cmd_login():
    """Login and start an interactive vault session."""
    print(BANNER)
    gateway = AuthGateway(VAULT_DIR)
    token = gateway.login()

    if not token:
        sys.exit(1)

    print("\nVault session active. Commands:")
    print("  encrypt <file>   — Encrypt a file into the vault")
    print("  decrypt <file>   — Decrypt a .vault file")
    print("  audit            — Show recent audit log")
    print("  exit             — End session\n")

    while True:
        try:
            cmd = input("vault> ").strip().split()
        except (KeyboardInterrupt, EOFError):
            print("\nSession ended.")
            break

        if not cmd:
            continue

        if not gateway.vault.validate_session_token(token):
            print("Session expired. Please login again.")
            break

        if cmd[0] == "exit":
            gateway.vault.revoke_session(token.session_id)
            print("Vault session closed. Goodbye.")
            break

        elif cmd[0] == "encrypt" and len(cmd) > 1:
            _encrypt_file(gateway.vault, token, cmd[1])

        elif cmd[0] == "decrypt" and len(cmd) > 1:
            _decrypt_file(gateway.vault, token, cmd[1])

        elif cmd[0] == "audit":
            gateway.show_audit_log()

        else:
            print("Unknown command. Try: encrypt <file>, decrypt <file>, audit, exit")


def _encrypt_file(vault, token, filepath):
    """Encrypt a file and save as .vault blob."""
    if not os.path.exists(filepath):
        print(f"  ✗ File not found: {filepath}")
        return
    try:
        with open(filepath, "rb") as f:
            plaintext = f.read()

        blob = vault.encrypt(plaintext, token)
        out_path = filepath + ".vault"

        with open(out_path, "w") as f:
            import dataclasses

            json.dump(dataclasses.asdict(blob), f, indent=2)

        print(f"  ✓ Encrypted: {filepath}")
        print(f"  ✓ Saved to:  {out_path}")
        print(f"  ✓ Blob ID:   {blob.blob_id}")
        print(f"  ⚠ Original file still exists. Delete it manually if needed.")

    except Exception as e:
        print(f"  ✗ Encryption failed: {e}")


def _decrypt_file(vault, token, filepath):
    """Decrypt a .vault blob file."""
    if not os.path.exists(filepath):
        print(f"  ✗ File not found: {filepath}")
        return
    try:
        with open(filepath, "r") as f:
            blob_data = json.load(f)

        blob = VaultBlob(**blob_data)
        plaintext = vault.decrypt(blob, token)

        # Determine output filename
        out_path = filepath.replace(".vault", ".decrypted")
        if out_path == filepath:
            out_path = filepath + ".decrypted"

        with open(out_path, "wb") as f:
            f.write(plaintext)

        print(f"  ✓ Decrypted: {filepath}")
        print(f"  ✓ Saved to:  {out_path}")
        print(f"  ✓ Size:      {len(plaintext)} bytes")

    except Exception as e:
        print(f"  ✗ Decryption failed: {e}")


def cmd_audit():
    """Show audit log without logging in (just config-level log)."""
    print(BANNER)
    gateway = AuthGateway(VAULT_DIR)
    gateway.show_audit_log(30)


def cmd_help():
    """Show help."""
    print(BANNER)
    print("COMMANDS:")
    print("  python vaultx.py setup     — First-time setup (run once)")
    print("  python vaultx.py login     — Log in and access vault")
    print("  python vaultx.py audit     — View audit log (no login needed)")
    print("  python vaultx.py serve     — Run the VAULT-X HTTP service")
    print("  python vaultx.py help      — Show this help\n")
    print("AUTHENTICATION LAYERS:")
    print("  [A] TOTP — 6-digit code from Google Authenticator")
    print("  [B] Passphrase — your secret password")
    print("  [C] Behavioral — your typing rhythm")
    print("  [D] ZKP — cryptographic identity proof")
    print("  [E] Device — hardware fingerprint binding\n")
    print("SECURITY NOTES:")
    print("  • Your vault key is stored in ./my_vault/")
    print("  • Back up the vault_data folder securely")
    print("  • 3 failed logins = 72-hour lockout")
    print("  • Session expires after 8 hours or 10 min idle\n")


def cmd_serve():
    """Run the HTTP server wrapper."""
    from server.vault_server import main as server_main

    raise SystemExit(server_main(sys.argv[2:]))


# ── Entry Point ──────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        cmd_help()
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "setup":
        cmd_setup()
    elif command == "login":
        cmd_login()
    elif command == "audit":
        cmd_audit()
    elif command == "serve":
        cmd_serve()
    elif command == "help":
        cmd_help()
    else:
        print(f"Unknown command: {command}")
        print("Run: python vaultx.py help")
        sys.exit(1)
