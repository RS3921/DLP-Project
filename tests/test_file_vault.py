"""Regression tests for durable File Vault encryption."""

import base64
import tempfile
import unittest
from pathlib import Path

from app_gui.webview_app import Api
from core.auth_gateway import AuthGateway
from core.vault_engine import VaultEngine


class FileVaultTests(unittest.TestCase):
    def test_native_bridge_encrypts_and_restores_selected_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "notes.txt"
            protected = root / "notes.txt.vault"
            restored = root / "restored-notes.txt"
            source.write_bytes(b"native file picker workflow")

            api = Api("dashboard-key")
            api._gateway = AuthGateway(str(root / "vault-data"))
            api._token = api._gateway.vault.create_session_token("owner")
            api._vault_index = root / "vault-data" / "file_vault_index.json"
            api._choose_open_file = lambda vault_only=False: protected if vault_only else source
            api._choose_save_file = (
                lambda selected, suggested: restored
                if selected == protected
                else protected
            )

            encrypted = api.encrypt_file()
            decrypted = api.decrypt_file()

            self.assertTrue(encrypted["ok"])
            self.assertTrue(decrypted["ok"])
            self.assertEqual(restored.read_bytes(), b"native file picker workflow")
            self.assertTrue(protected.is_file())
            self.assertGreaterEqual(len(api.list_file_vault()["files"]), 2)

    def test_file_package_survives_application_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            first_engine = VaultEngine(directory)
            first_token = first_engine.create_session_token("owner")
            package = first_engine.encrypt_file_payload(
                b"confidential file contents", "report.txt", first_token
            )

            restarted_engine = VaultEngine(directory)
            restarted_token = restarted_engine.create_session_token("owner")
            plaintext, original_name = restarted_engine.decrypt_file_payload(
                package, restarted_token
            )

        self.assertEqual(plaintext, b"confidential file contents")
        self.assertEqual(original_name, "report.txt")
        self.assertEqual(package["algorithm"], "ChaCha20-Poly1305+AES-256-GCM")

    def test_tampered_file_package_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = VaultEngine(directory)
            token = engine.create_session_token("owner")
            package = engine.encrypt_file_payload(b"protected", "secret.txt", token)
            ciphertext = bytearray(base64.b64decode(package["ciphertext"]))
            ciphertext[len(ciphertext) // 2] ^= 1
            package["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")

            with self.assertRaisesRegex(ValueError, "authentication failed"):
                engine.decrypt_file_payload(package, token)

    def test_invalid_or_expired_session_is_required(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = VaultEngine(directory)
            token = engine.create_session_token("owner")
            engine.revoke_session(token.session_id)

            with self.assertRaises(PermissionError):
                engine.encrypt_file_payload(b"protected", "secret.txt", token)


if __name__ == "__main__":
    unittest.main()
