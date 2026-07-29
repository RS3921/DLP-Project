"""Security regression tests for the enterprise-hardening controls."""

import base64
import json
import tempfile
import unittest
from pathlib import Path

import app_gui.webview_app
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.auth_gateway import AuthGateway
from layers.auth_layers import GeofenceLayer, ZKPLayer
from server.enterprise_store import EnterpriseStore

LOCATION = {"latitude": 19.0760, "longitude": 72.8777, "accuracy": 20}

class EnterpriseHardeningTests(unittest.TestCase):
    def test_behavioral_layer_rejects_different_rhythm(self):
        with tempfile.TemporaryDirectory() as directory:
            gateway = AuthGateway(directory)
            baseline = [110, 125, 118, 132, 121, 115, 128, 119]
            setup = gateway.setup_with_credentials("first secure passphrase", behavioral_timings=baseline, geofence_location=LOCATION)
            result = gateway.login_with_credentials(
                gateway.totp.get_code(), "first secure passphrase",
                [700, 850, 640, 900, 760, 820, 690, 880],
                setup["layer_d_key"], LOCATION,
            )
        self.assertFalse(result["layers"]["C"])

    def test_challenge_response_rejects_forged_proof(self):
        layer = ZKPLayer()
        self.assertFalse(layer.verify_proof(layer.generate_challenge(), "forged"))

    def test_device_binding_rejects_unregistered_device(self):
        layer = GeofenceLayer()
        layer.register_device("trusted-device")
        self.assertFalse(layer.verify("different-device"))

    def test_geofence_requires_current_location_and_rejects_outside_radius(self):
        layer = GeofenceLayer()
        layer.register_device("trusted-device")
        layer.register_location(19.0760, 72.8777, 500)
        self.assertFalse(layer.verify("trusted-device"))
        self.assertFalse(layer.verify(
            "trusted-device",
            {"latitude": 18.5204, "longitude": 73.8567, "accuracy": 20},
        ))
        self.assertTrue(layer.verify("trusted-device", LOCATION))

    def test_geofence_accepts_normal_windows_desktop_accuracy(self):
        layer = GeofenceLayer()
        layer.register_device("trusted-device")
        layer.register_location(19.0760, 72.8777, 500)
        self.assertTrue(layer.verify(
            "trusted-device",
            {"latitude": 19.0760, "longitude": 72.8777, "accuracy": 2_000},
        ))
        self.assertFalse(layer.verify(
            "trusted-device",
            {"latitude": 19.0760, "longitude": 72.8777, "accuracy": 20_000},
        ))

    def test_existing_vault_reset_requires_recovery_key(self):
        with tempfile.TemporaryDirectory() as directory:
            gateway = AuthGateway(directory)
            rhythm = [110, 125, 118, 132, 121, 115, 128, 119]
            first = gateway.setup_with_credentials("first secure passphrase", behavioral_timings=rhythm, geofence_location=LOCATION)
            denied = gateway.setup_with_credentials("replacement passphrase", behavioral_timings=rhythm, geofence_location=LOCATION)
            allowed = gateway.setup_with_credentials(
                "replacement passphrase", first["recovery_key"], rhythm, LOCATION
            )
        self.assertFalse(denied["ok"])
        self.assertTrue(allowed["ok"])

    def test_policy_signature_is_ed25519_and_verifiable(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EnterpriseStore(Path(directory) / "enterprise_state.json")
            envelope = store.signed_policy()
        material = {
            "policy": envelope["policy"],
            "issued_at": envelope["issued_at"],
            "signature_alg": envelope["signature_alg"],
            "public_key": envelope["public_key"],
        }
        raw = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        Ed25519PublicKey.from_public_bytes(
            base64.b64decode(envelope["public_key"])
        ).verify(base64.b64decode(envelope["signature"]), raw)
        self.assertEqual(envelope["signature_alg"], "Ed25519")

    def test_legacy_json_migrates_to_sqlite(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy = Path(directory) / "enterprise_state.json"
            legacy.write_text(
                '{"agents": {}, "events": [], "policies": {}}', encoding="utf-8"
            )
            store = EnterpriseStore(legacy)
            self.assertTrue(store.path.exists())
            self.assertEqual(store.path.suffix, ".db")


if __name__ == "__main__":
    unittest.main()
