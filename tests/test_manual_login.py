"""Tests for the native manual setup and five-layer login flow."""

import tempfile
import unittest
import sys
from unittest.mock import patch

import app_gui.webview_app  # configures UTF-8 output on Windows
from app_gui.webview_app import Api
from core.auth_gateway import AuthGateway

LOCATION = {"latitude": 19.0760, "longitude": 72.8777, "accuracy": 20}

class ManualLoginTests(unittest.TestCase):
    def test_setup_returns_offline_authenticator_qr(self):
        class FakeImage:
            def save(self, buffer, format):
                self.format = format
                buffer.write(b"valid-png-placeholder")

        class FakeQrCode:
            @staticmethod
            def make(uri):
                self = FakeImage()
                self.uri = uri
                return self

        with tempfile.TemporaryDirectory() as directory:
            api = Api("dashboard-key")
            api._gateway = AuthGateway(directory)
            rhythm = [110, 125, 118, 132, 121, 115, 128, 119]
            with patch.dict(sys.modules, {"qrcode": FakeQrCode}):
                result = api.setup(
                    "correct horse battery staple", "",
                    rhythm, LOCATION, 500
                )

        self.assertTrue(result["ok"])
        self.assertTrue(result["totp_qr_data_url"].startswith("data:image/png;base64,"))

    def test_setup_and_valid_credentials_pass_all_layers(self):
        with tempfile.TemporaryDirectory() as directory:
            gateway = AuthGateway(directory)
            rhythm = [110, 125, 118, 132, 121, 115, 128, 119]
            setup = gateway.setup_with_credentials("correct horse battery staple", behavioral_timings=rhythm, geofence_location=LOCATION)
            result = gateway.login_with_credentials(
                gateway.totp.get_code(),
                "correct horse battery staple",
                rhythm,
                setup["layer_d_key"],
                LOCATION,
            )

        self.assertTrue(setup["ok"])
        self.assertRegex(setup["totp_secret"], r"^[A-Z2-7]+$")
        self.assertNotIn(" ", setup["totp_secret"])
        self.assertTrue(result["ok"])
        self.assertTrue(all(result["layers"].values()))
        self.assertIsNotNone(result["token"])

    def test_invalid_totp_and_passphrase_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            gateway = AuthGateway(directory)
            rhythm = [110, 125, 118, 132, 121, 115, 128, 119]
            setup = gateway.setup_with_credentials("correct horse battery staple", behavioral_timings=rhythm, geofence_location=LOCATION)
            result = gateway.login_with_credentials(
                "000000", "wrong passphrase", rhythm,
                setup["layer_d_key"], LOCATION
            )

        self.assertFalse(result["ok"])
        self.assertFalse(result["layers"]["A"])
        self.assertFalse(result["layers"]["B"])

    def test_layers_d_and_e_require_fresh_user_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            gateway = AuthGateway(directory)
            rhythm = [110, 125, 118, 132, 121, 115, 128, 119]
            gateway.setup_with_credentials(
                "correct horse battery staple", behavioral_timings=rhythm,
                geofence_location=LOCATION
            )
            result = gateway.login_with_credentials(
                gateway.totp.get_code(), "correct horse battery staple", rhythm
            )

        self.assertFalse(result["ok"])
        self.assertFalse(result["layers"]["D"])
        self.assertFalse(result["layers"]["E"])

    def test_wrong_layer_d_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            gateway = AuthGateway(directory)
            rhythm = [110, 125, 118, 132, 121, 115, 128, 119]
            gateway.setup_with_credentials(
                "correct horse battery staple", behavioral_timings=rhythm,
                geofence_location=LOCATION
            )
            result = gateway.login_with_credentials(
                gateway.totp.get_code(), "correct horse battery staple", rhythm,
                "forged-possession-key", LOCATION
            )

        self.assertFalse(result["ok"])
        self.assertFalse(result["layers"]["D"])


if __name__ == "__main__":
    unittest.main()
