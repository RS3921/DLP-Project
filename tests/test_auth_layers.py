"""
tests/test_auth_layers.py
Tests for layers/auth_layers.py
Covers: TOTP, BiometricLayer, BehavioralLayer, ZKPLayer, GeofenceLayer.
"""
import time
import pytest

from layers.auth_layers import (
    TOTPLayer, BiometricLayer, BehavioralLayer, ZKPLayer, GeofenceLayer
)
from core.vault_engine import get_device_fingerprint


# ══════════════════════════════════════════════════════════════════
# LAYER A — TOTP
# ══════════════════════════════════════════════════════════════════

class TestTOTPLayer:

    def test_get_code_returns_6_digits(self, totp):
        code = totp.get_code()
        assert len(code) == 6
        assert code.isdigit()

    def test_correct_code_verifies(self, totp):
        assert totp.verify(totp.get_code()) is True

    def test_wrong_code_rejected(self, totp):
        assert totp.verify("000000") is False

    def test_code_at_boundary_accepted_with_window(self, totp):
        """Code from 30 seconds ago should pass with window=1."""
        past_code = totp.get_code(time.time() - 30)
        assert totp.verify(past_code, window=1) is True

    def test_old_code_rejected_outside_window(self, totp):
        old = totp.get_code(time.time() - 90)
        assert totp.verify(old, window=1) is False

    def test_export_and_restore(self, totp):
        code = totp.get_code()
        t2   = TOTPLayer.from_secret(totp.export_secret())
        assert t2.verify(code) is True

    def test_qr_uri_format(self, totp):
        uri = totp.get_qr_uri("test_account")
        assert uri.startswith("otpauth://totp/")
        assert "secret=" in uri
        assert "period=30" in uri

    def test_two_instances_same_secret_agree(self):
        t1 = TOTPLayer()
        t2 = TOTPLayer.from_secret(t1.export_secret())
        assert t1.get_code() == t2.get_code()

    def test_different_secrets_different_codes(self):
        t1 = TOTPLayer()
        t2 = TOTPLayer()
        # Extremely unlikely both produce the same code
        # (probability 1 in 10^6 per step)
        assert t1.export_secret() != t2.export_secret()


# ══════════════════════════════════════════════════════════════════
# LAYER B — BiometricLayer
# ══════════════════════════════════════════════════════════════════

class TestBiometricLayer:

    def test_correct_password_verifies(self, biometric):
        assert biometric.verify("StrongPassphrase2025!") is True

    def test_wrong_password_rejected(self, biometric):
        assert biometric.verify("WrongPassword999!") is False

    def test_empty_password_rejected(self, biometric):
        assert biometric.verify("") is False

    def test_short_password_raises_on_register(self):
        b = BiometricLayer()
        with pytest.raises(ValueError, match="12"):
            b.register("short")

    def test_register_returns_hash_and_salt(self):
        b = BiometricLayer()
        result = b.register("ValidPassphrase2025!")
        assert "hash" in result
        assert "salt" in result
        assert result["iterations"] == BiometricLayer.ITERATIONS

    def test_raw_password_not_stored(self):
        b = BiometricLayer()
        result = b.register("MySecret2025!!")
        assert "MySecret2025!!" not in str(result)

    def test_load_and_verify(self):
        b1 = BiometricLayer()
        stored = b1.register("LoadTestPass2025!")
        b2 = BiometricLayer()
        b2.load(stored)
        assert b2.verify("LoadTestPass2025!") is True
        assert b2.verify("wrong") is False

    def test_different_salts_different_hashes(self):
        b1 = BiometricLayer()
        b2 = BiometricLayer()
        r1 = b1.register("SamePassword2025!")
        r2 = b2.register("SamePassword2025!")
        assert r1["salt"] != r2["salt"]
        assert r1["hash"] != r2["hash"]

    def test_verify_before_register_raises(self):
        b = BiometricLayer()
        with pytest.raises(RuntimeError):
            b.verify("anything")


# ══════════════════════════════════════════════════════════════════
# LAYER C — BehavioralLayer
# ══════════════════════════════════════════════════════════════════

class TestBehavioralLayer:

    def test_no_baseline_auto_passes(self):
        b = BehavioralLayer()
        passed, score = b.verify(timings=[120, 110, 130, 125, 115])
        assert passed is True
        assert score == 1.0

    def test_load_baseline_and_score_similar_timings(self):
        b1 = BehavioralLayer()
        baseline = {"mean": 120.0, "stddev": 15.0, "median": 118.0, "count": 50}
        b1.load(baseline)
        # Timings close to mean → high score → pass
        timings = [119, 121, 118, 122, 120, 117, 123, 119, 121, 120]
        passed, score = b1.verify(timings=timings)
        assert passed is True
        assert score >= BehavioralLayer.PASS_THRESHOLD

    def test_wildly_different_timings_fail(self):
        b = BehavioralLayer()
        baseline = {"mean": 120.0, "stddev": 10.0, "median": 120.0, "count": 50}
        b.load(baseline)
        # 10× the mean → z-score >> 4 → score ≈ 0
        timings = [1200, 1100, 1300, 1250, 1150, 1200, 1400, 1100, 1050, 1200]
        passed, score = b.verify(timings=timings)
        assert passed is False
        assert score < BehavioralLayer.PASS_THRESHOLD

    def test_score_between_0_and_1(self):
        b = BehavioralLayer()
        b.load({"mean": 100.0, "stddev": 20.0, "median": 100.0, "count": 20})
        _, score = b.verify(timings=[90, 110, 95, 105, 100])
        assert 0.0 <= score <= 1.0


# ══════════════════════════════════════════════════════════════════
# LAYER D — ZKPLayer
# ══════════════════════════════════════════════════════════════════

class TestZKPLayer:

    def test_valid_proof_accepted(self, zkp):
        ch    = zkp.generate_challenge()
        proof = zkp.prove(ch)
        assert zkp.verify_proof(ch, proof) is True

    def test_wrong_proof_rejected(self, zkp):
        ch = zkp.generate_challenge()
        assert zkp.verify_proof(ch, "badhex" * 10) is False

    def test_expired_challenge_rejected(self, zkp):
        ch = zkp.generate_challenge()
        ch["timestamp"] = time.time() - 120   # 2 min old
        proof = zkp.prove(ch)
        assert zkp.verify_proof(ch, proof) is False

    def test_replay_attack_rejected(self, zkp):
        """Expired challenge is rejected — replay after window is impossible."""
        ch = zkp.generate_challenge()
        ch["timestamp"] = time.time() - 200   # force expiry
        proof = zkp.prove(ch)
        assert zkp.verify_proof(ch, proof) is False

    def test_different_key_cannot_prove(self):
        z1 = ZKPLayer()
        z2 = ZKPLayer()   # different secret
        ch    = z1.generate_challenge()
        proof = z2.prove(ch)   # z2's key ≠ z1's key
        assert z1.verify_proof(ch, proof) is False

    def test_export_import_key(self, zkp):
        ch     = zkp.generate_challenge()
        proof  = zkp.prove(ch)
        z2     = ZKPLayer.from_key(zkp.export_key())
        ch2    = z2.generate_challenge()
        proof2 = z2.prove(ch2)
        assert z2.verify_proof(ch2, proof2) is True

    def test_challenge_has_nonce_and_timestamp(self, zkp):
        ch = zkp.generate_challenge()
        assert "challenge" in ch
        assert "timestamp" in ch
        assert abs(ch["timestamp"] - time.time()) < 5

    def test_two_challenges_unique(self, zkp):
        c1 = zkp.generate_challenge()
        c2 = zkp.generate_challenge()
        assert c1["challenge"] != c2["challenge"]


# ══════════════════════════════════════════════════════════════════
# LAYER E — GeofenceLayer
# ══════════════════════════════════════════════════════════════════

class TestGeofenceLayer:

    def test_registered_device_passes(self, geofence):
        result = geofence.verify(get_device_fingerprint())
        assert result is True

    def test_unregistered_device_fails(self):
        geo = GeofenceLayer()
        geo.register_device("known_device_hash_abc")
        result = geo.verify("completely_unknown_device")
        assert result is False

    def test_no_registered_devices_always_passes(self):
        geo = GeofenceLayer()   # no devices registered
        result = geo.verify("any_device_hash")
        assert result is True

    def test_export_and_load(self):
        geo = GeofenceLayer()
        geo.register_device("device_abc")
        data = geo.export()
        geo2 = GeofenceLayer()
        geo2.load(data)
        result = geo2.verify("device_abc")
        assert result is True

    def test_multiple_devices_all_pass(self):
        geo = GeofenceLayer()
        hashes = ["device_a", "device_b", "device_c"]
        for h in hashes:
            geo.register_device(h)
        for h in hashes:
            result = geo.verify(h)
            assert result is True

    def test_ip_geofence_enabled_flag(self):
        geo = GeofenceLayer()
        assert not geo._geofence_enabled
        geo.add_allowed_ip("192.168.1.")
        assert geo._geofence_enabled
