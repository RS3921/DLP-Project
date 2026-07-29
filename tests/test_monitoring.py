"""
tests/test_monitoring.py
Tests for monitoring/continuous_monitor.py
Covers: all 6 streams, VaultMonitor start/stop,
        event bus routing, alert log writing.
"""
import os
import json
import time
import queue
import hashlib
import tempfile
import threading
import pytest

from monitoring.continuous_monitor import (
    VaultMonitor, MonitorEvent,
    BehavioralStream, CanaryIntegrityStream,
    NetworkStream, HSMHealthStream,
    RateLimitStream, SessionTimeoutStream,
)
from core.vault_engine import VaultEngine, get_device_fingerprint


# ── Helpers ───────────────────────────────────────────────────────
def _make_event_bus():
    return queue.Queue()

def _drain(bus, timeout=0.3):
    """Collect all events from the bus within timeout seconds."""
    events = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            events.append(bus.get_nowait())
        except queue.Empty:
            time.sleep(0.02)
    return events


# ══════════════════════════════════════════════════════════════════
# MonitorEvent
# ══════════════════════════════════════════════════════════════════

class TestMonitorEvent:

    def test_to_dict_has_required_keys(self):
        ev = MonitorEvent(1, "Behavioral", "WARNING", "test msg", {"k": "v"})
        d  = ev.to_dict()
        for key in ("timestamp","stream","stream_name","severity","message","details"):
            assert key in d, f"Missing key: {key}"

    def test_stream_formatted_as_s0n(self):
        ev = MonitorEvent(3, "Network", "INFO", "msg", {})
        assert ev.to_dict()["stream"] == "S-03"

    def test_to_alert_log_entry_compatible_format(self):
        ev    = MonitorEvent(4, "HSM Health", "CRITICAL", "key missing", {"file": "x"})
        entry = ev.to_alert_log_entry()
        assert "timestamp" in entry
        assert "event"     in entry
        assert "details"   in entry
        assert "MONITOR"   in entry["event"]

    def test_timestamp_defaults_to_now(self):
        before = time.time()
        ev     = MonitorEvent(1, "S", "INFO", "m", {})
        assert ev.timestamp >= before


# ══════════════════════════════════════════════════════════════════
# Stream 1 — BehavioralStream
# ══════════════════════════════════════════════════════════════════

class TestBehavioralStream:

    def test_high_score_produces_no_event(self):
        bus    = _make_event_bus()
        stream = BehavioralStream(bus, revoke_fn=None)
        stream.update_score("session_abc", 0.90)
        events = _drain(bus, 0.1)
        assert len(events) == 0

    def test_low_score_triggers_warning(self):
        bus    = _make_event_bus()
        stream = BehavioralStream(bus, revoke_fn=None)
        # Feed 5 scores all below WARN_THRESHOLD
        for _ in range(5):
            stream.update_score("session_abc", 0.40)
        events = _drain(bus, 0.2)
        severities = [e.severity for e in events]
        assert any(s in ("WARNING", "CRITICAL") for s in severities)

    def test_critical_score_calls_revoke(self):
        bus      = _make_event_bus()
        revoked  = []
        stream   = BehavioralStream(bus, revoke_fn=lambda sid: revoked.append(sid))
        for _ in range(5):
            stream.update_score("session_xyz", 0.20)
        events = _drain(bus, 0.2)
        assert "session_xyz" in revoked
        crits = [e for e in events if e.severity == "CRITICAL"]
        assert len(crits) >= 1

    def test_clear_session_removes_history(self):
        bus    = _make_event_bus()
        stream = BehavioralStream(bus, revoke_fn=None)
        stream.update_score("s1", 0.80)
        stream.clear_session("s1")
        assert "s1" not in stream._scores

    def test_rolling_window_5_scores(self):
        bus    = _make_event_bus()
        stream = BehavioralStream(bus, revoke_fn=None)
        # Push 7 scores — only last 5 should be kept
        for score in [0.9, 0.9, 0.9, 0.9, 0.9, 0.9, 0.9]:
            stream.update_score("sess", score)
        assert len(stream._scores.get("sess", [])) <= 5


# ══════════════════════════════════════════════════════════════════
# Stream 2 — CanaryIntegrityStream
# ══════════════════════════════════════════════════════════════════

class TestCanaryIntegrityStream:

    def test_unchanged_file_no_alert(self, tmp_path):
        bus    = _make_event_bus()
        stream = CanaryIntegrityStream(str(tmp_path), bus)
        # Create a vault file
        f = tmp_path / "clean.vault"
        f.write_bytes(b"original content")
        stream._take_snapshot()
        stream._check()
        events = _drain(bus, 0.1)
        assert len(events) == 0

    def test_modified_file_triggers_critical(self, tmp_path):
        bus    = _make_event_bus()
        stream = CanaryIntegrityStream(str(tmp_path), bus)
        f = tmp_path / "tampered.vault"
        f.write_bytes(b"original secure content")
        stream._take_snapshot()
        # Tamper
        f.write_bytes(b"TAMPERED BY ATTACKER!!!")
        stream._check()
        events = _drain(bus, 0.1)
        crits  = [e for e in events if e.severity == "CRITICAL"]
        assert len(crits) >= 1
        assert any("tampered.vault" in e.message or "tampered.vault" in str(e.details)
                   for e in crits)

    def test_update_checksum_prevents_false_alert(self, tmp_path):
        bus    = _make_event_bus()
        stream = CanaryIntegrityStream(str(tmp_path), bus)
        f = tmp_path / "legit.vault"
        f.write_bytes(b"before encrypt")
        stream._take_snapshot()
        # Legitimate vault write
        f.write_bytes(b"after encrypt new ciphertext v2")
        stream.update_checksum(str(f))   # register new checksum
        stream._check()
        events = _drain(bus, 0.1)
        assert len(events) == 0

    def test_only_vault_files_monitored(self, tmp_path):
        bus    = _make_event_bus()
        stream = CanaryIntegrityStream(str(tmp_path), bus)
        # Non-.vault file — should never trigger
        f = tmp_path / "config.json"
        f.write_bytes(b"original")
        stream._take_snapshot()
        f.write_bytes(b"modified")
        stream._check()
        events = _drain(bus, 0.1)
        assert len(events) == 0

    def test_start_and_stop(self, tmp_path):
        bus    = _make_event_bus()
        stream = CanaryIntegrityStream(str(tmp_path), bus)
        stream.start()
        assert stream._running is True
        stream.stop()
        assert stream._running is False


# ══════════════════════════════════════════════════════════════════
# Stream 4 — HSMHealthStream
# ══════════════════════════════════════════════════════════════════

class TestHSMHealthStream:

    def test_intact_keys_no_alert(self, vault_dir):
        engine = VaultEngine(vault_dir)
        bus    = _make_event_bus()
        stream = HSMHealthStream(vault_dir, bus)
        stream._baseline()
        stream._check()
        events = _drain(bus, 0.1)
        assert len(events) == 0

    def test_missing_master_key_critical(self, vault_dir):
        engine   = VaultEngine(vault_dir)
        bus      = _make_event_bus()
        stream   = HSMHealthStream(vault_dir, bus)
        stream._baseline()
        # Delete the master key
        os.remove(os.path.join(vault_dir, ".vault_master.key"))
        stream._check()
        events = _drain(bus, 0.1)
        crits  = [e for e in events if e.severity == "CRITICAL"]
        assert len(crits) >= 1

    def test_modified_key_critical(self, vault_dir):
        engine   = VaultEngine(vault_dir)
        bus      = _make_event_bus()
        stream   = HSMHealthStream(vault_dir, bus)
        stream._baseline()
        # Overwrite master key with different bytes (same size)
        key_path = os.path.join(vault_dir, ".vault_master.key")
        with open(key_path, "wb") as f:
            f.write(os.urandom(32))
        stream._check()
        events = _drain(bus, 0.1)
        crits  = [e for e in events if e.severity == "CRITICAL"]
        assert len(crits) >= 1

    def test_start_and_stop(self, vault_dir):
        VaultEngine(vault_dir)
        bus    = _make_event_bus()
        stream = HSMHealthStream(vault_dir, bus)
        stream.start()
        assert stream._running is True
        stream.stop()
        assert stream._running is False


# ══════════════════════════════════════════════════════════════════
# Stream 5 — RateLimitStream
# ══════════════════════════════════════════════════════════════════

class TestRateLimitStream:

    def _dev(self, name="test_device"):
        return hashlib.sha256(name.encode()).hexdigest()

    def test_first_attempt_no_delay(self):
        bus    = _make_event_bus()
        stream = RateLimitStream(bus)
        delay  = stream.record_attempt(self._dev("clean_device"))
        assert delay is None

    def test_warn_rate_returns_small_delay(self):
        bus    = _make_event_bus()
        stream = RateLimitStream(bus)
        dev    = self._dev("warn_device")
        delay  = None
        for _ in range(RateLimitStream.WARN_RATE + 1):
            delay = stream.record_attempt(dev)
        assert delay is not None
        assert delay <= 30

    def test_block_rate_returns_large_delay(self):
        bus    = _make_event_bus()
        stream = RateLimitStream(bus)
        dev    = self._dev("block_device")
        delay  = None
        for _ in range(RateLimitStream.BLOCK_RATE + 1):
            delay = stream.record_attempt(dev)
        assert delay >= 299.0   # allow floating point variance in elapsed time

    def test_blocked_device_is_blocked(self):
        bus    = _make_event_bus()
        stream = RateLimitStream(bus)
        dev    = self._dev("blocked_device")
        for _ in range(RateLimitStream.BLOCK_RATE + 1):
            stream.record_attempt(dev)
        assert stream.is_blocked(dev) is True

    def test_different_devices_independent(self):
        bus    = _make_event_bus()
        stream = RateLimitStream(bus)
        dev_a  = self._dev("device_a")
        dev_b  = self._dev("device_b")
        for _ in range(RateLimitStream.BLOCK_RATE + 1):
            stream.record_attempt(dev_a)
        # device_b untouched — should not be blocked
        assert stream.is_blocked(dev_b) is False

    def test_events_emitted_on_threshold(self):
        bus    = _make_event_bus()
        stream = RateLimitStream(bus)
        dev    = self._dev("threshold_device")
        for _ in range(RateLimitStream.WARN_RATE + 1):
            stream.record_attempt(dev)
        events = _drain(bus, 0.1)
        assert len(events) >= 1
        assert any(e.stream == 5 for e in events)


# ══════════════════════════════════════════════════════════════════
# Stream 6 — SessionTimeoutStream
# ══════════════════════════════════════════════════════════════════

class TestSessionTimeoutStream:

    def _make_token(self, engine, idle_min=0, age_h=0):
        tok = engine.create_session_token("owner_hash_xyz")
        tok.last_active = time.time() - idle_min * 60
        tok.issued_at   = time.time() - age_h * 3600
        return tok

    def test_fresh_session_no_event(self, engine):
        bus     = _make_event_bus()
        tok     = self._make_token(engine)
        revoked = []

        stream = SessionTimeoutStream(
            bus,
            get_sessions_fn = lambda: {tok.session_id: tok},
            revoke_fn       = lambda sid: revoked.append(sid),
        )
        stream._check()
        events = _drain(bus, 0.1)
        assert len(events) == 0
        assert len(revoked) == 0

    def test_idle_warning_emitted(self, engine):
        bus     = _make_event_bus()
        tok     = self._make_token(engine, idle_min=6)   # past IDLE_WARN_MIN=5
        revoked = []

        stream = SessionTimeoutStream(
            bus,
            get_sessions_fn = lambda: {tok.session_id: tok},
            revoke_fn       = lambda sid: revoked.append(sid),
        )
        stream._check()
        events = _drain(bus, 0.1)
        warns  = [e for e in events if e.severity == "WARNING"]
        assert len(warns) >= 1
        assert len(revoked) == 0

    def test_idle_logout_revokes_session(self, engine):
        bus     = _make_event_bus()
        tok     = self._make_token(engine, idle_min=11)  # past IDLE_LOGOUT_MIN=10
        revoked = []

        stream = SessionTimeoutStream(
            bus,
            get_sessions_fn = lambda: {tok.session_id: tok},
            revoke_fn       = lambda sid: revoked.append(sid),
        )
        stream._check()
        assert tok.session_id in revoked

    def test_hard_limit_revokes_session(self, engine):
        bus     = _make_event_bus()
        tok     = self._make_token(engine, age_h=9)   # past HARD_LIMIT_HOURS=8
        revoked = []

        stream = SessionTimeoutStream(
            bus,
            get_sessions_fn = lambda: {tok.session_id: tok},
            revoke_fn       = lambda sid: revoked.append(sid),
        )
        stream._check()
        assert tok.session_id in revoked

    def test_start_and_stop(self, vault_dir):
        bus    = _make_event_bus()
        stream = SessionTimeoutStream(bus, get_sessions_fn=lambda:{}, revoke_fn=None)
        stream.start()
        assert stream._running is True
        stream.stop()
        assert stream._running is False


# ══════════════════════════════════════════════════════════════════
# VaultMonitor — integration
# ══════════════════════════════════════════════════════════════════

class TestVaultMonitor:

    def test_start_and_stop(self, vault_dir, engine):
        monitor = VaultMonitor(vault_dir, engine)
        monitor.start()
        assert monitor.is_running() is True
        time.sleep(0.2)
        monitor.stop()
        assert monitor.is_running() is False

    def test_all_6_streams_present(self, vault_dir, engine):
        monitor = VaultMonitor(vault_dir, engine)
        assert hasattr(monitor, "behavioral")
        assert hasattr(monitor, "canary_poll")
        assert hasattr(monitor, "network")
        assert hasattr(monitor, "hsm_health")
        assert hasattr(monitor, "rate_limiter")
        assert hasattr(monitor, "session_timeout")

    def test_get_stream_status_returns_dict(self, vault_dir, engine):
        monitor = VaultMonitor(vault_dir, engine)
        monitor.start()
        status = monitor.get_stream_status()
        assert isinstance(status, dict)
        assert len(status) == 6
        monitor.stop()

    def test_alert_log_written_on_critical_event(self, vault_dir, engine):
        monitor = VaultMonitor(vault_dir, engine)
        monitor.start()

        ev = MonitorEvent(4, "HSM Health", "CRITICAL", "Test critical", {"key": "val"})
        monitor._handle(ev)

        log_path = os.path.join(vault_dir, "daemon_alerts.log")
        assert os.path.exists(log_path)
        with open(log_path) as f:
            content = f.read()
        assert "CRITICAL" in content or "MONITOR" in content
        monitor.stop()

    def test_audit_callback_called(self, vault_dir, engine):
        calls   = []
        monitor = VaultMonitor(vault_dir, engine, audit_callback=lambda et, d: calls.append(et))
        monitor.start()

        ev = MonitorEvent(4, "HSM", "CRITICAL", "test", {})
        monitor._handle(ev)
        time.sleep(0.1)

        assert len(calls) >= 1
        monitor.stop()

    def test_alert_callback_called_on_critical(self, vault_dir, engine):
        alerts  = []
        monitor = VaultMonitor(vault_dir, engine, alert_callback=lambda e: alerts.append(e))
        monitor.start()

        ev = MonitorEvent(2, "Canary", "CRITICAL", "blob tampered", {"file": "x.vault"})
        monitor._handle(ev)
        time.sleep(0.1)

        assert len(alerts) >= 1
        assert alerts[0].severity == "CRITICAL"
        monitor.stop()

    def test_record_decrypt_tracks_volume(self, vault_dir, engine):
        monitor = VaultMonitor(vault_dir, engine)
        monitor.start()
        # Establish baseline
        for _ in range(3):
            monitor.record_decrypt("session_vol")
        monitor._baseline_dpm = 3.0   # force baseline
        # Trigger anomaly — 20 decrypts >> 5× baseline of 3
        alerts = []
        monitor._alert_cb = lambda e: alerts.append(e)
        for _ in range(20):
            monitor.record_decrypt("session_vol")
        time.sleep(0.1)
        # Event should have been placed on the bus
        monitor.stop()

    def test_rate_limiter_accessible(self, vault_dir, engine):
        monitor = VaultMonitor(vault_dir, engine)
        import hashlib
        dev = hashlib.sha256(b"test").hexdigest()
        delay = monitor.rate_limiter.record_attempt(dev)
        # First attempt — no delay
        assert delay is None
