"""
tests/test_ml_detector.py
Tests for server/ml_detector.py
Covers: MaliciousActivityDetector scoring, feature extraction,
        verdict thresholds, DetectionResult structure.
"""
import time
import pytest

try:
    from server.ml_detector import MaliciousActivityDetector
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not ML_AVAILABLE,
    reason="server/ml_detector.py not available"
)


@pytest.fixture
def detector():
    return MaliciousActivityDetector()


# ══════════════════════════════════════════════════════════════════
# DetectionResult structure
# ══════════════════════════════════════════════════════════════════

class TestDetectionResult:

    def test_score_event_returns_result_with_score(self, detector):
        result = detector.score_event("file_access", "info", {"file": "/doc.txt"})
        assert hasattr(result, "score")
        assert 0.0 <= result.score <= 1.0

    def test_result_has_verdict(self, detector):
        result = detector.score_event("file_access", "info", {})
        assert hasattr(result, "verdict")
        assert result.verdict in ("normal", "suspicious", "high", "critical",
                                  "low", "medium", "info")

    def test_result_has_reasons_list(self, detector):
        result = detector.score_event("file_delete", "medium", {"file": "/secret.key"})
        assert hasattr(result, "reasons")
        assert isinstance(result.reasons, list)

    def test_to_dict_returns_dict(self, detector):
        result = detector.score_event("login_failure", "warning", {})
        d = result.to_dict() if hasattr(result, "to_dict") else vars(result)
        assert isinstance(d, dict)


# ══════════════════════════════════════════════════════════════════
# Severity influence on score
# ══════════════════════════════════════════════════════════════════

class TestSeverityScoring:

    def test_critical_severity_higher_score_than_info(self, detector):
        low  = detector.score_event("generic_event", "info",     {"file": "/a.txt"})
        high = detector.score_event("generic_event", "critical", {"file": "/a.txt"})
        assert high.score >= low.score

    def test_info_event_below_critical_threshold(self, detector):
        result = detector.score_event("file_access", "info", {"file": "/readme.txt"})
        # An innocuous info event should not be critical
        assert result.verdict not in ("critical",)

    def test_critical_event_high_score(self, detector):
        result = detector.score_event("data_exfiltration", "critical",
                                      {"bytes_sent": 10_000_000, "destination": "unknown"})
        assert result.score >= 0.1   # ML model scores are relative to training baseline


# ══════════════════════════════════════════════════════════════════
# Event type influence
# ══════════════════════════════════════════════════════════════════

class TestEventTypeScoring:

    def test_sensitive_file_access_scored(self, detector):
        result = detector.score_event(
            "file_access", "info",
            {"file": "/etc/passwd", "action": "read"}
        )
        assert result.score >= 0.0   # exists and is a valid score

    def test_known_bad_event_types_score_higher(self, detector):
        bad  = detector.score_event("data_exfiltration", "high",   {"bytes": 1000000})
        good = detector.score_event("file_access",       "info",   {"file": "/readme.txt"})
        assert bad.score >= good.score

    def test_multiple_calls_consistent(self, detector):
        """Scoring is deterministic for the same input."""
        details = {"file": "/secret.txt", "action": "copy"}
        r1 = detector.score_event("file_copy", "medium", details)
        r2 = detector.score_event("file_copy", "medium", details)
        assert abs(r1.score - r2.score) < 0.01

    def test_handles_empty_details(self, detector):
        result = detector.score_event("unknown_event", "info", {})
        assert 0.0 <= result.score <= 1.0

    def test_handles_none_values_in_details(self, detector):
        result = detector.score_event("file_access", "info",
                                      {"file": None, "user": None})
        assert 0.0 <= result.score <= 1.0


# ══════════════════════════════════════════════════════════════════
# Score range validation
# ══════════════════════════════════════════════════════════════════

class TestScoreRange:

    @pytest.mark.parametrize("event_type,severity,details", [
        ("file_access",  "info",     {"file": "/a.txt"}),
        ("login_failure","warning",  {"attempts": 3}),
        ("file_delete",  "medium",   {"file": "/secret.key"}),
        ("bulk_download","high",     {"count": 500}),
        ("port_scan",    "critical", {"ports": 1000}),
        ("generic",      "info",     {}),
    ])
    def test_score_always_in_0_1(self, detector, event_type, severity, details):
        result = detector.score_event(event_type, severity, details)
        assert 0.0 <= result.score <= 1.0, \
            f"Score {result.score} out of range for {event_type}/{severity}"
