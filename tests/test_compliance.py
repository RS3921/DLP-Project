"""Tests for the enterprise compliance readiness report."""

import tempfile
import time
import unittest
from pathlib import Path

from server.enterprise_store import EnterpriseStore


class ComplianceReportTests(unittest.TestCase):
    def test_default_report_has_frameworks_and_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EnterpriseStore(Path(directory) / "enterprise_state.json")
            report = store.compliance_report()

        self.assertEqual(report["total_controls"], 8)
        self.assertEqual(
            {framework["id"] for framework in report["frameworks"]},
            {"iso27001", "gdpr", "soc2"},
        )
        self.assertEqual(report["score"], 75)

    def test_live_endpoint_and_event_complete_the_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EnterpriseStore(Path(directory) / "enterprise_state.json")
            store._state["agents"]["agent-1"] = {
                "agent_id": "agent-1",
                "last_seen": time.time(),
                "revoked": False,
                "agent_token_hash": "stored-hash",
            }
            store._state["events"].append({"type": "test_event"})
            report = store.compliance_report()

        self.assertEqual(report["score"], 100)
        self.assertEqual(report["status"], "ready")
        self.assertTrue(all(control["status"] == "pass" for control in report["controls"]))

    def test_existing_state_is_migrated_with_compliance_config(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "enterprise_state.json"
            state_path.write_text(
                '{"agents": {}, "events": [], "policies": {}}',
                encoding="utf-8",
            )
            store = EnterpriseStore(state_path)

        self.assertIn("compliance", store._state)


if __name__ == "__main__":
    unittest.main()
