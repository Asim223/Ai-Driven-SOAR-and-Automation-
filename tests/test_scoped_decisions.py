
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app


class ScopedDecisionTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.runtime = Path(self.temp.name)
        patcher = patch.object(app, "RUNTIME", self.runtime)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.dataset = Path(__file__).resolve().parents[1] / "lab_data/training"
        self.incidents = app.run_pipeline(self.dataset, self.runtime)
        critical = next(i for i in self.incidents if i["risk_score"] >= 85)
        self.body = {
            "incident_id": critical["incident_id"],
            "action": "isolate_endpoint",
            "decision": "approve",
            "analyst": "Classroom Test Analyst",
        }

    def test_repeat_returns_same_record_without_append(self):
        first = app.record_human_decision(self.body)
        before = (self.runtime / "decisions.jsonl").read_bytes()
        second = app.record_human_decision(self.body)
        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])
        self.assertEqual(first["record"], second["record"])
        self.assertEqual(
            before, (self.runtime / "decisions.jsonl").read_bytes()
        )

    def test_new_run_has_disjoint_ids_and_rejects_stale_request(self):
        first_ids = {i["incident_id"] for i in self.incidents}
        second = app.run_pipeline(self.dataset, self.runtime)
        self.assertTrue(first_ids.isdisjoint(
            {i["incident_id"] for i in second}
        ))
        with self.assertRaises(KeyError):
            app.record_human_decision(self.body)

    def test_conflicting_decision_rejected(self):
        app.record_human_decision(self.body)
        before = (self.runtime / "decisions.jsonl").read_bytes()
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            app.record_human_decision({**self.body, "decision": "deny"})
        self.assertEqual(
            before, (self.runtime / "decisions.jsonl").read_bytes()
        )

    def test_replay_rejects_tampered_history(self):
        app.record_human_decision(self.body)
        path = self.runtime / "decisions.jsonl"
        row = json.loads(path.read_text())
        row["analyst"] = "Altered Name"
        path.write_text(json.dumps(row) + "\n", encoding="utf-8")
        before = path.read_bytes()
        with self.assertRaisesRegex(ValueError, "integrity"):
            app.record_human_decision(self.body)
        self.assertEqual(before, path.read_bytes())
