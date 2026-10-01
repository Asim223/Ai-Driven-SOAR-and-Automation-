
import sqlite3
import tempfile
import unittest
from pathlib import Path

from soar_lab.idempotency_demo import simulate_once


class IdempotencyDemoTests(unittest.TestCase):

    def test_replay_after_connection_close_creates_one_record(self):
        with tempfile.TemporaryDirectory() as folder:
            db_path = Path(folder) / "ledger.sqlite3"
            args = {
                "incident_id": "TEST-001",
                "entity_id": "WS-TEST",
                "action": "isolate_endpoint",
                "approval": {
                    "incident_id": "TEST-001",
                    "action": "isolate_endpoint",
                    "decision": "approve",
                    "status": "simulated",
                    "analyst": "Classroom Test Analyst",
                    "dry_run": True,
                },
            }

            first = simulate_once(db_path, **args)
            # The first call closed its connection. Replay reads disk state.
            second = simulate_once(db_path, **args)

            self.assertEqual(first["status"], "simulated")
            self.assertEqual(second["status"], "already_completed")
            self.assertEqual(
                first["idempotency_key"], second["idempotency_key"]
            )

            with sqlite3.connect(str(db_path)) as db:
                count = db.execute(
                    "SELECT COUNT(*) FROM simulations"
                ).fetchone()[0]
            self.assertEqual(count, 1)

    def test_denial_creates_no_simulation(self):
        with tempfile.TemporaryDirectory() as folder:
            db_path = Path(folder) / "ledger.sqlite3"
            result = simulate_once(
                db_path,
                incident_id="TEST-001",
                entity_id="test.user",
                action="disable_identity",
                approval={
                    "incident_id": "TEST-001",
                    "action": "disable_identity",
                    "decision": "deny",
                    "status": "denied",
                    "analyst": "Classroom Test Analyst",
                    "dry_run": True,
                },
            )
            self.assertEqual(result["status"], "denied")
            self.assertFalse(db_path.exists())


if __name__ == "__main__":
    unittest.main()
