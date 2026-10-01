
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app


class AuditAppendTests(unittest.TestCase):

    def test_append_preserves_existing_bytes_and_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            runtime = Path(folder)
            with patch.object(app, "RUNTIME", runtime):
                first = app.append_decision({"status": "simulated"})
                before = (runtime / "decisions.jsonl").read_bytes()
                second = app.append_decision({"status": "denied"})
                after = (runtime / "decisions.jsonl").read_bytes()

                self.assertTrue(after.startswith(before))
                self.assertEqual(second[0], first[0])
                self.assertEqual(
                    second[1]["previous_hash"], first[0]["record_hash"]
                )

    def test_tampering_blocks_append_without_rewriting_file(self):
        with tempfile.TemporaryDirectory() as folder:
            runtime = Path(folder)
            with patch.object(app, "RUNTIME", runtime):
                app.append_decision({"status": "denied"})
                path = runtime / "decisions.jsonl"
                row = json.loads(path.read_text())
                row["status"] = "simulated"
                path.write_text(json.dumps(row) + "\n", encoding="utf-8")
                tampered = path.read_bytes()

                with self.assertRaisesRegex(ValueError, "integrity"):
                    app.append_decision({"status": "new"})

                self.assertEqual(path.read_bytes(), tampered)

    def test_caller_cannot_supply_hash_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            runtime = Path(folder)
            with patch.object(app, "RUNTIME", runtime):
                with self.assertRaises(ValueError):
                    app.append_decision({
                        "status": "simulated",
                        "record_hash": "forged",
                    })
                self.assertFalse((runtime / "decisions.jsonl").exists())
