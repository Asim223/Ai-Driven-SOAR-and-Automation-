
import tempfile
import unittest
from pathlib import Path

from soar_lab import run_pipeline
from soar_lab.pipeline import enrich_event


class Lab6SafetyTests(unittest.TestCase):

    def test_low_confidence_matching_ioc_is_not_trusted(self):
        event = {
            "event_id": "LAB6-IOC-001",
            "timestamp": "2026-08-19T08:00:00Z",
            "source": "proxy",
            "event_type": "url_click",
            "severity": 50,
            "user": "analyst.one",
            "asset": "WS-01",
            "domain": "lab6-indicator.example",
        }
        assets = {
            "WS-01": {
                "criticality": "3",
                "business_unit": "Test",
            }
        }
        identities = {
            "analyst.one": {
                "privileged": "0",
                "risk_tier": "low",
            }
        }

        def evaluate(confidence):
            return enrich_event(
                dict(event),
                assets,
                identities,
                [{
                    "value": "lab6-indicator.example",
                    "confidence": confidence,
                    "labels": ["phishing"],
                }],
            )

        # Positive control proves the indicator matches the event.
        self.assertTrue(evaluate(70)["ioc_match"])

        # The same indicator below the threshold must not be trusted.
        self.assertFalse(evaluate(69)["ioc_match"])
        self.assertFalse(evaluate(0)["ioc_match"])

    def test_critical_without_approval_stays_pending(self):
        project = Path(__file__).resolve().parents[1]
        dataset = project / "lab_data" / "training"

        # Temporary outputs preserve the application's runtime evidence.
        with tempfile.TemporaryDirectory() as folder:
            incidents = run_pipeline(dataset, Path(folder))

        critical = [
            incident for incident in incidents
            if incident["risk_score"] >= 85
        ]
        self.assertTrue(
            critical,
            "The training fixture must contain a critical incident.",
        )

        for incident in critical:
            with self.subTest(incident_id=incident["incident_id"]):
                actions = incident["actions"]
                self.assertTrue(actions)
                self.assertTrue(
                    all(a.get("dry_run") is True for a in actions)
                )

                containment = [
                    a for a in actions
                    if a["action"] in {
                        "isolate_endpoint", "disable_identity"
                    }
                ]
                self.assertEqual(len(containment), 2)
                self.assertEqual(
                    {a["action"] for a in containment},
                    {"isolate_endpoint", "disable_identity"},
                )

                for action in containment:
                    self.assertIs(action["approval_required"], True)
                    self.assertEqual(
                        action["status"], "awaiting_approval"
                    )


if __name__ == "__main__":
    unittest.main()
