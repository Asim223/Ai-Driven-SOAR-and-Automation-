
import unittest
from soar_lab.pipeline import incident_features, summarize


def event(event_id, event_type, severity, action="observed"):
    return {
        "event_id": event_id,
        "event_type": event_type,
        "source": "endpoint",
        "severity": severity,
        "action": action,
        "message": "",
    }


class CapstoneFeatureTests(unittest.TestCase):

    def test_unrelated_severity_does_not_promote_process(self):
        group = [
            event("T1", "process_start", 15),
            event("T2", "account_lockout", 90),
        ]
        self.assertEqual(incident_features(group)["malware_signal"], 0)

    def test_high_severity_process_retains_signal(self):
        group = [event("T1", "process_start", 80)]
        self.assertEqual(incident_features(group)["malware_signal"], 1)

    def test_prevention_context_reaches_summary(self):
        group = [
            event("T1", "message_blocked", 55, "blocked"),
            event("T2", "file_quarantined", 60, "quarantined"),
        ]
        features = incident_features(group)
        result = summarize(group, 83, {"features": features})
        context = result["outcome_context"]
        self.assertEqual(
            context["assessment"],
            "prevention_recorded_for_observed_threat_events",
        )
        self.assertEqual(context["prevented_event_ids"], ["T1", "T2"])
        self.assertIn(context["assessment"], result["summary"])
        # Quarantine remains a threat-detection signal.
        self.assertEqual(features["malware_signal"], 1)

    def test_blocked_step_does_not_hide_other_activity(self):
        group = [
            event("T1", "credential_access", 92, "blocked"),
            event("T2", "large_upload", 90, "allowed"),
        ]
        result = summarize(
            group, 97, {"features": incident_features(group)}
        )
        context = result["outcome_context"]
        self.assertEqual(
            context["assessment"], "mixed_prevention_and_other_activity"
        )
        self.assertEqual(context["other_threat_event_ids"], ["T2"])
