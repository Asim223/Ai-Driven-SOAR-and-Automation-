import unittest
from soar_lab.pipeline import normalize_event


class NormalizationExtraTests(unittest.TestCase):
    def make_event(self):
        return {
            "event_id": "TEST-01",
            "timestamp": "2026-08-19T13:00:00+05:00",
            "source": " EMAIL ",
            "event_type": " Delivered ",
            "severity": 50,
        }

    def test_missing_event_id_rejected(self):
        event = self.make_event()
        del event["event_id"]
        with self.assertRaises(ValueError):
            normalize_event(event)

    def test_negative_severity_clamped(self):
        event = self.make_event()
        event["severity"] = -10
        self.assertEqual(normalize_event(event)["severity"], 0)

    def test_input_preserved_and_fields_normalized(self):
        event = self.make_event()
        before = event.copy()

        result = normalize_event(event)

        self.assertEqual(event, before)
        self.assertIsNot(result, event)
        self.assertEqual(result["timestamp"], "2026-08-19T08:00:00Z")
        self.assertEqual(result["source"], "email")
        self.assertEqual(result["event_type"], "delivered")
