import unittest
from soar_lab.pipeline import enrich_event


class EnrichmentExtraTests(unittest.TestCase):
    def test_ioc_confidence_boundary(self):
        event = {"domain": "BAD.EXAMPLE"}
        for confidence, expected in [(69, False), (70, True)]:
            with self.subTest(confidence=confidence):
                indicators = [{
                    "value": "bad.example",
                    "confidence": confidence,
                    "labels": ["phishing"],
                }]
                result = enrich_event(event, {}, {}, indicators)
                self.assertEqual(result["ioc_match"], expected)

    def test_string_privilege_flags(self):
        for flag in ("0", "1"):
            with self.subTest(flag=flag):
                result = enrich_event(
                    {"user": "test.user"},
                    {},
                    {"test.user": {"privileged": flag}},
                    [],
                )
                self.assertEqual(result["privileged_identity"], int(flag))

    def test_unknown_entities_have_defaults(self):
        result = enrich_event(
            {"asset": "UNKNOWN", "user": "unknown.user"}, {}, {}, []
        )
        self.assertEqual(result["asset_criticality"], 0)
        self.assertEqual(result["privileged_identity"], 0)
        self.assertEqual(result["business_unit"], "")
        self.assertEqual(result["identity_risk_tier"], "")
        self.assertEqual(result["ioc_matches"], [])
        self.assertFalse(result["ioc_match"])

    def test_original_event_unchanged(self):
        event = {"asset": "WS-01", "domain": "bad.example"}
        before = event.copy()
        result = enrich_event(event, {}, {}, [])
        self.assertEqual(event, before)
        self.assertIsNot(result, event)
