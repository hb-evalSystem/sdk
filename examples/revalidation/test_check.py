import json
import unittest
from pathlib import Path
from check import compare


def read(name):
    return json.loads(Path(__file__).with_name(name + ".json").read_text())


class RevalidationTests(unittest.TestCase):
    def setUp(self):
        self.before = read("baseline")
        self.after = read("candidate")

    def status(self):
        return {k: v["status"] for k, v in compare(self.before, self.after).items()}

    def test_isolated_change(self):
        self.assertEqual(self.status(), {"refund": "RETEST", "shipment_status": "APPLIES"})

    def test_shared_change(self):
        self.after["components"]["retry"] = "v2"
        self.assertEqual(set(self.status().values()), {"RETEST"})

    def test_incomplete_scope(self):
        del self.after["components"]["shipping"]
        self.assertEqual(self.status()["shipment_status"], "UNKNOWN")

    def test_unobserved_baseline(self):
        del self.before["actions"]["shipment_status"]["passed_test"]
        self.assertEqual(self.status()["shipment_status"], "UNKNOWN")

    def test_test_changed(self):
        self.after["actions"]["shipment_status"]["test"] = "shipment_read@2"
        self.assertEqual(self.status()["shipment_status"], "RETEST")

    def test_missing_action(self):
        del self.after["actions"]["refund"]
        self.assertEqual(self.status()["refund"], "UNKNOWN")
