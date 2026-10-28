"""P4 fingerprint tests -- L0-L3 cross-validation + risk scoring.

Verifies the headline invariant: independent L1 (protocol) and L2 (role/vendor)
paths must AGREE for a CONFIRMED fingerprint; otherwise it stays unconfirmed.
Also regression-guards the case-insensitive unattributed-vendor penalty.

REAL API: Frame(byts) constructor; classify(frame, sigset) -> flat dict with
L0_sig_hits/L1_protocols/L2_vendor/L2_role/L3/risk_score/risk_class/flags_risk.
"""
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (_ROOT, os.path.dirname(os.path.abspath(__file__))):
    if p not in sys.path:
        sys.path.insert(0, p)

from dpi.dissect import Frame                       # noqa: E402
from dpi.signatures import load_default             # noqa: E402
from fingerprint.fingerprint import classify, risk  # noqa: E402
from build_fixture import tcplike, random_udp       # noqa: E402


def _modbus():
    return Frame(tcplike("001234", "modbus", 502,
                         b"\x00\x07\x00\x00\x00\x06\x01\x04\x00\x00\x00\x01"))


def _dnp3():
    return Frame(tcplike("001a11", "dnp3-abb", 20000, b"\x05\x04\x00\x00\x01"))


def _unknown_uds():
    return Frame(random_udp("00dead", "unknown", 4406, b"\x00\x01\x02\x03"))


class TestClassification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sigset = load_default("dpi/signatures")

    def test_crossval_confirmed_modbus(self):
        fp = classify(_modbus(), self.sigset)
        self.assertTrue(fp["L1_protocols"])
        self.assertEqual(fp["L2_role"], "modbus-server")
        self.assertEqual(fp["L3"], "confirmed")

    def test_crossval_unconfirmed_unknown(self):
        fp = classify(_unknown_uds(), self.sigset)
        self.assertEqual(fp["L3"], "unknown")
        self.assertIn("crossval_unconfirmed", fp["flags_risk"])

    def test_dnp3_confirmed(self):
        fp = classify(_dnp3(), self.sigset)
        self.assertIn("dnp3", fp["L1_protocols"])
        self.assertEqual(fp["L3"], "confirmed")

    def test_unattributed_vendor_flagged(self):
        fp = classify(_modbus(), self.sigset)
        self.assertIn("unattributed_vendor", fp["flags_risk"])
        self.assertIn("modbus_server_exposed", fp["flags_risk"])

    def test_modbus_exposed_flag_and_risk(self):
        fp = classify(_modbus(), self.sigset)
        self.assertIn("modbus_server_exposed", fp["flags_risk"])
        rs = risk(fp)
        self.assertGreaterEqual(rs["score"], 30)
        self.assertIn(rs["level"], ("medium", "high"))

    def test_risk_scoring_monotone(self):
        exposed = risk(classify(_modbus(), self.sigset))["score"]
        benign = risk(classify(_unknown_uds(), self.sigset))["score"]
        self.assertGreater(exposed, benign)


if __name__ == "__main__":
    unittest.main(verbosity=2)
