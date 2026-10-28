"""P4 DPI unit tests -- dissect + signature matching (invariant: passive only).

Builds the 4-frame fixture via testvectors/build_fixture.py and asserts L0/L1/L2
extraction is correct and that the unknown frame is handled. No sockets, no
network, no active probing -- these tests exercise the passive pipeline only.

REAL API (dpi/dissect.py): Frame(byts) constructor; attributes
src_oui/dst_oui/is_tcp/is_udp/l4_proto/dport/src_ip/dst_ip/app/truncated;
as_ocsf_network() for the OCSF projection (which carries 'protocol').
"""
import os
import sys
import unittest

# Make both repo root and testvectors/ importable (run either way).
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (_ROOT, os.path.dirname(os.path.abspath(__file__))):
    if p not in sys.path:
        sys.path.insert(0, p)

from dpi.dissect import Frame            # noqa: E402
from dpi.signatures import load_default  # noqa: E402
from build_fixture import tcplike, random_udp  # noqa: E402


def _proto(f):
    return f.as_ocsf_network()["protocol"]


def _modbus():
    app = b"\x00\x07\x00\x00\x00\x06\x01\x04\x00\x00\x00\x01"
    return Frame(tcplike("001234", "modbus", 502, app))


def _dnp3():
    app = b"\x05\x04\x00\x00\x01"
    return Frame(tcplike("001a11", "dnp3-abb", 20000, app))


def _s7():
    app = bytes([0x03, 0x00, 0x08, 0x00, 0x14, 0x00, 0x01])
    return Frame(tcplike("001942", "s7-siemens", 102, app))


def _unknown_uds():
    app = b"\x00\x01\x02\x03"
    return Frame(random_udp("00dead", "unknown", 4406, app))


class TestDissect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sigset = load_default("dpi/signatures")

    def test_modbus_hit(self):
        f = _modbus()
        self.assertEqual(_proto(f), "tcp")
        self.assertEqual(f.dport, 502)
        hits = self.sigset.match_frame(f)
        self.assertIn("P4-MODBUS-TCP-001", [h["sig_id"] for h in hits])
        self.assertIn("modbus_tcp", sorted({h["protocol"] for h in hits}))

    def test_dnp3_hit(self):
        f = _dnp3()
        self.assertEqual(_proto(f), "tcp")
        self.assertEqual(f.dport, 20000)
        protos = sorted({h["protocol"] for h in self.sigset.match_frame(f)})
        self.assertIn("dnp3", protos)

    def test_s7_hit(self):
        f = _s7()
        self.assertEqual(f.dport, 102)
        protos = sorted({h["protocol"] for h in self.sigset.match_frame(f)})
        self.assertIn("s7comm", protos)

    def test_unknown_udp_no_hit(self):
        f = _unknown_uds()
        self.assertEqual(_proto(f), "udp")
        self.assertEqual(self.sigset.match_frame(f), [])

    def test_oem_truncated_no_crash(self):
        f = Frame(b"\x00" * 10)
        self.assertTrue(f.truncated)
        self.assertIsNone(f.src_ip)
        self.assertIsNone(f.dst_ip)
        self.sigset.match_frame(f)


class TestOui(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sigset = load_default("dpi/signatures")

    def test_oui_known_vendors(self):
        self.assertEqual(self.sigset.vendor_for_oui("001a11"), "ABB")
        self.assertEqual(self.sigset.vendor_for_oui("001942"), "Siemens")

    def test_oui_unknown(self):
        self.assertEqual(self.sigset.vendor_for_oui("001234"), "unknown")
        self.assertEqual(self.sigset.vendor_for_oui(None), "unknown")


if __name__ == "__main__":
    unittest.main(verbosity=2)
