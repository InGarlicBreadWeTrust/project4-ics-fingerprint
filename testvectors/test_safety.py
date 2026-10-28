"""P4 safety tests -- the zero-egress static guard + non-vacuity proof.

This is the core of "passive by construction": the guard must be PROVEN to flag
bad code and spare clean code (not vacuously pass by matching nothing), in-scope
OT literals must be caught even in the out-of-band module, and the real pipeline
core must currently pass clean.
"""
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (_ROOT, os.path.dirname(os.path.abspath(__file__))):
    if p not in sys.path:
        sys.path.insert(0, p)

from safety import egress_guard as eg   # noqa: E402


class TestNonVacuity(unittest.TestCase):
    def test_bad_flagged_and_clean_spared(self):
        results = eg.negative_tests()
        for label, ok, detail in results:
            self.assertTrue(ok, "%s failed: %s" % (label, detail))

    def test_bad_kinds_present(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            bad = os.path.join(td, "bad.py")
            open(bad, "w").write(eg._BAD)
            clean = os.path.join(td, "clean.py")
            open(clean, "w").write(eg._CLEAN)
            self.assertGreaterEqual(len(eg._lint_python(bad)), 3)
            self.assertEqual(eg._lint_python(clean), [])


class TestShellToolRegex(unittest.TestCase):
    # The _SHELL_TOOL regex must require an iproute2 subcommand so it does not
    # false-positive on variable names like `ip` or substrings like `tc`.
    def test_ip_variable_not_flagged(self):
        src = "ip = 192.168.0.7\n"
        self.assertIsNone(eg._SHELL_TOOL.search(src))

    def test_ip_link_flagged(self):
        src = 'os.system("ip link show")\n'
        self.assertIsNotNone(eg._SHELL_TOOL.search(src))

    def test_tc_variable_not_flagged(self):
        src = "tcp_port = 502\n"
        self.assertIsNone(eg._SHELL_TOOL.search(src))

    def test_tc_qdisc_flagged(self):
        src = 'os.system("tc qdisc add dev eth0 root")\n'
        self.assertIsNotNone(eg._SHELL_TOOL.search(src))


class TestInScopeLiteral(unittest.TestCase):
    def test_literal_detected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            f = os.path.join(td, "x.py")
            open(f, "w").write('os.system("nmap 10.99.99.100")\n')
            vs = eg._lint_python(f)
            self.assertTrue(any(v.kind == "in-scope-literal" for v in vs))
            self.assertTrue(any(v.kind == "shellout" for v in vs))

    def test_clean_file_no_literal(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            f = os.path.join(td, "c.py")
            open(f, "w").write("x = 0\n")
            self.assertEqual(eg._lint_python(f), [])


class TestCoreInvariant(unittest.TestCase):
    def test_real_core_passes_clean(self):
        # The entire pipeline core must have ZERO violations today.
        self.assertEqual(eg.scan_core(eg.ROOTS), [])

    def test_outband_module_clean(self):
        # The out-of-band module must carry its marker and use an ALLOWED tool only.
        self.assertEqual(list(eg.lint_outband("output/egress_outband.py")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
