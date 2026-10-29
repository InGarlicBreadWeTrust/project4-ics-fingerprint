"""End-to-end passivity smoke test for project4-ics-fingerprint.

Runs the reference pipeline (ingest -> dpi -> fingerprint -> OCSF report) on the
synthetic ``testvectors/four_frames.pcap`` into a throwaway output directory and
asserts OCSF events are produced. This PROVES the pipeline works end-to-end.

Zero network by construction (see SAFETY-POLICY.md H1/H2 and safety/attestation.py):
ingest, dpi, fingerprint, and output never open a socket or spawn a network child,
so the pipeline is passive. The static (safety/egress_guard.py) and runtime
(safety/attestation.py) gates enforce this independently.

Usage:
    python3 testvectors/run_e2e.py            # uses committed fixture
    python3 testvectors/run_e2e.py out.pcap   # uses an explicit pcap
"""
import os
import sys
import tempfile

# Make the repo root importable regardless of the caller's cwd.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from output.report import run_pipeline   # noqa: E402
from dpi.signatures import load_default  # noqa: E402


def main(argv=None):
    argv = sys.argv[1:] if argv is None else sys.argv[1:]
    pcap = argv[0] if argv else "testvectors/four_frames.pcap"
    if not os.path.exists(pcap):
        print("run_e2e: fixture %r not found; run "
              "python3 testvectors/build_fixture.py first" % pcap)
        return 1
    with tempfile.TemporaryDirectory() as out:
        sigset = load_default("dpi/signatures")
        results = run_pipeline(pcap, sigset, out)
        n = len(results)
        if n == 0:
            print("run_e2e: FAIL - zero OCSF events produced")
            return 1
        print("run_e2e: OK - %d OCSF event(s) from %s" % (n, pcap))
        return 0


if __name__ == "__main__":
    sys.exit(main())
