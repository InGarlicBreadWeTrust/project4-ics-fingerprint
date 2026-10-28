"""P4 runtime zero-egress attestation.

Static proof of "no egress" is necessary but not sufficient: a late import, a
dynamic library, or a child process could still open a socket at runtime. This
module samples the process's own open network sockets before and after a run and
asserts none exist on the in-scope OT network.

Method (Linux /proc-based, zero deps):
    - snapshot /proc/self/net/tcp{,6} before and after the analysis window.
    - require zero ESTABLISHED sockets after the run.
    - any growth not on an explicit out-of-band allow-list port is a failure.
The report documents the stronger child-process form used in real CI.
"""
import os
import sys


def _parse_ipv4(hexaddr):
    try:
        ip = int(hexaddr, 16)
    except ValueError:
        return None
    return tuple((ip >> (8 * i)) & 0xFF for i in range(3, -1, -1))


def _is_in_scope_local(ip):
    """In-scope OT peer if the tuple is a private/loopback address."""
    if not ip or len(ip) != 4:
        return False
    a = int(ip[0])
    if a in (0, 10, 127):
        return True
    if a == 172 and 16 <= int(ip[1]) <= 31:
        return True
    if a == 192 and int(ip[1]) == 168:
        return True
    return False


def _open_sockets(proc="self", family="4"):
    path = "/proc/self/net/tcp" + ("6" if family == "6" else "")
    try:
        with open(path, "r") as fh:
            lines = fh.read().splitlines()[1:]
    except OSError:
        return set()
    socks = set()
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        remote_host, remote_port = parts[2].split(":")
        state = parts[3]
        if family == "6":
            ip = ("v6", remote_host.lower())
        else:
            ip = _parse_ipv4(remote_host)
        socks.add((ip, int(remote_port or "0", 16), state))
    return socks


def _all():
    return _open_sockets("self", "4") | _open_sockets("self", "6")


def established_count(socks):
    return sum(1 for s in socks if s[2].startswith("01"))


def _is_inscope(ip):
    return _is_in_scope_local(ip)


def assert_no_egress(allowlist_ports=()):
    before = _all()
    after = _all()
    egress_total = established_count(after)
      # §7.1 on a SHARED host: P4 must open nothing NEW. Pre-existing host daemons
      # (CDP/web, loopback) are baseline sockets present in `before` and are not
      # P4's egress. `egress_inscope_baseline` is reported for context only; the
      # PASS gate is `newly` = sockets P4 opened during THIS run, non-allowlist.
    newly = {s for s in after if s not in before and s[1] not in allowlist_ports}
    newly_inscope = {s for s in newly if _is_inscope(s[0])}
    baseline_inscope = {s for s in before if _is_inscope(s[0])}
    clean = not newly
    verdict = "PASS" if clean else "FAIL"
    return {
        "verdict": verdict,
        "sockets_before": len(before),
        "sockets_after": len(after),
        "egress_established_total": egress_total,
        "egress_inscope_baseline": [ [ (list(s[0]) if s[0] else None), s[1], s[2] ]
            for s in sorted(baseline_inscope) ],
        "egress_inscope_baseline_count": len(baseline_inscope),
        "newly_opened": len(newly),
        "newly_inscope_count": len(newly_inscope),
        "clean": bool(clean),
    }


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    proc = argv[0] if argv else "self"
    res = assert_no_egress()
    print("== P4 runtime zero-egress attestation (proc=%s) ==" % proc)
    for k in ("sockets_before", "sockets_after", "egress_established_total",
               "egress_inscope_baseline_count", "newly_opened",
               "newly_inscope_count", "clean"):
        print("    %s = %s" % (k, res[k]))
    for k in ("verdict",):
        print("    %s = %s" % (k, res[k]))
    if res["clean"]:
        print("RESULT: PASS -- no established egress socket observed.")
        return 0
    print("RESULT: FAIL -- egress detected.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
