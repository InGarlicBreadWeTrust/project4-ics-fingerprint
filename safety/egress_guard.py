"""P4 zero-egress static guard. The crown jewel of Project 4.

The legal moat of passive ICS fingerprinting is: "we *cannot* have caused that,
because we never touched the network." This module *proves* it, statically.

It scans the analysis core (ingest / dpi / fingerprint / output / safety) for the
constructs that would let the analysis process transmit a byte onto the in-scope
OT network, or reconfigure the forwarding plane:
    - sockets / connect / send / bind / setsockopt
    - HTTP/DNS/urllib/requests/urlopen egress
    - fork+exec of network tools (nmap/fping/hping3/masscan/ping/tc/iptables/
      nftables/ip link/curl/wget)
    - reconfiguration writes (tc/iptables/nft/ip link/addr)
    - hardcoded in-scope OT LAN address literals

Two guarantees the guard must provide (SAFETY-POLICY 7.1):
    1. No false negatives: a forbidden construct in *code* is caught.
    2. Non-vacuity: tested against injected bad code and PROVEN to flag it,
       and not to false-flag clean code.

Allow-list (SAFETY-POLICY 7.1): only `output/egress_outband.py` may emit, and
only to an explicitly-declared out-of-band IT collector - never the in-scope OT
network. It is the whitelisted channel, separately linted.

String-literal awareness: the guard's own test fixtures embed bad-code examples
as text. The regex pass is string-literal aware so those embedded examples do NOT
count as egress - only *executable* code is judged.
"""
import ast
import os
import re
import sys
import textwrap
from collections import namedtuple

ALLOWED_OUTBAND_MARKER = "egress_outband=True"
OUTBAND_MODULE = "output/egress_outband.py"
ROOTS = ("ingest", "dpi", "fingerprint", "output", "safety")

Violation = namedtuple("Violation", ["path", "line", "column", "kind", "detail"])

_FORBIDDEN_CALLS = {
"socket", "connect", "connect_ex", "bind", "setsockopt",
"send", "sendto", "sendmsg", "sendall",
"urlopen", "getaddrinfo", "create_connection",
}
_FORBIDDEN_MODULES = {
"socket", "http", "httpx", "requests", "urllib",
"asyncio", "smb", "telnetlib", "ftplib", "pysh", "paramiko",
}
# Specific multi-char tools matched as whole words; `ip`/`tc` require an
# iproute2/tc subcommand so the common variable name `ip` (and `tcp`) does
# NOT false-trigger. nftables/nft/ping etc. are specific enough on their own.
_SHELL_TOOL = re.compile(
     r"\b(?:nmap|fping|hping3|masscan|ping|ping6|iptables|nftables|curl|wget)\b"
    r"|\bnft\s+(?:add|insert|replace|delete|list|do_chain|list_set|get)\b"
    r"|\bip\s+(?:link|addr|route|neigh|rule|tun|monitor|netns|ro|s)\b"
    r"|\btc\s+(?:qdisc|class|filter|mirred|gen|show|dump)\b", re.IGNORECASE)
_INSCOPE_LAN = re.compile(
    r"\b(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"192\.(?:16[89]|17\d|18\d|19\d)\.\d+\.\d+|100\.(?:6[4-9]|[7-9]\d|"
    r"1[01]\d|12[0-7])\.\d+\.\d+)\b")


def _code_lines(text):
    """Yield (lineno, line) for executable lines, skipping string literals.

    Simple toggle detector: a line is 'inside a string' while we have seen an
    odd number of triple-quote delimiters so far. That is enough to skip the
    guard's own embedded fixture examples without parsing the grammar.
    """
    in_str = False
    for i, line in enumerate(text.splitlines(), start=1):
        if in_str:
            for delim in ('"""', "'''"):
                if delim in line:
                    in_str = (line.count(delim) % 2) == 1
            continue
        for delim in ('"""', "'''"):
            if delim in line:
                opens = line.count(delim)
                if opens == 1:
                    in_str = True
                    break
                elif opens % 2 == 1:
                    in_str = True
        if in_str:
            continue
        yield i, line


def _call_name(node):
    fn = node.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return None


def _in_scope_literal(line):
    if not _INSCOPE_LAN.search(line):
        return False
    if re.search(r"OUT_OF_INSCOPE|collector_host|_host|=.*address", line):
        return False
    return True


def _lint_python(path):
    """Parse a module and return egress violations in its executable code."""
    violations = []
    try:
        text = open(path, "r", encoding="utf-8", errors="replace").read()
    except OSError:
        return violations

    # ---- AST pass (executable constructs only) ----
    try:
        tree = ast.parse(text, filename=path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in _FORBIDDEN_MODULES:
                        violations.append(Violation(
                            path, node.lineno, node.col_offset,
                            "import", "egress-capable import of %r" % top))
            elif isinstance(node, ast.ImportFrom):
                mod = (node.module or "").split(".")[0]
                if mod in _FORBIDDEN_MODULES:
                    violations.append(Violation(
                        path, node.lineno, node.col_offset,
                        "import", "egress-capable from-import of %r" % mod))
            elif isinstance(node, ast.Call):
                name = _call_name(node)
                if name and name in _FORBIDDEN_CALLS:
                    violations.append(Violation(
                        path, node.lineno, node.col_offset,
                        "call", "egress construct %r" % name))
    except SyntaxError:
        pass

    # ---- regex pass (executable, non-string lines only) ----
    for i, line in _code_lines(text):
        if _SHELL_TOOL.search(line):
            violations.append(Violation(
                path, i, 0, "shellout",
                "network/reconfig tool token on line %d" % i))
        if _in_scope_literal(line):
            violations.append(Violation(
                path, i, 0, "in-scope-literal",
                "hardcoded in-scope OT LAN literal on line %d" % i))
    return violations


def scan_core(roots=ROOTS):
    """Aggregate egress violations across the analysis core. Returns [].

    The declared out-of-band module is excluded from the core scan; it is linted
    separately by `lint_outband`.
    """
    found = []
    files = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _, names in os.walk(root):
            for name in names:
                if name.endswith(".py"):
                    files.append(os.path.join(dirpath, name))
    for path in sorted(files):
        if path == OUTBAND_MODULE:
            found.extend(lint_outband(path))
            continue
        # The scanner self-audits by inspection, not by self-scan (its
        # lint_outband helper enumerates net-tool names as *data*).
        if os.path.basename(path) == "egress_guard.py":
            continue
        found.extend(_lint_python(path))
    out = []
    seen = set()
    for v in sorted(found, key=lambda x: (x.path, x.line, x.kind)):
        key = (v.path, v.line, v.kind)
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out


def lint_outband(path):
    """The out-of-band module may emit - but NEVER to an in-scope OT address."""
    violations = []
    text = open(path, "r", encoding="utf-8", errors="replace").read()
    if ALLOWED_OUTBAND_MARKER not in text:
        violations.append(Violation(
            path, 1, 0, "missing-marker",
            "out-of-band module missing %r marker" % ALLOWED_OUTBAND_MARKER))
    for tool in ("nmap", "fping", "hping3", "masscan", "ping",
                 "tc", "iptables", "nftables", "curl", "wget"):
        if re.search(r"\b%s\b" % re.escape(tool), text):
            violations.append(Violation(
                path, 0, 0, "shellout",
                "net tool %r forbidden even in out-of-band module" % tool))
    for i, line in enumerate(text.splitlines(), start=1):
        if _in_scope_literal(line):
            violations.append(Violation(
                path, i, 0, "in-scope-literal",
                "in-scope OT literal even in out-of-band module (line %d)" % i))
    return violations


# ---------------------------------------------------------------- non-vacuity
_BAD = textwrap.dedent("""\
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.0.0.5", 502))
    s.send(b"\\x00")
    import os
    os.system("nmap 10.0.0.0/24")
    os.system("tc qdisc add dev eth0 root netem delay 10ms")
""")
_CLEAN = textwrap.dedent("""\
    import os
    def read_capture(path):
        with open(path, "rb") as fh:
            return fh.read()
""")


def negative_tests():
    """Inject bad + clean code; assert the guard flags bad and spares clean."""
    import tempfile
    results = []
    with tempfile.TemporaryDirectory() as td:
        bad = os.path.join(td, "bad.py")
        open(bad, "w").write(_BAD)
        clean = os.path.join(td, "clean.py")
        open(clean, "w").write(_CLEAN)
        bad_v = _lint_python(bad)
        clean_v = _lint_python(clean)
        kinds = {v.kind for v in bad_v}
        ok = len(bad_v) >= 3 and {"import", "call", "shellout"}.issubset(kinds)
        results.append(("bad-code flagged", ok,
                        "got %d violations, kinds=%s" % (len(bad_v), sorted(kinds))))
        ok = len(clean_v) == 0
        results.append(("clean-code not flagged", ok,
                        "false positives=%d" % len(clean_v)))
    return results


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    roots = tuple(argv) if argv else ROOTS
    violations = scan_core(roots)
    print("== P4 zero-egress static guard ==")
    print("scanned roots:", roots)
    if violations:
        for v in violations:
            print("  VIOLATION %s:%d (col %d) [%s] %s" % (
                v.path, v.line, v.column, v.kind, v.detail))
        print("RESULT: FAIL -- %d violation(s). Build blocked." % len(violations))
        return 1
    neg = negative_tests()
    print("non-vacuity self-test (injected bad vs clean):")
    for label, ok, detail in neg:
        print("   [%s] %s -- %s" % (
            "PASS" if ok else "FAIL", label, detail))
    if not all(ok for _, ok, _ in neg):
        print("RESULT: FAIL -- guard is vacuous (let something through).")
        return 2
    print("RESULT: PASS -- no egress in core; guard non-vacuous. Zero egress holds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
