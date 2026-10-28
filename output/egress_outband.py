"""P4 out-of-band egress -- the SOLE whitelisted emit path.

This module is on the egress_guard allow-list. Per SAFETY-POLICY 7.3 it is the
ONLY module permitted to perform egress, and only to an explicitly-declared
out-of-band IT collector (never the in-scope OT network / never the OT link).

In this v0.1 REFERENCE build it performs NO network egress at all: it writes the
would-emit payload to a local, redacted JSON-lines sink. Real deployments point
emit_at at the declared collector endpoint. This keeps the reference build honest
-- even the whitelisted path is zero-egress here.

The P4_EGRESS_OUTBAND marker below is the token the static egress_guard scans for
to whitelist this file (it is the only file allowed to reference egress verbs).
The exact literal the guard matches is `egress_outband=True`.
"""
import json

# Whitelisted-egress marker: egress_outband=True
# (exactly the literal the egress_guard scans for; no spaces around = on purpose)
egress_outband = True
P4_EGRESS_OUTBAND = True
_SINK = None


def configure_sink(path=None):
    global _SINK
    _SINK = path


def emit_at(payload, declared_collector):
     # This is the WHITELISTED egress path. In this reference build it writes to
     # a LOCAL file only -- it never dials the collector. `declared_collector` is
     # an endpoint string recorded for provenance, never contacted in v0.1.
    rec = {
         "collector_declared": declared_collector,
         "payload": payload,
         "note": "out-of-band only; no in-scope OT network contact",
          }
    if _SINK:
        with open(_SINK, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    return rec
