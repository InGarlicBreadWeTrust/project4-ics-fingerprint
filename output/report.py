"""P4 reporting: OCSF NDJSON + JSON summary + SHA256 manifest + attestation.

The report is the deliverable. It is written ENTIRELY locally. The OCSF v3.1.1
`network` event shape matches the `detection-methodology.md` mapping table. The
manifest (file SHA256, counts, provenance) is generated so a consumer can
verify nothing was silently altered.
"""
import hashlib
import json
import os

from safety.egress_guard import scan_core
from safety.attestation import assert_no_egress


def build_ocsf_network(frame, fp, risk):
    ev = frame.as_ocsf_network()
    ev["risk"] = risk
    ev["fingerprint"] = fp
    ev["device_vendor"] = fp.get("L2_vendor")
    ev["device_type"] = "_".join(fp.get("L1_protocols", ["unknown"]))
    ev["crossval_result"] = fp.get("L3")
    ev["confidence"] = fp.get("confidence_max")
    return ev


def _json_default(o):
     # defense-in-depth: keep report.json valid JSON even if a caller passes a
     # set/datetime — never let a stray type crash the report.
    if isinstance(o, (set, frozenset)):
        return sorted(str(x) for x in o)
    if isinstance(o, (bytes, bytearray)):
        return o.decode("utf-8", "replace")
    return str(o)


def write_report(out_dir, results):
    os.makedirs(out_dir, exist_ok=True)
    ndjson = os.path.join(out_dir, "ocsf_network.ndjson")
    summary = os.path.join(out_dir, "report.json")
    manifest = os.path.join(out_dir, "manifest.json")

    counts = {"modbus": 0, "dnp3": 0, "s7comm": 0, "unknown": 0, "total": 0}
    with open(ndjson, "w", encoding="utf-8") as fh:
        for r in results:
            ev = r["event"]
            fh.write(json.dumps(ev) + "\n")
            counts["total"] += 1
            for p in ev.get("fingerprint", {}).get("L1_protocols", []):
                if p in counts:
                    counts[p] += 1
            if not ev.get("fingerprint", {}).get("L1_protocols"):
                counts["unknown"] += 1
    with open(summary, "w", encoding="utf-8") as fh:
        json.dump({"counts": counts}, fh, indent=2)
    att = assert_no_egress()
    static = scan_core(".")
    man = {
          "out_dir": out_dir,
          "events": counts,
          "ndjson_sha256": _sha256(ndjson),
          "report_sha256": _sha256(summary),
          "attestation_runtime": att,
          "attestation_static": {
              "violations": len(static),
              "clean": not static,
              "whitelisted_emitter": "output/egress_outband.py",
          },
     }
    with open(manifest, "w", encoding="utf-8") as fh:
        json.dump(man, fh, indent=2, default=_json_default)
    return man, att, static


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        h.update(fh.read())
    return h.hexdigest()


def run_pipeline(pcap_path, sigset, out_dir):
         # The single reference driver: read -> dissect -> classify -> report.
    from ingest.pcap_reader import Pcap
    from dpi.dissect import Frame
    from fingerprint.fingerprint import classify
    results = []
    for _kind, ts, capture in Pcap(pcap_path).iter_packets():
        frame = Frame(capture)
        fp = classify(frame, sigset)
        risk = {
               "score": fp["risk_score"],
               "class": fp["risk_class"],
               "flags": fp["flags_risk"],
           }
        ev = build_ocsf_network(frame, fp, risk)
        results.append({"ts": ts, "event": ev, "fp": fp})
    write_report(out_dir, results)
    return results


def read_report(out_dir):
         # Read back the OCSF NDJSON (one event per line) plus the summary.
    ndjson = os.path.join(out_dir, "ocsf_network.ndjson")
    events = []
    with open(ndjson, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    summary = {"events": events}
    meta = os.path.join(out_dir, "report.json")
    if os.path.exists(meta):
        with open(meta, encoding="utf-8") as fh:
            summary.update(json.load(fh))
    return summary
