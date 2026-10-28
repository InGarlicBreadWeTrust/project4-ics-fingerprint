"""4-layer passive classification: L0 signatures, L1 L3 protocol, L2 role/OUI, L3 cross-val.

The headline invariant: no active probing. `classify` consumes a parsed Frame
plus a SignatureSet and emits a fingerprint dict. Cross-validation (independent
L1 and L2 paths must AGREE) keeps false-confidence out. Output is a flat dict
the report layer serialises.
"""


def _max_confidence(confs):
    order = {"unknown": 0, "low": 1, "medium": 2, "high": 3}
    if not confs:
        return "unknown"
    return max(confs, key=lambda c: order.get(c, 0))


def L1(frame, sigset):
        # L0/L1: signature hits + protocol + confidence, all passive.
    hits = list(sigset.match_frame(frame))
    protocols = sorted({h["protocol"] for h in hits})
    confs = [h["confidence"] for h in hits]
    return hits, protocols, _max_confidence(confs)


def L2(frame, sigset):
    oui_hex = frame.src_oui.hex() if frame.src_oui else None
    vendor = sigset.vendor_for_oui(oui_hex)
    role = "unknown"
    if frame.dport in (5000, 5001, 5002, 502):
        role = "modbus-server"
    elif frame.dport == 102:
        role = "plc/rtu (s7comm)"
    elif frame.dport == 20000:
        role = "dnp3-master/slave"
    elif frame.dport == 40001:
        role = "iec60870-5-104"
    return {"vendor": vendor, "role": role}


def L3(fp, frame, sigset):
        # Cross-validate: two INDEPENDENT paths (protocol vs role/vendor).
    paths = []
    if fp["L1_protocols"]:
        paths.append("L1")
    if fp["L2_role"] != "unknown":
        paths.append("L2-role")
    if fp["L2_vendor"] != "unknown":
        paths.append("L2-vendor")
    if len(paths) < 2:
        return "unknown"
    return "confirmed"


def risk(fp):
        # Risk from observed facts only. No active scanning.
    flags = []
      # unattributed OR unresolved vendor (vendor_for_oui returns "unknown").
    vendor = fp.get("L2_vendor")
    if not vendor or str(vendor).strip().lower() == "unknown":
        flags.append("unattributed_vendor")
    if fp["L2_role"] == "modbus-server":
        flags.append("modbus_server_exposed")
    if fp["L3"] == "unknown":
        flags.append("crossval_unconfirmed")
    score = 0
    score += 10 if "unattributed_vendor" in flags else 0
    score += 30 if "modbus_server_exposed" in flags else 0
    score += 10 if "crossval_unconfirmed" in flags else 0
    score = min(score, 100)
    if score < 30:
        level = "low"
    elif score < 70:
        level = "medium"
    else:
        level = "high"
    return {"score": score, "level": level, "flags": flags}


def classify(frame, sigset):
        # Orchestrate L0->L1->L2->L3; emit the flat dict the report layer wants.
    hits, protocols, conf_max = L1(frame, sigset)
    l2 = L2(frame, sigset)
    fp = {
          "L0_sig_hits": [h["sig_id"] for h in hits],
          "L1_protocols": protocols,
          "L1_dport": frame.dport,
          "L2_vendor": l2["vendor"],
          "L2_role": l2["role"],
          "L2_oui": frame.src_oui.hex() if frame.src_oui else None,
          "confidence_max": conf_max,
      }
    fp["L3"] = L3(fp, frame, sigset)
    rs = risk(fp)
    fp["risk_score"] = rs["score"]
    fp["risk_class"] = rs["level"]
    fp["flags_risk"] = rs["flags"]
    return fp
