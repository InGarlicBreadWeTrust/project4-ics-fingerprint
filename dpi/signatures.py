"""P4 signature matcher: load language-neutral YAML signatures and match a Frame.

Depends only on PyYAML + the dissect module. No network, no unbounded alloc.
Confidence is inherited from the matched signature's `confidence` field.
The v0.1 signatures are SEED patterns (see each YAML's notes), NOT exhaustive
conformance -- matching is an honest heuristic "this looks like modbus/dnp3/s7".
"""
import glob
import os
import yaml


def _hex_pat(pat):
    p = pat.replace(" ", "")
    if len(p) % 2:
        return None
    try:
        return bytes.fromhex(p)
    except ValueError:
        return None


class SignatureSet:
    def __init__(self, path="dpi/signatures"):
        self.sigs = []
        self.oui = {}
        self._load(path)

    def _load(self, path):
        for f in sorted(glob.glob(os.path.join(path, "*.yaml"))):
            data = self._safe_load(f)
            if data is None:
                continue
            for s in data.get("signatures", []):
                raw = s.get("match", {}).get("app", {}).get("patterns", [])
                pats = [_hex_pat(p) for p in raw]
                s["_compiled"] = [p for p in pats if p]
                self.sigs.append(s)
            for k, v in data.get("vendor_notes", {}).items():
                self.oui[k.lower()] = v

    @staticmethod
    def _safe_load(f):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                return yaml.safe_load(fh)
        except (yaml.YAMLError, OSError):
            return None

    def match_frame(self, frame):
        hits = []
        app = frame.app
        for s in self.sigs:
            m = s.get("match", {})
            l4 = m.get("l4", "any")
            if l4 == "tcp" and not frame.is_tcp:
                continue
            if l4 == "udp" and not frame.is_udp:
                continue
            mode = m.get("dport_match", "any")
            if mode == "required" and frame.dport not in set(m.get("dports", [])):
                continue
            matched = [p.hex() for p in s.get("_compiled", []) if p in app]
            if matched:
                hits.append({
                    "sig_id": s.get("id", "?"),
                    "protocol": s.get("protocol", "?"),
                    "confidence": s.get("confidence", "unknown"),
                    "dport": frame.dport,
                    "matched": matched,
                })
        return hits

    def vendor_for_oui(self, oui_hex):
        return self.oui.get((oui_hex or "").lower(), "unknown")


def load_default(path=None):
    base = path or os.path.join(
         os.path.dirname(os.path.abspath(__file__)), "signatures")
    return SignatureSet(base)


if __name__ == "__main__":
    ss = load_default()
    print("loaded %d signatures, %d OUI entries"
          % (len(ss.sigs), len(ss.oui)))
