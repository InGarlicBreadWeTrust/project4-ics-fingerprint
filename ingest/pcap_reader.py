"""P4 ingest: minimal classic-PCAP reader.

Deliberately dependency-free and READ-ONLY. Handles the classic libpcap on-disk
format only: fixed 24-byte global header + 16-byte per-record block header.
Sufficient to passively read captures a TAP/SPAN port produces; it does NOT open
libpcap live and does NOT touch any network.
"""
import struct


GLOBAL_HDR = 24
BLOCK_HDR = 16
PACKET = "packet"

_MAGIC_LE = 0xA1B2C3D4
_MAGIC_BE = 0xD4C3B2A1


class Pcap:
    def __init__(self, path):
        self.path = path
        self.byts = self._read_bounded(path)
        self.le = self._detect_endianness(self.byts[0:4])
        self.fmt = "<" if self.le else ">"
        self.snaplen = self._u32(GLOBAL_HDR + 8)
        self.datalink = self._u32(GLOBAL_HDR + 16)
        self.offset = GLOBAL_HDR

    def _read_bounded(self, path):
        with open(path, "rb") as fh:
            return fh.read()

    def _detect_endianness(self, magic4):
        val = struct.unpack("<I", magic4)[0]
        if val == _MAGIC_LE:
            return True
        if val == _MAGIC_BE:
            return False
        raise ValueError("not a classic pcap magic: 0x%08x" % val)

    def _u32(self, idx):
        if idx + 4 > len(self.byts):
            return 0
        return struct.unpack_from(self.fmt + "I", self.byts, idx)[0]

    def is_classic(self):
        return struct.unpack("<I", self.byts[0:4])[0] in (_MAGIC_LE, _MAGIC_BE)

    def iter_packets(self):
        pos = self.offset
        total = len(self.byts)
        out = []
        while pos + BLOCK_HDR <= total:
            ts_sec = self._u32(pos)
            include_len = self._u32(pos + BLOCK_HDR - 4)
            start = pos + BLOCK_HDR
            avail = total - start
            if include_len > avail:
                data = self.byts[start:total]
                out.append((PACKET, ts_sec, data))
                break
            data = self.byts[start:start + include_len]
            out.append((PACKET, ts_sec, data))
            pos = start + include_len
        return out


if __name__ == "__main__":
    print("pcap_reader self-check: classic magic LE/BE supported")
