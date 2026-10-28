"""P4 DPI: bounded L2/L3/L4 layer extractor.

Recovers the fields the OCSF `network` event and the ICS signature matchers need,
from a raw capture payload, with NO network egress and NO unbounded allocation
(SAFETY-POLICY 2.2, 5.2). Every read bounds by remaining length; a truncated or
unknown frame yields partial fields, never a crash or out-of-bounds.

Recoverable fields:
     - Ethernet II/III link type; src/dst OUI (IEEE vendor attribution, L2)
      - IP v4 src/dst, L4 proto (6=TCP, 17=UDP)
      - L4 sport/dport, is_tcp/is_udp flags
      - L4 application payload handed to the DPI
"""
import struct

PROTO_TCP = 6
PROTO_UDP = 17


class Frame:
    def __init__(self, byts):
        self.ether_type = 0
        self.src_mac = None
        self.src_oui = None
        self.dst_oui = None
        self.ip_version = 0
        self.src_ip = None
        self.dst_ip = None
        self.l4_proto = 0
        self.sport = 0
        self.dport = 0
        self.is_tcp = False
        self.is_udp = False
        self.app = b""
        self.parse_ok = False
        self.truncated = False
        self._from_bytes(byts)

    def _from_bytes(self, b):
        if len(b) < 14:
            self.truncated = True
            return
        self.src_oui = b[6:9]
        self.dst_oui = b[0:3]
        self.src_mac = "%02x:%02x:%02x%02x:%02x:%02x" % (
            b[6], b[7], b[8], b[9], b[10], b[11])
        eth = struct.unpack_from(">H", b, 12)[0]
        self.ether_type = eth
        if eth == 0x01:
            self._ethernet_iii(b)
        else:
            self._ethernet_ii(b)

    def _ethernet_iii(self, b):
        self._ip(b[14:])

    def _ethernet_ii(self, b):
        if self.ether_type in (0x0800, 0x0806, 0x86DD):
            self._ip(b[14:])
        else:
            self.parse_ok = True

    def _ip(self, ip):
        if len(ip) < 20:
            self.truncated = True
            return
        ihl = (ip[0] & 0x0F) * 4
        self.ip_version = ip[0] >> 4
        self.src_ip = ".".join(str(x) for x in ip[12:16])
        self.dst_ip = ".".join(str(x) for x in ip[16:20])
        self.l4_proto = ip[9]
        l4 = ip[ihl:]
        if self.l4_proto == PROTO_TCP:
            self._tcp(l4)
        elif self.l4_proto == PROTO_UDP:
            self._udp(l4)
        else:
            self.parse_ok = True

    def _tcp(self, p):
        if len(p) < 4:
            self.truncated = True
            return
        self.is_tcp = True
        self.sport = struct.unpack_from(">H", p, 0)[0]
        self.dport = struct.unpack_from(">H", p, 2)[0]
        dataoff = ((p[12] >> 4) & 0x0F) * 4
        self.app = p[dataoff:] if dataoff <= len(p) else b""
        self.parse_ok = True

    def _udp(self, p):
        if len(p) < 8:
            self.truncated = True
            return
        self.is_udp = True
        self.sport = struct.unpack_from(">H", p, 0)[0]
        self.dport = struct.unpack_from(">H", p, 2)[0]
        self.app = p[8:]
        self.parse_ok = True

    def as_ocsf_network(self):
        proto = "tcp" if self.is_tcp else ("udp" if self.is_udp else "")
        return {
            "action": "observation",
            "category_uid": 3,
            "category_name": "network",
            "protocol": proto,
            "src_endpoint": {"ip": self.src_ip or "", "port": self.sport},
            "dst_endpoint": {"ip": self.dst_ip or "", "port": self.dport},
            "src_mac": self.src_mac or "",
            "src_oui": self.src_oui.hex() if self.src_oui else "",
            "length": len(self.app),
            "parse_ok": self.parse_ok,
            "truncated": self.truncated,
         }
