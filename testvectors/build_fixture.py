"""Build a synthetic classic-PCAP fixture: known-IP Modbus/DNP3/S7comm/unknown.

Produces a libpcap-format file the reader can replay. No live capture, no
socket. Deterministic seed fixture for the reference pipeline.

Usage: python3 testvectors/build_fixture.py <out.pcap>
"""
import struct
import sys


def _addr_bytes(ip):
     # 192.168.0.7 -> 4 bytes, no socket
    return bytes(int(o) & 0xFF for o in ip.split("."))


def _csum(data):
    s = 0
    if len(data) % 2:
        data = data + b"\x00"
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def ipv4(src_ip, dst_ip, proto, l4):
    ver_ihl = 0x45
    total = 20 + len(l4)
   # 20-byte header: first 12 bytes are computed, then the 8 address bytes.
    hdr = struct.pack("!BBHHHBBH",
            ver_ihl, 0, total, 8, 0x40, 64, proto, 0)
    idx = 10
    csummed = hdr[:idx] + struct.pack("!H", _csum(hdr)) + hdr[idx + 2:]
    return csummed + _addr_bytes(src_ip) + _addr_bytes(dst_ip) + l4


def udp_l4(sport, dport, app):
     # valid-length UDP, checksum 0 (the reader does not validate it)
    return struct.pack("!HHHH", sport, dport, 8 + len(app), 0) + app


def tcp_l4(sport, dport, app, syn=False):
    flags = 0x02 if syn else 0x10
    data_off = 5
    header = struct.pack("!HHIIBBHHH",
            sport, dport, 0, 0, data_off << 4, flags, 65535, 0, 0)
    assert len(header) == 20
    return header + app


def _mac_src(oui_prefix, tail_byte):
      # full 6-byte source MAC: first 3 bytes = OUI prefix, a tag byte at [3]
    src = bytes.fromhex(oui_prefix) + bytes([tail_byte, 0, tail_byte])
    return b"\xff\xff\xff\xff\xff\xff" + src


def tcplike(oui_prefix, ip, dport, app):
      # OUI in the source MAC, OT address space in the destination IP
    mac_hdr = _mac_src(oui_prefix, 0x11) + struct.pack("!H", 0x0800)
    l4 = tcp_l4(0x1F90, dport, app)
    return mac_hdr + ipv4("192.168.0.7", "10.99.99.100", 6, l4)


def random_udp(oui_prefix, ip, dport, app):
    mac_hdr = _mac_src(oui_prefix, 0x22) + struct.pack("!H", 0x0800)
    l4 = udp_l4(0x1F90, dport, app)
    return mac_hdr + ipv4("192.168.0.7", "10.99.99.100", 17, l4)


def pcap_frame(ts, capture):
    return struct.pack("<IIII", 0, 0, 16 + len(capture), len(capture)) + capture


def build(path):
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 100, 65535, 1, 101)
    modbus_app = b"\x00\x07\x00\x00\x00\x06\x01\x04\x00\x00\x00\x01"
    dnp3_app = b"\x05\x04\x00\x00\x01"
    s7_app = bytes([0x11, 0x10, 0x05, 0x00, 0x00, 0x01, 0x11, 0x63,
             0x0d, 0x01, 0x10, 0x01, 0x11])
    frames = [
        tcplike("001234", "modbus", 502, modbus_app),
        tcplike("001a11", "dnp3-abb", 20000, dnp3_app),
        tcplike("001942", "s7-siemens", 102, s7_app),
        random_udp("00dead", "unknown", 4406, b"\x00\x01\x02\x03"),
      ]
    out = hdr + b"".join(pcap_frame(0.0, f) for f in frames)
    with open(path, "wb") as fh:
        fh.write(out)
    print("wrote %d bytes; %d frames to %s" % (len(out), len(frames), path))


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "testvectors/four_frames.pcap"
    build(path)
