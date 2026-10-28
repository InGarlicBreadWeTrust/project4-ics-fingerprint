# SAFETY POLICY — PASSIVE-ONLY (the operating contract)

> This document is the product. Every other design decision — detection,
> signatures, deployment, license — must survive this policy. If a feature
> conflicts with any hard rule below, **the feature is rejected.** This tool must
> be safe to run *inline in a live substation, 24×7, next to a relay.*

**Audience:** anyone running this in a production OT/ICS network. **Enforced by:**
the `build-approach.md` CI guard **and** a runtime assertion (both fail if egress
is possible). **Sign-off required before any run:** the site's OT owner *and*, for
safety-critical segments, the site's safety officer.

---

## 0. The one rule

> **The analysis process must be incapable of transmitting a single packet onto the
> in-scope (OT) network. No bytes go out. Not a probe, not an ACK, not a
> retransmit, not a malformed packet, not a "friendly" hello.**

Passivity is not "be gentle." Passivity is "be physically incapable of touching the
network beyond *listening*." Below is the rule broken into enforceable pieces.

---

## 1. Hard rules (non-negotiable)

| # | Rule | Why |
|---| --- | --- |
| H1 | **No active probes.** Never initiate a connection (SYN/ICMP/UDP/ARP-who-has/LLC). No request the tool *causes* to be generated. | A probe can crash/stall/reset a PLC or trip a safety loop. Active probing is also the legal-liability vector. |
| H2 | **No synthetic / malformed packets.** Never inject, retransmit, or fuzz. No packet is constructed and put on the wire. | Malformed packets are the classic ICS "gotcha" payload (e.g. the IEC 11088/6118-style "send this exact byte" class of exploits). We never generate a packet. |
| H3 | **No DoS-capable / high-rate operations.** The tool emits **zero** packets, so it cannot DoS *itself*; additionally, capture and CPU/memory are bounded (see §6) so it cannot starve the mirror port or the substation switch. | Even a *listen* load (CPU/disk) that drops the capture appliance could drop real monitoring. Bounded. |
| H4 | **Read-only capture only.** Ingest is *file-based* (PCAP/PCAPNG), *mirror/SPAN/TAP port*, or *flow feed* (NetFlow/sFlow/IPFIX). The tool **never** configures an inline tap, and **never** touches `tc`, `iptables/nftables`, `ip link` forwarding, switch trunk config, or any BPF *forwarding* rule on the observed segment. | The only thing that can "affect the network" is the *capture*, and that must be a switch port mirror configured by the **site's network team**, never by this tool. |
| H5 | **Zero-egress proof.** On every interface used for capture, the process holds **no send socket** on the in-scope L2/L3 domain. A runtime assertion + a CI static scan prove it (see §7). | This is the *mechanism* that lets us say "we can't have caused that." |
| H6 | **Safety-Instrumented-System gate.** The tool may never be co-located, configured, or used on a segment that carries **SIS / ESD / EPOD / FIPS / IEC 61511 Safety Instrumented Systems** levels, without **documented, signed** safety-officer authorization *for that capture placement*. | Even passive monitoring on the wrong conduit can mask or delay a real safety event, or create a false sense of coverage. Physical safety outranks data completeness, always. |
| H7 | **No secrets, no PII exfiltration, no telemetry.** No outbound network calls to vendor/cloud/servers. No logging of credential-bearing fields (Modbus/OPC-UA/MQTT cleartext credentials) beyond the minimum needed for a finding, which is then **redacted** in reports. | Cleartext industrial credentials in traffic must not become stored/leaked secrets. |
| H8 | **Deterministic & auditable.** Every fingerprint/finding cites the exact packet fields that produced it. Run twice on the same capture ⇒ identical inventory. Exportable for legal/defense. | "Help not get sued" = a clean, reproducible chain of custody. |

---

## 2. Authorized capture is a precondition

Passivity does **not** remove the legal requirement to be *authorized to
capture.* Observing a network you are not entitled to observe is still intrusion.
Before any run:

1. **Authorization / consent** — written authorization from the asset owner to
   perform passive monitoring in the named segment(s). For a co-op/util
   running under NERC CIP / a state regulator, record the authorization id.
2. **In-scope subnets / assets** — explicit list of VLANs/subnets the capture
   may touch. Out-of-scope = not captured.
3. **Blackout / maintenance windows** — times when capture is paused.
4. **Safety-officer sign-off** where any SIS/EPOD conduit is adjacent (H6).
5. **Data-processing agreement** where capture data may contain PII / regulated
   process data (§7 / H7).

This is recorded in the run manifest, not in the binary.

---

## 3. Capture topology (the only two safe options)

```
  Option A — mirror/SPAN/TAP                      Option B — PCAP file
  ┌────────────┐  mirror port (configured        ┌──────────┐
  │ Substation │  by SITE network team, NOT by    │  TAP /    │
  │ switch/PLC │◀─────────────────── this tool)   │ capture    │
  └─────┬──────┘                                  │ agent      │
        │ passive (read-only mirror)              └────┬───────┘
        ▼                                              │ files
  ┌───────────┐   PCAP/PCAPNG / or flow feed        ▼ ▼
  │ Capture    │ ───────────────►  Passive-ICS-Fingerprint  ──►  OCSF + report
  │ appliance  │      (SPAN)       (egress = 0 on        out-of-band
  └───────────┘                    in-scope iface)        (approved channel)
```

- **Never inline in the forwarding path** of a process link, and never on a link
  the tool itself configures.
- The capture appliance may be a SPAN port, a TAP, an sFlow/NetFlow collector —
  any of which sits *off* the live forwarding path.
- **Agent egress to the in-scope OT VLAN is blocked at the host** (H5, §7). The
  agent only *sends results out of band* (e.g. to an IT-collector on a different
  network, or stays air-gapped and exfiltrates on an approved channel).

---

## 4. What we do *not* do (the anti-pattern list)

Explicitly forbidden — and statically checked in CI:

- ❌ `socket(AF_INET, SOCK_STREAM, …)` + `connect()` to any in-scope host.
- ❌ Any use of `nmap` / `fping` / `hping3` / `masscan` / NSE "safe read-only"
  scans (these still open a socket and *can* stress a PLC — not "safe enough").
- ❌ ICS "safe read-only" probes that the prior art labels safe (e.g. a
  single `modbus-discover` / `s7-info` / `bacnet-info` connection) — we forbid
  even *one* active connection. **This is our differentiator and our legal moat.**
- ❌ Building a request/response transaction the tool originates.
- ❌ Replaying (even read-only) frames/payloads back onto the mirror.
- ❌ Any write to `tc`, `iptables`, `nftables`, `ip link`, or switch config.
- ❌ DNS/HTTP egress to vendor servers, update check, crash-report, telemetry.

> **Note on "passive" prior art that opens one socket:** some ICS "asset
> discovery" tools open a *single read-only* connection to a device to read a
> banner or `sysDescr`. That is **still active egress** and, per ICS lore, can
> stress or reset fragile devices. This project treats "zero bytes out" as the bar;
> one socket is a failure.

---

## 5. Physical-safety gate (hard stop before placement)

A safety review is recorded **per capture point**, not once:

1. Is the conduit a Safety Instrumented System / EPOD / FIPS / ESD domain? If yes
   → **stop**, get the safety officer; do **not** place a monitor that could
   mask/alter timing on that conduit.
2. Is the capture port a *live process* link (no mirror available)? If the only
   option is an inline tap that the tool/config affects → **stop**. Prefer a
   passive TAP or ask the network team for a mirror.
3. Does the monitor's CPU/disk/CPU-affinity risk starving the mirror switch or the
   capture appliance during a process event? If yes → cap resources (§6).
4. If any of the above is unresolved, **the run does not happen.**

> Rule of thumb used throughout this project: **availability & physical safety
> outrank data completeness, always.** It is fine to *miss* an asset; it is never
> fine to have *caused* a fault.

---

## 6. Bounded resource profile (so a monitor itself can't cause harm)

- **No unbounded memory growth.** Flow tables and dedup windows are bounded
  (LRU/size-capped); on pressure, evict oldest, never grow unbounded.
- **No unbounded disk.** Rotating, size-bounded captures; `tcpdump -G/-W` style
  roll.
- **Bounded CPU.** No busy-loop; poll with `select`/`SIGTERM`-ready. Pin to a
  cgroup limit.
- **Graceful stop on SIGTERM/SIGINT** — no half-written state, no leftover probes.
- **Watchdog**: if the capture appliance's throughput exceeds the monitor's
  drain rate, the monitor *drops with back-pressure* rather than buffering into
  OOM — it degrades its own coverage, it never harms the segment.

---

## 7. Enforcing "zero egress" — how we prove it

Passivity must be *demonstrable*, not asserted. Two guards:

**7.1 Static / build-time guard (CI).** A linter over the source tree fails the
build if it finds any of:
- an outbound socket to an in-scope interface/address (pattern: `connect(`,
  `socket(SOCK_STREAM`, `send`, `sendto`, `setsockopt(...SO_...)` to in-scope);
- calls into `nmap/fping/hping/masscan/ping` binaries or their NSE "safe" scans;
- any `tc/iptables/nft`/`ip link` shell-out;
- outbound DNS/HTTP to vendor domains; `curl/wget` to network addresses.
(Allow-list the *out-of-band* result-egress channel only — e.g. a specific host
on the IT collector — never the in-scope OT network.)

**7.2 Runtime assertion (every process).** On start, the monitor:
- opens the capture source (file/iface-mirror/feed) **read-only**;
- asserts it opened **no** socket on the in-scope interface for `SOCK_STREAM/
  SOCK_DGRAM` egress (or runs under a capability/namespace that *cannot* egress on
  that interface);
- prints a **zero-egress attestation** to the run manifest: `egress_packets=0`,
  `send_socket_on_in_scope=0`, `net_ops=off`.
- optional: run the analyzer in a Linux **network namespace with the in-scope
  interface unshared**, so egress on OT is structurally impossible, and the
  result-egress channel is the only path out. This is the strongest form and is
  the recommended default for a substation deployment.

The attestation goes into every report artifact (§ H8) — that is the "here is
proof we couldn't have caused it" the legal team wants.

---

## 8. Data minimization & secret handling

- **Redact credential-bearing fields.** Modbus/OPC-UA/MQTT/Sparkplug/HTTP can
  carry cleartext passwords and tokens. Reports store only `credential_PRESENT`
  flags + a redaction marker, **never** the secret value.
- **No PII beyond what is observable.** IP/MAC/OUI/hostname-from-banners are
  in-band and expected; personal data is not collected.
- **No telemetry, no phone-home, no update checks, no crash-report.** Air-gapped-
  friendly.
- **Capture retention & access** per the data-processing agreement; encrypted at
  rest; access-logged.
- **No secrets in the repo or the run manifest** (env/secrets via the deployment
  platform, never committed; never in logs).

---

## 9. Sign-off checklist (run manifest)

Every run records, signed by a named human:

```
[ ] Authorization id (written consent to monitor these subnets)
[ ] In-scope VLAN/subnet list; explicit out-of-scope list
[ ] Capture type: PCAP-file | SPAN | TAP | sFlow/NetFlow/IPFIX
[ ] Safety-officer sign-off (if any SIS/EPOD/FIPS/EPOD conduit adjacent)  H6
[ ] Zero-egress mechanism chosen (namespace / capability / host policy)
[ ] Zero-egress attestation captured (egress_packets=0, send_socket=0)
[ ] Blackout / maintenance windows honoured
[ ] Resource bounds set (mem cap, disk cap, CPU cgroup)
[ ] Data-processing agreement reference; PII handling; retention
[ ] Report redaction config (credentials not stored in clear)
[ ] Signed by: ____  Date: ____  Site/segment: ____
```

> **Bottom line:** *we listen, we never speak to the network; we are structurally
> incapable of causing a fault; and we can prove it, per run.*
