# Detection Methodology — Passive ICS/OT Fingerprinting

> Passivity is the constraint that shapes the entire method. We never *ask* a
> device a question; we only *read the answers the network already produced* (or
> a PCAP/flow record already contains). Every signal below has a passive-only
> justification. See `SAFETY-POLICY.md` for the hard rules.

---

## 1. Signal model

A device's fingerprint is assembled from **three signal families**, all
passive-derivable:

| Family | Signals | Passive-derivable from | Notes |
| --- | --- | --- | --- |
| **Identity / OUI** | MAC → OUI → vendor/device class; TCP/IP fingerprint (TTL, initial window, options, IPID behaviour) | L2/L3/L4 header fields seen in existing frames | Like `macDetec` (OUI lookups) + `p0f`-style passive IP fingerprint — but *derived*, never requested. |
| **Protocol / role** | Protocol identity + depth; conversation pattern (master↔slave polling cadence); timing; request/response structure | L4/transport + application payloads already on the wire | This is where DPI signatures live (§4). |
| **In-band identity fields** | OPC-UA endpoint URL + server version, HTTP `Server`/`User-Agent` banner, SNMP `sysDescr`/`sysObjectID`/`sysName`, Modbus unit-id, Sparkplug BIRTH topic+alias, IEC 61850 device identity | *Fields that the device itself emitted*, in traffic we observed | **Never requested by us** — we only read what the device *already* sent in the window. This is the key distinction from active banner-grabbing. |

**Crucial invariant:** every in-band identity field we read, we read **because the
device already emitted it during the observation window** — we never generate a
request that *causes* that field to be emitted. (e.g. we see an OPC-UA
`GetEndpoints` response a *real* client already requested and logged; we do not
perform the `GetEndpoints` call.)

---

## 2. Two ingest tiers

### Tier 1 — high-fidelity: PCAP / PCAPNG (on a mirror/SPAN/TAP or offline)
- Full packets, application-layer DPI is possible → richest fingerprints.
- Capture is *read-only file/iface*; the appliance sits off the forwarding path
  (`SAFETY-POLICY.md §3`). **No tap we configure.**

### Tier 2 — lightweight: flow feeds (NetFlow v5/v9, IPFIX, sFlow)
- No payload (or limited payload) → app-layer DPI is *partial*; we fingerprint from
  5-tuples, byte/packet counts, protocol by IANA port + flow entropy, and any
  *embedded* protocol the flow protocol exposes. Good for distributed / many-site
  small-operator coverage where full PCAP is infeasible. See `build-approach.md`
  P2.

> Both tiers are passive. Tier 2 additionally cannot see application headers, so
> Tier-2 app-layer results are **lower confidence and clearly marked.**

---

## 3. Pipeline (all stages read-only)

```
 capture (mirror/PCAP/flow) ─► L2/L3/L4 reassembly ─► DPI dissection ─► feature extraction
                                                                        │
              ┌─────────────────────────────────────────────────────────┘
              ▼
      protocol identity (L0–L3 confidence) ──┐
      vendor (OUI)                      ─────┤
      role (conv. pattern + timing)     ──────┼► cross-validate ─► device fingerprint record
      in-band identity fields           ─────┤        (≥2 signals agree)
      Purdue level (subnet+topology)    ─────┘
              │
              ▼
   risk-indicator scoring (IEC 62443 SR + MITRE ATT&CK-for-ICS mapping) ─► OCSF + report + manifest
```

- **Reassembly is stateful but bounded** (connection/state tables are size-capped,
  LRU-evicted — see `SAFETY-POLICY §6`), so a long capture cannot OOM us.
- **Dissection uses a permissive, safe language core** (Rust, zero-C, no GC
  pauses — embedded-friendly) with a Python orchestrator option. See
  `build-approach.md`.
- **No stateful transaction we originate** — flow/session state is *observed*,
  not *generated*.

---

## 4. DPI protocol detection — confidence tiers

Every signature in `signature-catalogue.md` produces a match at a **confidence
tier**; a device's protocol is only *asserted* (not "candidate") at L2+ (or via
cross-validation, §5):

| Tier | Signal | Confidence |
| --- | --- | --- |
| **L0** | EtherType / IANA port alone (e.g. TCP/502) | weak — port alone is forgeable/mis-set; *candidate* |
| **L1** | port **and** protocol magic / transaction-id structure (e.g. Modbus MBAP header; S7 COTP; OPC-UA `opc.ua`) | medium |
| **L2** | field-level structure / function-code grammar / role-consistent payloads (e.g. Modbus FC set + unit-id; S7 PDU TPKT; DNP3 ASDU cause-of-transmission) | strong — asserted |
| **L3** | device identity field matches (OPC-UA endpoint+version; `sysDescr`; Sparkplug BIRTH alias + topic) | very strong — *identity-confirmed* |

- **Low-confidence (L0/L1) alone ⇒ "candidate protocol,"** surfaced with the
  counter-evidence; never silently classified.
- **L2 or higher ⇒ protocol asserted.** L3 ⇒ identity-confirmed device.

---

## 5. Cross-validation (the anti-mis-ID rule)

The biggest real failure mode in this space is **silent mis-identification**
(prior-art lesson: the Eris-OT workbench itself had an OUI-dict collision that
mislabelled Honeywell devices as GE in *every* report until caught by a
contributor — see `prior_art.md` / `build-approach.md` test plan). Our rules:

- A device is **classified** only when **≥2 independent passive signals agree**
  (e.g. port **and** magic **and** OUI family all consistent). Signals are
  independent when they come from different layers/fields that a *single* wrong
  config can't all lie.
- **OUI collisions** are not trusted alone: OUI family is *one* signal; a device
  is classified to a *family*, and a specific product is asserted only with a
  second signal (protocol + in-band identity).
- **Conflicts are reported, not hidden:** if OUI says "vendor A, class: PLC" but
  protocol/port says "HTTP/Web server", we record the conflict and flag it as a
  *finding* ("unusual/possible rogue device") rather than picking one silently.
- **Every assertion carries a confidence label and its evidence** (the exact
  fields/offsets), so an auditor can see why and challenge it.

---

## 6. Role & Purdue inference

- **Role** (PLC / RTU / HMI / SCADA / OPC-server / historian / gateway /
  fire-and-forget sensor): from conversation **topology + cadence** — e.g. a
  host that *initiates and polls* many peers at regular intervals → master/SCADA;
  a host that *only responds* → field device/PLC; a host that *publishes* to
  Sparkplug B / MQTT → edge gateway; a host speaking OPC-UA/HTTP with rich
  identity → engineering server/HMI-class.
- **Purdue level** (0 field, 1 control, 2 manufacturing, 3 enterprise, 4
  business …): inferred from **VLAN/subnet** + **conversation topology** +
  protocol set, *not* from any active probe. Marked as *inferred*; the
  operator can correct it. Cross-Purdue traffic becomes a risk indicator (§7).
- **IT-on-OT:** any TCP/IP fingerprint or HTTP/SMB/DHCP/WinRM/RDP on an OT
  segment is a risk indicator ("IT service on OT network"), derived passively.

---

## 7. Risk-indicator surface (passive-derived; mapped to standards)

Each is derived from *observed* traffic and mapped to **IEC 62443-3-3 security
requirements** and **MITRE ATT&CK-for-ICS**:

| Indicator (passive) | Maps to |
| --- | --- |
| Control protocol with **no authentication** (Modbus/S7/DNP3 with no auth; writes observed) | IEC 62443 FR1 IAC / T0842 passive recon |
| **Cleartext** engineering/control session (OPC-UA `SecurityMode=None`; cleartext MQTT/HTTP) | IEC 62443 FR2 UC; T0861 |
| **Cross-zone / cross-Purdue** communication (a L0/L1 host talking to L3 enterprise) | IEC 62443 FR5 restricted data flow; T0874/T0888 |
| **Control writes from unexpected source** | T0840 / inhibit-response / impair-process-control |
| **C2-like beaconing / periodic out-bound to unknown host** | T0888 / C2 |
| **Suspicious external / internet-accessible OT device** | T0842 / initial access |
| **Default/hardcoded-cred indicators** (identity fields match known defaults) | IEC 62443 FR1; T0888 |
| **IT service on OT segment** (WinRM/RDP/SMB/DNS on L1/L2) | IEC 62443 FR2; T0874 |
| **Malware IOC match** (against a CISA KEV / STIX feed, matched against observed payloads/URLs/IOCs) | ATT&CK-for-ICS |

> **No indicator requires an active probe** — this is the whole point. The prior
> art's "safe active" probes (open *one* read-only connection) are *excluded*; we
> get these findings from what already flows. If an indicator genuinely can only be
> seen actively, it is **omitted**, not forced (SAFETY-POLICY wins over coverage —
> always).

---

## 8. Determinism, reproducibility, auditability

- **Same capture ⇒ byte-identical output.** No wall-clock in output; timestamps
  from capture time; no RNG affecting classification; dedup windows quantized &
  deterministic (fixed seed/order).
- **Chain of custody:** every record cites the originating **capture + packet
  sequence numbers + field offsets**, so a finding is reproducible from raw PCAP.
- **Run manifest + zero-egress attestation** travels with every report
  (`SAFETY-POLICY §7/§9`) — the "here is proof we sent nothing" that supports the
  "we did not cause this" legal posture.
- **Version-pinned signature catalogues** so a re-run with the same catalogue is
  reproducible; catalogue version stamped in the manifest.

---

## 9. What the method deliberately does *not* do

- No active banner grab, no SNMP *query* we initiate, no "get you the banner"
  request. We read only what's on the wire.
- No packet we generate. No request we originate. No retransmit/replay.
- No SIS/EPOD conduit placement without the §H6 safety sign-off.
- Where passive coverage is insufficient, we say "insufficient data — needs longer
  capture / a second collector," **not** "let me ping you." Coverage gaps are
  *reported*, never *bought* with active probing.

---

## 10. References (passive ICS analysis lineage)

- `nsacyber/GRASSMARLIN` — canonical passive ICS topology mapper (archived 2023).
- `eris-ot/marlinspike-dpi` / `marlinspike` — modern passive PCAP DPI pipeline
  (passive-by-design; AGPL — see license doc; reference only).
- `thainnos/macDetec` — passive OUI/MAC device identification (GPL-3.0, stale).
- `corelight/zeek` — permissive passive analyzer (BSD-3); the safe base.
- Standards: **IEC 62443** (3-3/4-1), **NIST SP 800-82 r3**, **MITRE ATT&CK for
  ICS**, **OCSF**, **Purdue/ISA-95**, **T3S/MALCOM** ICS test data.
- (full prior-art + name resolution: `prior_art.md`)
