# PRD — Passive ICS/OT Device Fingerprinting & Asset Discovery for Small Utilities

*First-draft product requirements. Scope = passive-only. Safety policy
(`SAFETY-POLICY.md`) overrides any goal below.*

---

## 1. Problem

Rural co-ops, community & small utilities, and similar operators run ICS/OT
networks (PLCs, RTUs, HMIs, DCS, OPC servers, synchrophasor/PMU feeds) that are
under-resourced, often unmanaged, and increasingly in-scope for NERC CIP /
state-regulator / IEC 62443 obligations. They need to **know what devices are on
their network** for risk, compliance, and incident response — but they *cannot
safely* scan it: an active scan can disrupt a physical process, and an active
"authorized" scan opens legal liability ("help not get sued").

**The gap:** the mature OSS passive ICS mappers are either **abandoned**
(GRASSMARLIN, archived 2023), **stale** (macDetec, 2020), **copyleft** (the
modern Eris-OT family is AGPL-3.0), or **heavy/commercial** (Nozomi, Dragos,
Claroty, Fathom). Small operators want something *passive, permissively
licensed, lightweight, deployable by one sysadmin at a substation.*

## 2. Vision

> A small, permissively-licensed, passive-only tool that a rural co-op or small
> utility can drop on a SPAN/mirror port (or feed it PCAP/flow records) to get a
> **device inventory + protocol-fingerprint + risk surface** of their OT network
> **without ever sending a packet into that network** — safe for production and
> defensible under a "we never touched anything active" posture.

## 3. Users

- **Primary:** the lone / small sysadmin & security point-of-contact at a rural
  co-op, community solar/water/hydro plant, small utility, or IEC 62443-
  regulated operator with limited staff.
- **Secondary:** a managed-security-service provider doing low-cost passive
  assessments across many small sites; a security team doing a one-off baseline
  before any authorized active testing.
- **Out of scope (do not serve):** operators who *want* active scanning, exploit
  testing, or red-team capability. This tool has **none** by design (that's not a
  limitation — it's the product, per `SAFETY-POLICY.md`).

## 4. Goals (in priority order)

1. **Passive-only, provably.** Zero bytes egress on the in-scope network,
   *demonstrable* per run (§7 of SAFETY-POLICY). *(Highest priority — it's the
   whole point.)*
2. **Safe in production.** Safe to run 24×7 on a live substation mirror. Bounded
   resources; degrades own coverage rather than harming the segment.
3. **Useful output for a non-OT specialist.** A readable device inventory +
   "what might this be + how confident + here's the bytes that say it" report a
   co ops sysadmin can act on and hand to an auditor.
4. **Permissible & permissive-licensed.** Apache-2.0 core; no copyleft
   propagation into the core (see `license-assessment.md`).
5. **Compliant & audit-ready.** OCSF + plain report; MITRE ATT&CK-for-ICS +
   IEC 62443 SR mapping; deterministic/reproducible; signed run manifest.
6. **Lightweight & offline.** 1 core / 1 GB RAM; no internet, no vendor servers,
   runs air-gapped or on an engagement laptop.

## 5. Non-goals

- ❌ Active scanning, port knocking, banner grabbing we *request*, any "safe
  read-only" connection probe → forbidden by `SAFETY-POLICY.md` H1/H4.
- ❌ Exploitation, DoS, fuzzing, packet injection → forbidden (H2/H3).
- ❌ In-line tap we configure on a process link → forbidden (H4).
- ❌ Replacing commercial passive platforms at enterprise scale (we're the
  small-site / permissive alternative; commercial platforms remain for large
  enterprises).
- ❌ Live process-data value monitoring (we read traffic for *identity* &
  *role*, not for process control or historian-grade V/Q/T time-series, though
  we may pass through what flows give us).

## 6. Functional scope (MVP v0.1)

### 6.1 Ingest (all passive)
- **PCAP / PCAPNG** file (offline) and mirror/SPAN/TAP interface ingest
  (read-only, via a *file-backed* capture loop, never our own tap config).
- **Flow feeds:** NetFlow v5/v9, IPFIX, sFlow (lightweight; payload-light).
  *(Phase 2, but designed from day one — see `build-approach.md`.)*

### 6.2 Detection & fingerprint (passive-only; details in `detection-methodology.md`)
- Vendor from **MAC/OUI** (IEEE OUI + IRI/IETF vendor OUI registry).
- **Protocol identification** with confidence tiers L0–L3 across the starter
  catalogue (`signature-catalogue.md`): Modbus/TCP, S7comm, DNP3, IEC 60870-5-
  104, EtherNet/IP(CIP), OPC UA, BACnet, PROFINET, HART-IP, Sparkplug B over
  MQTT, IEC 61850 MMS/GOOSE/SV, IEEE C37.118 — plus an **IT baseline** (SNMP,
  DNS, TCP/IP fingerprint, HTTP banner) for "is an IT host on the OT network".
- **Role inference** (PLC/RTU/HMI/OPC-server/historian/gateway/scada) from
  conversation + timing patterns.
- **Purdue-level inference** from subnet / conversation topology.
- **Device identity** from observed fields only (OPC-UA endpoint/version, HTTP
  `Server`/`User-Agent`, SNMP `sysDescr`/`sysObjectID`, Modbus unit-id, Sparkplug
  BIRTH aliases) — **never requested by us**.
- **Cross-validated** fingerprints: a device is *classified* only when ≥2
  independent passive signals agree; otherwise it's a *candidate* (see §7 of
  detection-methodology and the OUI-collision lesson learned from prior art).

### 6.3 Output
- **Asset inventory** record per host: IP, MAC, OUI→vendor, protocol(s) +
  confidence, role, Purdue level, identity fields, first/last seen, conversation
  summary.
- **Risk indicator set** (passive-derived): unauthenticated/ cleartext control
  protocol exposure (e.g. Modbus writes, OPC-UA `SecurityMode=None`), cross-Purdue
  / cross-zone communication, suspicious external comms / C2-like beaconing,
  IT services on the OT network — each annotated with **MITRE ATT&CK-for-ICS** and
  **IEC 62443 SR** mapping + remediation guidance.
- **Export formats:** OCSF NDJSON (v1.4.x), plain **CSV/JSON report**, optional
  **SARIF 2.1** and a **STIX 2.1** bundle. All deterministic.
- **Run manifest + zero-egress attestation** (SAFETY-POLICY §7/§9).

## 7. Quality / acceptance criteria

- **A1 (safety):** the CI static guard + runtime assertion both pass; a run on a
  PCAP with `--mode passive` records `egress_packets=0`, `send_socket_on_in_scope=0`.
- **A2 (correctness):** on published ICS PCAPs (T3S / MALCOM test sets / public
  OT captures), protocol detection matches ground-truth labels above the
  per-protocol target (see `build-approach.md`), with confidence tiers and no
  *silent* mis-classification above L2.
- **A3 (no false-positive-as-certain):** mis-IDs are surfaced as *candidates* with
  confidence, never asserted; cross-validation required to promote to classified.
- **A4 (license):** core is Apache-2.0; no GPL/AGPL symbol linked into the core
  (copyleft deps run as separate processes / not at all); license check passes in CI.
- **A5 (lightweight):** cold-start < 10s; resident memory ≤ 1 GB at 1 Gbps drain;
  runs on a single core.
- **A6 (audit):** every finding cites the originating packet field offsets; two
  runs on one capture produce byte-identical output (determinism).
- **A7 (offline):** full MVP runs with no network egress; no required internet.
- **A8 (legal):** run manifest records authorization id, safety sign-off, PII/
  credential redaction config per SAFETY-POLICY §9.

## 8. Open questions for the returning user / stakeholders

1. **License final choice:** Apache-2.0 (recommended) vs MIT vs MPL. Confirm.
2. **Output schema:** OCSF-first (recommended) — acceptable, or do you also need
   a specific SIEM vendor format day one?
3. **Flow feeds:** is there an existing NetFlow/sFlow/IPFIX source at your sites,
   or should MVP be PCAP-only first (Phase 1)? (Phase 2 is flow.)
4. **Safety sign-off flow:** who is the named sign-off owner per deployment?
5. **OUI dataset source & license:** which vendor OUI list to vendor (see
   `license-assessment.md`)?
6. **Deployment target:** Linux-only for v0.1 OK? (Rust core; cross-compile later.)

## 9. Success metric (north star)

> A small utility can stand up passive monitoring on one mirror, within a week,
> get a defensible "this is what's on my OT network + what risks it exposes"
> report, **without anyone in the safety-critical path ever being contacted by the
> tool** — and can show, per run, that the tool sent *zero* bytes into that network.
