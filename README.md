# Passive-ICS-Fingerprint — defensive OT/ICS asset discovery for small & rural utilities

> **DEFENSIVE / SAFETY-FIRST / PASSIVE-ONLY.** No active probes. No synthetic or
> malformed packets. No DoS-capable scans. Sends **zero packets to the network**.
> Built for rural co-ops, small & community utilities, and other operators who
> cannot afford an active scan to crash a PLC or trip a safety system — and who
> want to *not get sued* for touching production ICS.

**Status:** first-draft OSS skeleton (research + design). No code yet. See `build-approach.md`.

---

## Why this exists (the "help not get sued" thesis)

Active ICS scanning is dangerous *and* legally fraught:

- **Physical risk.** A probe that is routine on an IT host (a SYN flood, a malformed
  Modbus/S7 request, an aggressive `nmap -sV`) can stall a PLC, reboot an HMI, or
  trip a Safety Instrumented System. That is a *physical-world* consequence, not a
  log line. In critical infrastructure that can mean loss of service, equipment
  damage, or — in energy/water/hospitals — real-world harm.
- **Legal risk.** Authorized *passive* observation of traffic you are entitled to
  mirror is defensible. *Active* probing of a network you do not own can be
  construed as unauthorized access (CFAA-style), can create liability for
  downstream physical harm, and can violate the utility's incident response.
  **Passivity is the legal moat.** If we never send a byte into the in-scope
  network, we cannot have "caused" a malfunction and "unauthorized active
  access" claims are hard to make.

This project is the *passive* end of the ICS asset-discovery spectrum: it learns
about devices **only from traffic that already exists** on a SPAN/TAP/mirror, a
PCAP file, or a NetFlow/sFlow/IPFIX feed. It is safe to run in production, in a
live substation/sensor network, 24x7, next to a relay.

---

## What it does (one paragraph)

Ingest **passively-captured** network data (PCAP/PCAPNG on a mirror port, or
NetFlow/sFlow/IPFIX flow records) and produce a **device & protocol fingerprint
inventory**: for every observed host — IP, MAC/OUI→vendor, protocol identity +
confidence tier, inferred role (PLC/RTU/HMI/OPC-server/historian/gateway),
inferred Purdue level, and device-identity fields drawn only from observed
packets (OPC-UA endpoints, HTTP banners, SNMP sysDescr, Modbus unit-id, Sparkplug
BIRTH aliases, …). Output is a permissive, reproducible, **SIEM-ready** artifact
(OCSF + a plain JSON/CSV report) with every finding traceable to the exact bytes
that produced it. **No bytes are ever sent back onto the observed network.**

---

## Safety policy is the product (front-and-center)

👉 **Read `SAFETY-POLICY.md` first.** It is the operating contract. It is also
enforced: a CI/build guard and a runtime assertion both prove the analysis process
**egresses zero packets on the in-scope network.** The design, the code, and the
tests all derive from that one rule.

Passive-only safety is not a preference; it is the single most important property
of this tool, and it is what makes the others (fingerprint accuracy, licensing,
deployment) safe to do in a substation.

---

## Repository / doc map

| Doc | Purpose |
| --- | --- |
| `SAFETY-POLICY.md` | **The passive-only safety contract. Read first.** Hard rules, egress proof, physical-safety gate, legal basis. |
| `PRD.md` | Product requirements — goals, users, scope, non-goals, acceptance criteria. |
| `detection-methodology.md` | How detection works: pipeline, signals, confidence tiers, cross-validation. |
| `signature-catalogue.md` | **Starter signature catalogue** (protocol → detection → fingerprint fields), permissive & passive-verified. |
| `license-assessment.md` | Licensing strategy (permissive core) + copyleft traps of the prior art. |
| `build-approach.md` | Build plan: languages, phases, the no-egress test harness, validation. |
| `prior_art.md` | Researched landscape + name-resolution of the originally-named repos. |

---

## Prior-art one-liner (full detail in `prior_art.md`)

- **`nsacyber/GRASSMARLIN`** — the canonical NSA/CISA passive ICS topology mapper — **archived 2023-04-14, read-only** (the historical origin of "ICSFingerPrint").
- **`thainnos/macDetec`** — passive ARP/MAC-OUI device identification — **GPL-3.0, last commit Oct 2020 (STALE)**.
- **`eris-ot/marlinspike`**, **`eris-ot/marlinspike-dpi`**, **`eris-ot/glassmarlin`** — the modern passive OT/ICS family (PCAP in, no bytes out), **AGPL-3.0**, very active but **AGPL (network copyleft) and ~2026, low-adoption** → reference, do not link.
- **`corelight/zeek`** — **BSD-3 (permissive)**, the gold-standard passive analyzer → the safe base to build on.
- **`OISF/suricata`** — DPI engine, **GPLv2 (copyleft)** → reference, separate process only.

**Name-resolution of the task's originally-named repos** (see `prior_art.md` for the
full reasoning): the names `ICSFingerPrint` and `marlinspike/marlinspike-dpi` resolve
to the **Eris-OT GRASSMARLIN lineage**; `ICS-Peer` / `ICSAssetScanner` have no
canonical public repo and map to macDetec + the Eris-OT family. This is the
"canonical name unresolved" finding — recorded, not assumed.

## License

Intended: **Apache-2.0** (permissive, with a patent grant) for our own code and
signature data. Rationale and the copyleft traps that *forbid* statically linking
any prior-art engine into our core → `license-assessment.md`.

---

*No secrets in this repo or in our capture pipeline. No telemetry. No outbound to
any vendor server. See `SAFETY-POLICY.md` §Data minimization.*
