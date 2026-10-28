# Build Approach — passive ICS fingerprint, phased

> Everything here is built to `SAFETY-POLICY.md` (passive-only, zero-egress,
> bounded resources, sign-off manifest) and to the permissive license in
> `license-assessment.md` (Apache-2.0 core, no copyleft linked). Passivity and
> safety come before every feature.

---

## 1. Language & stack

| Layer | Choice | Why |
| --- | --- | --- |
| **DPI core (L1/L2/L3 dissection, feature extraction, fingerprinting)** | **Rust** | Memory-safety, zero-C dependency, no GC pause (safe for an embedded/edge substation appliance), deterministic. Mirrors `marlinspike-dpi`'s "zero-C, file-first, no sockets-by-default" design — *but Apache-2.0, not AGPL.* |
| **Orchestrator / collector / flow-ingest / output** | Rust core + **optional Python** orchestration | Python for glue (PCAP file iteration, flow-record ingest, SIEM output, reporting, tests) — fast to iterate; the *hot DPI path* stays Rust. |
| **Capture ingest** | PCAP/PCAPNG file iterator first; live mirror via a safe read-only interface (e.g. `pcap` file/reader, or a zero-C raw reader) | **File-first** (like the prior art) means we can *prove zero-egress trivially* (we never open a send socket) and validate offline before any live run. Live read-only capture is behind a flag with the §7 attestation. |
| **Flow feeds (P2)** | Minimal permissive parser or `isovalent/yaf` **as a separate process** (output = IPFIX/JSON data) | Flow = Tier-2 ingest; keep the copyleft YAF out-of-tree. |
| **Output** | **OCSF** NDJSON (Apache-2.0 schema), + CSV/JSON report, optional SARIF 2.1 + STIX 2.1 bundle | SIEM-ready, standard, permissive. |
| **Signatures** | Data files (YAML/JSON), version + checksum-pinned, **Apache-2.0 data** | Decouple signature updates from code; permissive. |
| **Passive IP/OUI** | OUI lookups (IEEE/IANA-derived per `license-assessment §3`); p0f-style derived IP fingerprint (implemented, *not* linked to GPL p0f) | Passive identity; permissive. |

## 2. Design invariants (from the docs, encoded in build)

- **Zero egress on the in-scope network** — enforced by two guards (§5), not just asserted.
- **Bounded state** — connection/flow tables are LRU size-capped; OOM ⇒ drop with
   back-pressure, never grow unbounded (SAFETY-POLICY §6).
- **Determinism** — no wall-clock/wall-RNG in classification; reproducible output
  (detection-methodology §8).
- **Provenance on every finding** — packet sequence + field offsets cited.
- **No phone-home / no telemetry / no secrets in code or logs** (SAFETY-POLICY §8).
- **Safety gate** — no SIS/EPOD/FIPS/ESD placement without the signed manifest (H6).

## 3. Components & module layout

```
passive-ics-fingerprint/
├─ safety/                 SAFETY-POLICY enforcement (manifest, egress assert)
│  ├─ manifest.rs/.py      run manifest + sign-off H6 check + zero-egress attestation
│  └─ egress_guard.rs      static + runtime zero-egress guards (§5)
├─ ingest/
│  ├─ pcap/                PCAP/PCAPNG file reader (zero-C, read-only)
│  ├─ live_capture/        optional read-only mirror reader (behind flag; asserts §7)
│  └─ flows/               NetFlow v5/v9 + IPFIX + sFlow (P2; yaf out-of-band)
├─ dissect/                L2/L3/L4 reassembly (bounded, stateful)
├─ dpi/                    protocol dissection → signatures (Rust hot path)
├─ signatures/             YAML/JSON signature catalogue (§catalogue doc), version-pinned
│  └─ oui/                 OUI dataset (permissive source), checksum-pinned
├─ fingerprint/            L0–L3 + cross-validation + OUI role + Purdue + risk mapping
├─ output/                 OCSF / CSV / JSON / SARIF / STIX + run manifest
├─ safety/manifest + signoff (written on every run, signed per SAFETY-POLICY §9)
└─ tests/                  passive-only proof per signature; CI guards; PCAP ground-truth
```

## 4. Phased plan (MVP first; passivity & safety in every phase)

### Phase 0 — Safety & scaffolding (do first, gate the rest)
- Repo + `LICENSE` (Apache-2.0) + `NOTICE` + `SPDX`.
- **`egress_guard`:** the static CI lint that fails on any outbound
   socket/connect/send/`tc`/`ip`/`nmap`/`fping`/vendor-HTTP (SAFETY-POLICY §7).
- **Runtime zero-egress attestation** + run **manifest** (SAFETY-POLICY §9; H6 sign-off).
- *Exit:* run with no ingest → attestation `egress_packets=0` + a signed manifest; CI green.

### Phase 1 — Passive PCAP core, 3 core protocols, permissive
- PCAP/PCAPNG file reader (zero-C, read-only).
- Dissect L2/L3/L4 (bounded).
- 3 core signatures **Modbus-TCP, S7comm, DNP3** (+ SNM/HTTP/DNS baseline + OUI
   lookup) — the most common rural-utility ICS protocols.
- L0–L3 confidence + **cross-validation** (§5 of detection-methodology) + OUI →
   vendor/role + Purdue inference.
- OCSF + CSV/JSON report + provenance + sign-off manifest.
- *Exit:* acceptance A1 (zero-egress attest + guard), A2 (correctness on
   published PCAPs), A4 (license clean), A5 (lightweight), A6 (deterministic),
   A8 (manifest).

### Phase 2 — Catalogue breadth + flow feeds
- Add signatures: IEC 60870-5-104, EtherNet/IP(CIP), OPC-UA, BACnet, PROFINET,
   HART-IP, Sparkplug B over MQTT, IEC 61850 MMS/GOOSE/SV, IEEE C37.118
   (§catalogue doc A). Each with a **passive-only proof test**.
- Flow ingest (NetFlow v5/v9, IPFIX, sFlow) — Tier-2, lower confidence, marked.
   (`isovalent/yaf` as a separate process; permissive flow parser.)
- Risk surface (§7 of detection-methodology): no-auth control traffic, cross-Purdue,
   cleartext sessions, C2-like beaconing, IT-on-OT — each mapped to IEC 62443 +
   ATT&CK-for-ICS.
- *Exit:* full catalogue at L1–L3; flow path works; risk scoring populated.

### Phase 3 — Baseline, drift, hardening, scale-out
- **Baseline & drift detection:** a "normal" OT topology baseline + alert on new/
  changed devices/protocol/comms (anomaly = passive finding). Deterministic.
- **Distributed collectors:** many small substation sites → one out-of-band
   collector; collectors send **results** out-of-band, **never** anything into the
   OT segment.
- **SARIF + STIX + CISA-KEV IOC matching** (against observed payloads/URLs —
   passive matches, not active probes).
- **SIEM export** (OCSF/SARIF/JSON; add a specific SIEM adapter if a stakeholder
   names one — open question in PRD §8).
- Hardening: cgroup memory cap, crash-safe output, chaos tests (huge/long
   captures don't OOM or corrupt).

## 5. The zero-egress test harness (the differentiator — non-negotiable)

**5.1 Static CI guard** (fails build if found):
- grep/AST: `connect(`, `socket(` (`SOCK_STREAM`/`SOCK_DGRAM`/`UDP` w/
  in-scope), `send`/`sendto`/`write` to a network fd, `fork+exec` of
  `nmap|fping|hping3|masscan|ping`, `tc`/`iptables`/`nftables`/`ip link`/`ip addr`
  add/delete, `curl`/`wget`/outbound-HTTP to any address, `setsockopt`
  forwarding rules.
- **Allow-list:** the *out-of-band* result channel (an explicitly-declared
   collector host + port) is whitelisted; the in-scope OT network is never in the
  allow-list.
- **Negative-test fixtures:** the suite *adds* each forbidden construct and
  asserts the guard *catches* it (guard must not go false-negative).
- **License guard:** SPDX/lichecheck fails on GPL/AGPL/LGPL in a core file.

**5.2 Runtime attestation** (every run):
- the process opens capture **read-only**; asserts on start it holds **no**
  send-capable socket on the in-scope interface (or runs in a **Linux network
  namespace** with the in-scope interface unshared — the recommended default,
   making egress on OT *structurally* impossible).
- writes to the manifest: `egress_packets=0; send_socket_on_in_scope=0;
  net_ops=off` + the chosen mechanism + the signed sign-off (SAFETY-POLICY §9).
- **negative test:** the harness *tries* to open a send socket and asserts the
   guard/runtime **refuses**; a successful refusal is the passing test.

**5.3 Deployment topology (production):** collector agent on the mirror/SPAN/TAP
port (off the forwarding path); agent's network namespace isolates OT; agent
sends **results only**, out-of-band, to the approved channel; PCAPs encrypted at
rest, access-logged, retained per the DPA, **credential-bearing fields
redacted** (SAFETY-POLICY §8).

## 6. Validation plan (no active testing — ever)

- **Golden PCAPs:** run the MVP on **published/public ICS PCAPs** (T3S / MALCOM
   ICS test sets, public OT captures, and — *carefully, as data only* — sample
   PCAPs from the prior art). For each, compare our fingerprint vs ground truth
   and record per-protocol **detection rate + false-positive + confidence-tier
   accuracy**. **No live active tests. No probe of any device that isn't already
   emitting traffic we observe.**
- **Determinism test:** two runs on one capture ⇒ byte-identical output.
- **Egress test (§5):** the suite asserts 0 egress; the negative tests prove the
   guard is non-vacuous.
- **Resource test:** at 1 Gbps drain, resident memory ≤ 1 GB, no OOM/crash over a
   long (≥24 h) capture; graceful SIGTERM.
- **"Safe in prod" demonstration:** run the agent on a *mirror* in a lab with
   real ICS, confirm `egress_packets=0` attested, and confirm the ICS devices
   show **zero new/changed behaviour** (a control-loop health baseline before/after
   — a passive "we didn't touch you" proof for the safety officer).

## 7. Definition of "build" vs "ship"

- **Build (this repo):** a runnable passive PCAP analyzer with 3+ protocols,
   zero-egress guarded, permissive-licensed, OCSF output, deterministic,
   manifest-signed. ✅ target v0.1.
- **Ship (production, per-deployment):** the v0.1 **plus a per-deployment human
   sign-off** (SAFETY-POLICY §9), capture placement reviewed by the OT owner +
   safety officer, resource caps set for the site, credentials redacted, DPA in
   place. **Ship is gated, not automatic** — "help not get sued" requires the
   human sign-off, not just correct code.

## 8. Risks & mitigations (cross-ref)

- **Copyleft infection** → process-isolate / don't link copyleft; Apache-2.0 core
  (license-assessment.md).
- **Zero-egress is asserted but not proven** → the §5 guard + attestation *prove*
  it; namespace isolation is the default.
- **Signature currency / false-positives** → confidence tiers, cross-validation,
   OUI-class-not-product, version+checksum-pinned catalogues.
- **Resource blowup in a substation** → bounded LRU state, cgroup caps, graceful
  degrade.
- **Stale prior art** → depend on standards/permissive schemas, not single projects
  (license-assessment §4).

## 9. First 5 things to build (concrete order)

1. `LICENSE`/`NOTICE`/SPDX + `egress_guard` static lint (Phase 0) — *before any protocol code*.
2. PCAP/PCAPNG read-only file reader + L2/L3/L4 bounded dissect.
3. Modbus-TCP / S7 / DNP3 signatures + OUI lookup + cross-validation.
4. Runtime zero-egress attestation + run manifest + sign-off checklist.
5. OCSF + CSV/JSON output + determinism test + golden-PCAP validation.
→ **This order exists so the tool can never, even at 0.1, send a byte into a network.**
