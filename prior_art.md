# Prior-art Landscape & Name Resolution (research report)

> Passive ICS device fingerprinting + asset discovery. This report resolves the
> repos named in the brief, assesses each on **license + last-push/activity +
> aliveness(maintained)**, and confirms the **passive-only safety property** (no
> active probe / no malformed packet / no DoS-capable scan — safe to run in
> production). Goal: "help not get sued."
>
> **Caveat on exact commit dates:** exact `last_push` dates for some repos are
> from web/registry snapshots taken during this research window; for production
> build-decision, **re-validate** license + `pushed_at` + `archived` directly
> against the GitHub API (`license.license.spdx_id`, `pushed_at`, `archived`,
> `stargazers_count`) with a token — see `build-approach.md §6` and the
> "what's missing" in the report JSON.

---

## A. Repos named in the brief — resolution & assessment

| Repo (resolved) | Original brief name | License | Last activity | Maintained? | Passive-only safety? | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| **`nsacyber/GRASSMARLIN`** | "ICSFingerPrint" (unresolved) → **GRASSMARLIN lineage** | **Non-standard NSA/CISA NOTICE (not an OSI/standard OSS license)**; archived 2023-04-14 (read-only, no new commits) | **`pushed_at` frozen since 2023-04-14; `archived=true`** | **NO (archived 2023)** | **YES (by design: passive-only; "does no active scans, only listens")** but *dead.* | The canonical historical passive ICS topology mapper — the real "ICSFingerPrint." **Do NOT depend on it** (de-fact standard license is non-standard AND it's dead); use its *method* as reference. |
| **`eris-ot/marlinspike`** | "marlinspike/marlinspike-dpi" (resolved) | **AGPL-3.0** | Continuous through 2026 (v3.5.5; 18 releases; created 2026-03-25) | **YES** | **YES (explicit: "all detection and analysis is passive… no active scanning or packet transmission of any kind")** | Reference (AGPL → do not link into our permissive core; consume only its *data output* if at all). |
| **`eris-ot/marlinspike-dpi`** | "marlinspike/marlinspike-dpi" | **AGPL-3.0** | Continuous 2026 (v1.16.0; 6 releases / 19 tags; created 2026-03-26) | **YES** | **YES (strongest passive property we saw: "parses captured network frames rather than capturing interfaces, so it binds no sockets, captures no interfaces, and runs from any directory")** — ideal *design* reference for our Rust DPI core. | Reference-only (AGPL); our core is Apache-2.0 so we *reimplement the passive-parsing idea*, not link theirs. |
| **`eris-ot/glassmarlin`** | (passive PCAP triage successor) | **AGPL-3.0-or-later** | v0.1.2, 2026 — **very new, 1 star, single-contributor** | **YES, but sustainability-risk (single-org, low adoption)** | **YES ("read a packet capture; produce a structured report… no Python, no Wireshark, no Docker, no internet connection")** | Design-inspiration only; **not a dependency** (bus-factor / single-org risk; AGPL). |
| **`thainnos/macDetec`** (= `ITI/ICS-Security-Tools/macDetec`, "ICS-Peer"-ish passive asset enumeration) | "ICS-Peer" / "ICSAssetScanner" (no canonical repo) | **GPL-3.0** | **Last commit Oct 26, 2020 — STALE/NOT maintained** | **NO (stale 5 yrs)** | **YES (passive ARP/MAC-OUI identification — "passively identifies ICS device types by reading MAC addresses and OUI prefixes from traffic; no active scanning… does not send any packets")** | The canonical **passive asset-discovery-by-OUI** tool — a *design reference* for our OUI layer (use the *idea + a permissive OUI dataset*, NOT its GPL'd code/DB; and it is **stale**, so its OUI data is untrustworthy). |
| **`corelight/zeek`** (Zeek, former Bro) | (general passive analyzer base) | **BSD-3-Clause (permissive)** | Continuous (Corelight custodian since 2017), actively maintained | **YES** | **YES (passive network-analysis framework by design; Zeek never actively probes; ICS add-ons exist as community/passive scripts)** | **The recommended permissive build base** (see `license-assessment.md`). Zeek + a passive ICS script set is a permissive, non-copyleft passivity path. |
| **`OISF/suricata`** | (DPI engine reference) | **GPLv2** ("GPLv2, with additional license from OISF") | 8.0.7 released 2026-09-15, active | **YES** | **YES (passive-capable: sniffs and inspects, can be deployed in sniffer mode; but it's a GPL engine)** | Reference / separate-process only (GPL → can't link into a permissive core; consume its EVE-JSON out-of-band). Suricata's ICS ruleset supports passive detection of ICS protocols. |
| **`isovalent/yaf`** | (flow generator; Tier-2 ingest) | **GPL-3.0** | Maintained by Isovalent/Anomali; less frequent (not daily) | **YES (but not daily)** | **YES (purely passive flow generation from PCAP/live)** | Reference / separate process for NetFlow/IPFIX/sFlow ingest; don't link GPL into core. |

### Name-resolution summary (the "canonical name unresolved" finding)

- **`ICSFingerPrint`** → the task's name is unresolved as a *live canonical
   repo.* The closest canonical passive ICS mapper is **NSA/CISA GRASSMARLIN
   (`nsacyber/GRASSMARLIN`)** — now archived — and its modern successor is the
   **Eris-OT family** (marlinspike / glassmarlin). We treat "ICSFingerPrint" as
   "the GRASSMARLIN→Eris-OT passive-mapping lineage."
- **`marlinspike/marlinspike-dpi`** → resolves to **`eris-ot/marlinspike-dpi`**
   (and the related `eris-ot/marlinspike`).
- **`ICS-Peer` / `ICSAssetScanner`** → **no canonical public repo by those exact
   names.** The brief's *intent* (passive ICS device discovery / asset enumeration)
   maps best to **`thainnos/macDetec`** (passive OUI/MAC device identification;
   GPL-3.0, stale, passive-safe) — i.e. "passive asset discovery by MAC/OUI." We
   implement that capability ourselves (permissive OUI dataset, not macDetec's
   GPL DB); macDetec remains a design reference only.
- **None** of the brief's four names is a *maintained permissively-licensed
   passive* dependency ready to link — which is exactly why we build our own
   permissive core and reference them per `license-assessment.md`.

---

## B. Broader passive ICS / asset-discovery landscape (context, lower confidence)

| Item | Notes |
| --- | --- |
| **NIST / ICS-CERT test data (T3S, MALCOM)** | Public ICS PCAPs + test sets — the right **validation corpus** (run our tool *on* them, never *into* them). Not a live tool. |
| **Commercial passive platforms** (Nozomi, Dragos, Claroty, Fathom) | Passive-by-design at enterprise cost — the commercial benchmark we aim to match *for small operators*. Out of scope to replicate. |
| **`shodan` / `IoTDB`-style external scans** | **EXCLUDED** — active external scanning ≠ passive; not for use *inside* a live substation. |
| **`nmap` NSE "safe" probes** (`modbus-discover`, `s7-info`, `bacnet-info`) | **EXCLUDED** — these are *active* (open a connection); even "safe read-only" is active egress and can stress a PLC. Forbidden by `SAFETY-POLICY.md H1/H4.* |
| **Passive-only emerging/new tools (low confidence, 2026)**: e.g. `SiteQ8/ConduitShield`, `AhmedQazafy/Scrutics-Lightweight-OT-ICS…`, `oliver-dolski/wayside`, `rameyjm7/rf-sentinel`, `frangelbarrera/industrial-scanner` | A wave of new passive/OT tools appeared in 2026, but most are **<1–14 stars, single-contributor, unvetted**; **do not adopt** — note-and-watch only. (`frangelbarrera/industrial-scanner` reportedly mixes passive + **active modbus probing** → NOT passive-safe → excluded.) |
| **STIX / OCSF / MITRE ATT&CK-for-ICS / IEC 62443 / NIST SP 800-82r3** | Standards & schemas — the *safe, permissive, durable* dependencies. **Output + mapping layer** (OCSF Apache-2.0; ATT& CC/STIX CC-BY; IEC 62443/800-82 as reference). |
| **Purdue / ISA-95 model** | The topology model we map devices/segments to (passive, inferred from subnet + conversation topology). Not an active tool. |

---

## C. What matters for our build (the synthesis)

1. **Passive-only is the universal design property** across every usable candidate
   (GRASSMARLIN "does no active scans, only listens"; Eris-OT "no active scanning
   or packet transmission"; macDetec "does not send any packets"; Zeek is passive
   by framework design; YAF is passive flow gen). **We match this, and add a
   machine-provable zero-egress guard** (the differentiator; see
   `build-approach.md §5`) that none of the candidates *fully* provide out-of-
   the-box.
2. **The one permissive license is Zeek (BSD-3).** The AGPL Eris-OT family is
   *great but non-linkable* for a permissive core; **we reference their passive-
   parsing design and build our own Apache-2.0 Rust DPI core** (their
   `marlinspike-dpi` "binds no sockets / runs from any directory by default" is the
   gold-standard passive-parsing pattern to copy in a non-AGPL license).
3. **Aliveness is the trap.** The historically-canonical tools are **dead or stale**
   (GRASSMARLIN archived 2023; macDetec stale since 2020). The *live* tools are
   either copyleft (Eris-OT AGPL; Suricata/YAF GPL) or too new to trust
   (2026 wave, 1–3 stars). **Mitigation: depend on durable standards + Zeek, pin &
   checksum datasets, keep all copyleft as separate processes** (`license-
   assessment.md §4`).
4. **Safety sign-off is a build gate, not a nicety.** Because this runs *inside a
   live substation*, the per-deployment human sign-off
   (`SAFETY-POLICY.md §9`) — authorization, safety-officer, PII/redaction, DPA —
   is what makes "help not get sued" real. Correct code is necessary; signed
   placement is sufficient.

---

## D. Re-validation checklist (before build; `build-approach §6` / "what's missing")

For each `prior_art` repo, re-pull live against the GitHub API (with a token, to
beat the unauthenticated rate limit / the "curl to api.github.com" that was
blocked this session):
- `license.license.spdx_id` (confirm exact SPDX; watch GRASSMARLIN's non-standard
  NOTICE and Eris-OT AGPL).
- `pushed_at` / `updated_at` + `archived` (confirm aliveness: GRASSMARLIN archived,
  macDetec stale).
- `stargazers_count` / contributor count / last-release date (sustainability/bus-
  factor flag).
- For `macDetec`/OUI datasets: confirm the **OUI dataset's** license (community lists
  vary) — pick a permissive source or derive from IANA (`license-assessment §3`).
- Confirm the "passive-only" property in the *current* code, not just the README
  (README can drift; check the code path for any `connect(`/e.gress).

---

## E. Sources consulted (this research run)

- GitHub: `nsacyber/GRASSMARLIN` (README/CHANGELOG — passive, "no active scans,"
  archived 2023-04-14; successor `eris-ot/marlinspike`).
- GitHub / Eris-OT: `marlinspike`, `marlinspike-dpi` (zero-C passive PCAP DPI;
  "binds no sockets… no active scanning"; OCSF/Bronze output; OUI-collision bug
  fix noted — relevant to our cross-validation discipline), `glassmarlin`.
- GitHub / `thainnos/macDetec`(+`ITI`): passive OUI/MAC device ID; GPL-3.0;
  "does not send any packets"; last commit 2020 → stale.
- Vendor / community: Zeek (`corelight/zeek`, BSD-3, OT add-ons), Suricata
  (`OISF/suricata`, GPLv2, ICS rules + EVE JSON), YAF (`isovalent/yaf`,
  GPL-3.0, IPFIX), OCSF (Apache-2.0), MITRE ATT&CK-for-ICS, STIX 2.1, IEC
  62443, NIST SP 800-82 r3, NIST/MALCOM/T3S ICS test data.
