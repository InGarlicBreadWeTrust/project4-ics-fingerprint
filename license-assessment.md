# License Assessment — permissive core, copyleft-aware

> Goal: a permissively-licensed core (Apache-2.0) that small operators can use,
> vendor into commercial products, fork, and embed in substation hardware
> **without a copyleft infection** — while still *referencing* the AGPL/GPL prior
> art without legally tainting the core.

---

## 1. Decision (recommended)

- **Our own code + signature catalogue + OCSF output schema:** **Apache-2.0**
  (permissive + an explicit patent grant — important for OT/energy where the
   "help not get sued" posture matters; patent grant covers us). *MIT or MPL-2.0
  are acceptable alternatives; Apache-2.0 is recommended.* (See open-questions in
   `PRD §8`.)
- **Data / signature catalogue:** Apache-2.0 (data we own & control) — keep the
  catalogue under the project license so it can be redistributed without friction.

## 2. The copyleft traps in the prior art (do not link these into the core)

| Repo | License | Trap | How we handle it |
| --- | --- | --- | --- |
| `eris-ot/marlinspike` | **AGPL-3.0** | **Network copyleft (AGPL): "if you run it as a network service, downstream users must get source"** — would **infect a permissive/enterprise embed** | **Reference only.** If we use it, it runs as a **separate process** we call out-of-band (its *output* is data / OCSF NDJSON, not code); we never `link`/`include`/`import` its code. No AGPL in the core. |
| `eris-ot/marlinspike-dpi` | **AGPL-3.0** | Same AGPL network-copyleft | **Reference only.** Same process-isolation: consume its Bronze/OCSF *output* at most, never its code. Or just use it as a design reference for our own (Apache) DPI core. |
| `eris-ot/glassmarlin` | **AGPL-3.0-or-later** | Same + very new / low adoption = single-org/bus-factor risk | **Reference/design-inspiration only.** Not a dependency. (See "sustainability" in §4.) |
| `nsacyber/GRASSMARLIN` | **Non-standard NSA/CISA NOTICE (not a standard OSS license; archived 2023)** | **License is *non-standard* AND the project is **archived/read-only** → sustainability risk; not a permissive-licensed dependency | **Historical reference only.** Its method informs our design; we don't depend on the code (and can't rely on a dead license/project). |
| `thainnos/macDetec` | **GPL-3.0** | **Copyleft (strong copyleft, not merely copyleft):** linking GPL into the core **would force the whole core to GPL** → kills permissiveness | **Don't link.** *Re-use the OUI-lookup *idea* and a permissive OUI dataset* (not macDetec's GPL'd code/DB). If we want its DB, check its *dataset* license separately; otherwise derive our own from IEEE/IANA. |
| `corelight/zeek` | **BSD-3-Clause** | **PERMISSIVE** — no copyleft trap | **The safe base.** We *can* build a Zeek-script-based passive detector on Zeek without license infection; this is the recommended "permissive passive engine" foundation. (Zeek add-ons for ICS exist per prior art.) |
| `OISF/suricata` | **GPLv2** ("GPLv2, with additional license from OISF") | **Copyleft → can't link into a permissive core** | **Reference / separate process only.** If used, consume its **EVE JSON** output (data, not code) out-of-band; never link its GPL code. Suricata is *passive-capable* but its GPL forces process isolation from the permissive core. |
| `isovalent/yaf` | **GPL-3.0** (Yet Another Flow) | **Copyleft** | **Separate process / not linked.** Flow-generation, if needed, runs out-of-band; its *output* (IPFIX/JSON) is data we may consume. |

**The one-line rule:** *Our core stays Apache-2.0 and links nothing copyleft.
Every copyleft/AGPL/GPL prior-art component is (a) a design reference, or (b) a
separate process whose **output is consumed as data** — never as code in our tree.*

## 3. Datasets & schemas — license check before vendoring

| Item | Source(s) | License status | Verdict for us |
| --- | --- | --- | --- |
| **OUI / MAC vendor registry** | IEEE (official OUI registry), IANA, plus community lists (e.g. macOUI, Wireshark MAC-manufacturer — *check each list's license*) | Varies; **IANA/IEEE registry data is generally usable**, but *community lists* may be permissive or unclear — **must be checked individually; prefer permissive/MIT-sourced or derive from IANA** | **Vendored dataset must be Apache-2.0/CC0/CC-BY or derived from IANA; check & pin + checksum.** |
| **OCSF** (output schema) | OCSF / Open Cybersecurity Schema Framework | **Apache-2.0** | ✅ Use as output schema. |
| **STIX 2.1** | OASIS / MITRE | **CC-BY / permissive** | ✅ Use for threat-intel artifacts. |
| **MITRE ATT&CK-for-ICS** | MITRE | **CC-BY-4.0** | ✅ Map risks to it; data is CC-BY. |
| **NIST IEC 62443 refs / KEV** | CISA/STIX / NIST | Public domain / CC | ✅ Cite & cross-reference. |
| **Nmap NSE / nmap** | GPL-2.0 (strong) — *and active* | GPL + **active** | ❌ **Rejected entirely:** GPL *and* active — neither permissive nor passive. Never reference its "safe" probes (they're still active egress). |

> **Critical license lesson (from the task's brief):** "permissive license" for
> *our* project does **not** mean "use all the permissive things out there." Some
> of the best passive tools are **AGPL/GPL** and would *infect* a permissive core
> if linked. The permissiveness of our project is defended by **not** linking them —
> either as a design reference (read-only) or as a process whose *data output* we
> consume. This is the single most important license decision and it favors
> **Zeek (BSD-3) as the safe build base** over the AGPL Eris-OT family for the
> *build*, while the AGPL family remains a *methodological reference*.

## 4. Sustainability / bus-factor (license-adjacent legal risk)

The AGPL Eris-OT repos are **high-quality but ~2026, low-external-adoption
(1–3 stars / single-contributor for glassmarlin), single-org.** That is a
**sustainability risk** (the org could stop, or re-license) regardless of
license. Mitigations:

- Do **not** make the core *depend* on any single OSS project (Eris-OT, GRASSMARLIN,
   macDetec). Depend on **standards + permissive schemas** (OCSF, Zeek, IANA/OUI,
   MITRE ATT&CK) so a single project's death doesn't kill us.
- Pin versions & checksums of any dataset we vendor (OUI, ATT&CK, signature
   catalogue), and document the fallback if a source goes dead.
- **Avoid** adopting a project whose license is *non-standard / non-OSI*
   (GRASSMARLIN's NSA/CISA notice) as a hard dependency.

## 5. License hygiene in CI

- A **license check** in CI fails the build if any *core* (non-vendored) source
  carries GPL/AGPL/LGPL text, OR if a *vendored* file's declared license is
  incompatible with Apache-2.0 and not declared in `LICENSES`/`NOTICE`.
- A **SPDX `LICENSE`/`NOTICE`** + a `LICENSE` file (Apache-2.0 text) at repo root.
- **Patent grant:** Apache-2.0 carries an express patent grant; that's the
   reason it's preferred over MIT for a project touching energy/OT — it
   reduces the *sue-us-on-a-patent* vector that "help not get sued" wants to
   minimize.
- **No proprietary dependencies** anywhere in the core (no cloud SDKs that pull
   transitive copyleft, no "free for personal use" — that breaks "help not get
   sued").

## 6. Open questions

- Final license: **Apache-2.0 (recommended)** vs MIT vs MPL-2.0 — confirm.
- OUI dataset source + its exact license — pick a permissive/MIT/CC0 OUI list
  *or derive from IANA* and pin it; record the choice here and in the catalogue
  doc § C.
- Whether we will ever *process-consume* (vs just reference) an AGPL component —
   if yes, ensure the *consumed data output* and not the code, and that the
   process runs in a separate namespace (both for license *and* for the zero-
   egress guarantee — SAFETY-POLICY §7).
