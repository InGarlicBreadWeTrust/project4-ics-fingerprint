# Security Disclosure

This project fingerprints ICS/OT traffic **passively** on the management side only
(ingest → dpi → fingerprint → OCSF output). It never sends packets and, by
construction, opens **no off-box network socket** during a run. Reports should
treat it as a passive detector, not an active scanner.

## Responsible disclosure

1. **Do not disclose publicly** before a coordinated fix exists.
2. Email a summary + repro to the maintainers (or open an issue labelled
   `security` in the repo).
3. We aim to acknowledge within 5 business days and patch material findings within
   30 days.

## In scope (and what is proven in CI)

- Core analysis layers under `ingest/`, `dpi/`, `fingerprint/`, `output/`,
  `safety/` import **no network primitives** — CI runs a static check that
  asserts zero egress primitives in core.
- **Runtime attestation** asserts the pipeline opens no new off-box socket during a
  run. A bypass of this guarantee is in scope.
- Signature parsing (`dpi/signatures.py`) and the fingerprint pipeline.

## Out of scope

- Live target systems — this project does not run on them.
- Any content repurposed for active scanning or attack.

## By construction

The pipeline is passive: it reads a mirror/tap and writes OCSF output. No
telemetry, no call-home. See `README.md` "Design principles".
`requirements.txt` declares the sole third-party dependency (PyYAML).

<!-- TODO(maintainer): fill in a real disclosure channel here. -->
