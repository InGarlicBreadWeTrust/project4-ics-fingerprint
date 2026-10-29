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

## Contact

- Open a new **draft issue** in this repo and label it `security` — GitHub
  notifies the owner (`@InGarlicBreadWeTrust`) immediately.
- Or contact the owner directly via the GitHub Contact-owner interface at
  `https://github.com/InGarlicBreadWeTrust` (also in the "About" sidebar).
- **PGP public key**: `PGP-KEY.asc` in this repo (RSA 4096, expires 2029-10-28).
  - Identity: `InGarlicBreadWeTrust <80548374+InGarlicBreadWeTrust@users.noreply.github.com>`
  - Fingerprint: `BC48:60A3:23AC:CA43:FE78:72FE:A0FD:52A2:0971`
  - Key ID (short): `0x52A20971`
  - For encrypted contact: import the public key with
    `gpg --import PGP-KEY.asc`, then encrypt your report with it.
