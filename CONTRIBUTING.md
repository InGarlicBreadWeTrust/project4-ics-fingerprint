# Contributing

This is the `project4-` passive ICS/OT packet-fingerprint pipeline
(ingest -> dpi -> fingerprint -> OCSF output). It is deliberately small,
stdlib-only core, and passive. The bar for a merged change: "prove it passive and
keep CI green."

## How to contribute

1. Fork the repo.
2. Work on a feature branch.
3. Add a test under `testvectors/` (a `test_*.py` file or a new fixture +
   `check_` function in `testvectors/_lib.py`) that exercises the layer you
   changed.
4. Open a PR with a short description of what changed and the new test you added.

## We accept

- New DPI signatures (YAML under `dpi/signatures/`) + their signature-file test.
- New fingerprint heuristics with regression tests.
- Clarifying docs, especially around the safety layer.
- Bug fixes that keep every check green.

## We do not accept

- Any code that imports a network primitive in the core layers
   (`ingest/`, `dpi/`, `fingerprint/`, `output/`, `safety/`). CI runs a
  static check that asserts **zero off-box network egress** in core; the run
  must not phone home.
- Any active-scanning capability or a path that sends packets to a target.
- A new third-party dependency without a note in `requirements.txt` and a
   one-line justification in the PR.
- Secret material, credentials, or telemetry/call-home.

## CI (must stay green)

1. `unit` — the `testvectors/` test suite (3.9-3.12 matrix).
2. `static-egress` — core layers contain no network primitives.
3. `runtime-attest` — a full pipeline run opens no new off-box socket
   (`python3 -m safety.attestation`).

## Before you push

- `python3 -m unittest discover -s testvectors -p 'test_*.py' -v`
- `python3 -m safety.attestation`
