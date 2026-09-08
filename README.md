# Drone Forensics Toolkit -- foundation layer

This is the first slice of the toolkit: the two modules everything else
(acquisition modules, ArduPilot/DJI parsers, timeline reconstruction, the
CLI, the report generator) will be built on top of.

- `normalize/schema.py` -- the platform-agnostic `NormalizedEvent` that
  every parser must emit into, plus a JSONL-backed `NormalizedEventStore`.
- `custody/ledger.py` -- a hash-chained (SHA-256 + BLAKE3), append-only
  chain-of-custody ledger. Any edit to a past entry is detectable via
  `verify_chain()`.

## Setup

```bash
pip install -r requirements.txt --break-system-packages
```

(Only `blake3` and `pytest` are actually exercised by this slice; the rest
of `requirements.txt` is pinned now so later weeks don't need dependency
churn.)

## Run the tests

```bash
pytest -v
```

## Why these two modules came first

Every acquisition module needs to hash evidence and log the action the
moment it touches a file -- so the custody ledger has to exist before any
real acquisition code is written. Every parser (DJI, ArduPilot, mobile
app) needs to emit into one common shape, or timeline reconstruction and
reporting would need to special-case every vendor -- so the schema has to
be fixed before parser work starts. Both are small and fully covered by
tests here, including a test that proves tampering with a past ledger
entry is actually detected (`tests/test_ledger.py::test_tampering_with_ledger_is_detected`).
