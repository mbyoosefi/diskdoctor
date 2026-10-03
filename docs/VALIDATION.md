# Validation record

## Authoritative baseline

- main / v1.9.5: `d57178e94a2d90fb1483e3a7daecaf98d0f0ca50`.
- Baseline diskdoctor.py SHA-256:
  `c80f562c64698692a126d00d575ae78b5ea0fc9b3fc00c311ed88e40337b06e1`.
- Unmodified baseline self-test: **229/229 passed**, Python 3.10 / Windows.
- Baseline fixture is byte-preserved in tests/baseline_v195.py.

## V2 regression method

The preserved field suite is executed with current forensic functions, including
filesystem probes, partition parsing, evidence, triage, entropy controls, raw
search, VBK ranking/verification and auto mode. Historical mutation assertions
run inside the reference fixture only; they do not authorize v2 writes. Actual
v2 source mutation, rejection, transaction/rollback and injected failures are
tested independently in tests/test_safety.py. AST comparisons additionally pin
preserved algorithms and aligned read behavior to the baseline.

The final local run passed **229/229 field assertions and 75/75 v2 tests**,
including persisted readback tamper detection. Syntax compilation passed;
the combined self-test exited 0. The CI matrix is recorded separately below.

All local tests use Python 3.10 and Windows. Physical disk state tests are mocks;
all byte mutations use synthetic regular images. No real physical disk was read,
offlined, repaired or written during implementation/testing.

## CI

`.github/workflows/safety.yml` defines all six requested combinations:

| OS | Python | Result |
|---|---|---|
| Ubuntu 22.04 | 3.8 | passed |
| Ubuntu 22.04 | 3.10 | passed |
| Ubuntu 22.04 | 3.12 | passed |
| Windows 2022 | 3.8 | passed |
| Windows 2022 | 3.10 | passed |
| Windows 2022 | 3.12 | passed |

All six jobs passed on implementation/documentation commit
`32bfb47f9a13235b46d2585df43faaa81087a23b` in
[workflow run 37123496389](https://github.com/mbyoosefi/diskdoctor/actions/runs/37123496389).
The subsequent validation-record commit changes this documentation only.

Each job compiles syntax, runs the unit/write-safety/fault-injection/tamper and
read-only invariance suite, then runs the preserved self-test scenarios.
Workflow configuration alone is not a passing CI result. Do not create a final
release before remote results and review are complete.

See [HARDENING.md](HARDENING.md) for unsupported and UNKNOWN cases and
[MUTATION_AUDIT.md](MUTATION_AUDIT.md) for the complete mutation audit.
