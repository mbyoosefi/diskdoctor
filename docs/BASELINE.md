# Baseline capture

Repository: https://github.com/mbyoosefi/diskdoctor
Branch: main; tag: v1.9.5
Commit: d57178e94a2d90fb1483e3a7daecaf98d0f0ca50
SHA-256 diskdoctor.py: c80f562c64698692a126d00d575ae78b5ea0fc9b3fc00c311ed88e40337b06e1
Baseline self-test: **229/229 passed**, exit 0, Python 3.10, Windows.
Command: python diskdoctor.py --self-test --lang en --no-color

The unmodified implementation is retained in tests/baseline_v195.py as a
reference fixture. Its write tests use synthetic images only. The v2 tests
must additionally test intentional rejection of unsafe v1 authorizations.
The reference is never a production entry point or a v2 safety gate.
