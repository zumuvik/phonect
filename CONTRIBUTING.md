# Contributing to phonect

Thank you for your interest in phonect!  This document outlines the process
for contributing code, documentation, and ideas.

## Code of Conduct

Be respectful, inclusive, and constructive.  Harassment, trolling, and
personal attacks will not be tolerated.

## Reporting Issues

- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md) — do **not**
  open a public issue.
- **Bugs and feature requests**: Use the
  [GitHub Issues](https://github.com/zumuvik/phonect/issues) tracker.
  Provide as much context as possible: OS version, Python version, logs, steps
  to reproduce.

## Development Setup

```bash
git clone https://github.com/zumuvik/phonect.git
cd phonect
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
# All tests
pytest

# Specific test files
pytest tests/test_crypto.py -v
pytest tests/test_daemon.py -v

# End-to-end CLI test
python scripts/e2e_cli_test.py
```

## Coding Standards

### Python (PC side)

- **Python ≥ 3.11** — use modern features (`dataclasses`, `tomllib`, etc.).
- **Type hints** everywhere — run `mypy` before committing.
- **Async** — the daemon uses `asyncio`.  Keep blocking I/O in executor threads.
- **Docstrings** — Google style (one-line for simple functions, full for public APIs).
- **Cryptography** — always use the `cryptography` library, never raw OpenSSL
  or low-level primitives.

### Kotlin (Android side)

- **Kotlin** — idiomatic Kotlin, no raw Java where avoidable.
- **Coroutines** — use `kotlinx.coroutines` for async operations.
- **RSA key material** must always be created with `setUserAuthenticationRequired(true)`
  in Android Keystore.
- **BiometricPrompt** — use AndroidX Biometric library, never the deprecated
  FingerprintManager API.

### Protocol Compatibility

The wire protocol is defined in `src/phonect/protocol.py`.  Any change to the
message format must be reflected in:
- Python `protocol.py`
- Kotlin `ProtocolHandler.kt`

## Branching and PR Workflow

1. Fork the repo and create a feature branch from `main`.
2. Make your changes, keeping commits atomic and well-described.
3. Run the full test suite: `pytest`
4. Ensure the E2E test passes: `python scripts/e2e_cli_test.py`
5. Open a Pull Request against `main`.

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add foreground service TCP listener
fix: handle connection reset during polling loop
docs: update threat model in SECURITY.md
refactor: move crypto ops to dedicated module
```

## Architecture Overview

```
┌────────────────────────────────────────────────────────┐
│  Linux PC                               Android Phone  │
│                                                         │
│  ┌──────────────┐     TCP (LAN)      ┌──────────────┐  │
│  │  phonect-daemon │◄───────────────►│  android app  │  │
│  │  (asyncio)      │                  │  (foreground   │  │
│  │                 │    JSON frames   │   service)     │  │
│  │  crypto.py      │                  │  CryptoManager │  │
│  │  handshake.py   │                  │  Biometric     │  │
│  │  protocol.py    │                  │  ProtocolHndlr │  │
│  └─────────────────┘                  └─────────────────┘  │
└────────────────────────────────────────────────────────┘
```

## Need Help?

Open a [Discussion](https://github.com/zumuvik/phonect/discussions) or ask in
the issue tracker.  We're happy to guide new contributors.
