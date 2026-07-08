#!/usr/bin/env python3
"""
End-to-end CLI test: spawns server, connects client, verifies handshake.
More reliable than bash-based tests.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
if not VENV_PYTHON.exists():
    VENV_PYTHON = Path(sys.executable)


def run(*args: str, timeout: float = 15) -> subprocess.CompletedProcess:
    """Run a phonect CLI subcommand, return CompletedProcess."""
    cmd = [str(VENV_PYTHON), "-m", "phonect.cli", *args]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        # 1. Generate mobile keypair
        priv = tmp_path / "mobile.pem"
        pub = tmp_path / "mobile.pub"
        result = run("gen-keys", f"--private-key={priv}", f"--public-key={pub}")
        print(result.stdout)
        if result.returncode != 0:
            print("FAIL: key generation", result.stderr, file=sys.stderr)
            return 1

        # 2. Start server in background
        log_file = tmp_path / "server.log"
        with open(log_file, "w") as lf:
            server_proc = subprocess.Popen(
                [str(VENV_PYTHON), "-m", "phonect.cli", "server", str(pub),
                 "--port=0", "--timeout=15"],
                stdout=lf,
                stderr=subprocess.STDOUT,
                text=True,
            )

        # Wait for server to be ready and extract port
        port = None
        for attempt in range(20):
            time.sleep(0.25)
            log_text = log_file.read_text() if log_file.exists() else ""
            import re
            for line in log_text.splitlines():
                # "Listening on port 38365 ..."  (from print)
                m_port = re.search(r"port\s+(\d+)", line.lower())
                if m_port:
                    port = int(m_port.group(1))
                    break
                # "HandshakeServer listening on 0.0.0.0:38365 ..."  (from log)
                m_addr = re.search(r":(\d+)\s*\(", line)
                if m_addr:
                    port = int(m_addr.group(1))
                    break

            if port is not None:
                break

        if port is None:
            server_proc.kill()
            server_proc.wait()
            print("FAIL: could not determine server port", file=sys.stderr)
            print(log_file.read_text())
            return 1

        print(f"Server started on port {port} (PID={server_proc.pid})")

        # 3. Run client
        client_proc = subprocess.run(
            [str(VENV_PYTHON), "-m", "phonect.cli", "client", str(priv),
             "127.0.0.1", str(port),
             "--device-name=e2e-test-phone", "--timeout=10"],
            capture_output=True,
            text=True,
            timeout=20,
        )

        # Wait for server
        server_proc.wait(timeout=10)

        print("\n=== SERVER LOG ===")
        print(log_file.read_text())

        print("\n=== CLIENT STDOUT ===")
        print(client_proc.stdout)
        if client_proc.stderr:
            print("=== CLIENT STDERR ===")
            print(client_proc.stderr)

        if client_proc.returncode == 0:
            print("\n✓ E2E CLI TEST PASSED")
            return 0
        else:
            print("\n✗ E2E CLI TEST FAILED")
            return 1


if __name__ == "__main__":
    sys.exit(main())
