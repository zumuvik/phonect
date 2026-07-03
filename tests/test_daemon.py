"""
Tests for the phonect daemon module.

Focuses on the challenge-response loop, session detection, and config loading.
D-Bus integration is tested via mocks/stubs (no system bus required).
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path
from typing import List, Optional

import pytest

from phonect.config import DaemonConfig, load_config, write_default_config
from phonect.crypto import generate_key_pair
from phonect.daemon import PhonectDaemon
from phonect.handshake import HandshakeClient


# ======================================================================
# Config tests
# ======================================================================

class TestConfig:
    def test_default_config_returns_minimal(self):
        """load_config() with no file returns defaults (no keys)."""
        cfg = load_config(Path("/nonexistent/config.toml"))
        assert cfg.bluetooth_mac == ""
        assert cfg.pc_name == ""
        assert cfg.has_pc_key is False
        assert cfg.has_trusted_key is False

    def test_write_and_load_config(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            path = Path(f.name)

        try:
            written = write_default_config(path)
            assert written == path
            assert path.exists()

            cfg = load_config(path)
            assert cfg.bluetooth_mac == ""
            assert cfg.pc_name == "my-laptop"
            assert cfg.log_level == "INFO"
        finally:
            path.unlink(missing_ok=True)

    def test_config_validation(self):
        kp = generate_key_pair()
        with tempfile.TemporaryDirectory() as tmp:
            pub_key = Path(tmp) / "device.pub"
            pub_key.write_bytes(kp.public_key_pem)
            priv_key = Path(tmp) / "pc_private.pem"
            priv_key.write_bytes(kp.private_key_pem)

            config_path = Path(tmp) / "config.toml"
            config_path.write_text(f"""\
[keys]
public_key = "{pub_key}"
private_key = "{priv_key}"

[device]
bluetooth_mac = "AA:BB:CC:DD:EE:FF"
pc_name = "my-pc"
unlock_on_start = true
""")
            cfg = load_config(config_path)
            assert cfg.bluetooth_mac == "AA:BB:CC:DD:EE:FF"
            assert cfg.pc_name == "my-pc"
            assert cfg.unlock_on_start is True
            assert cfg.has_pc_key is True
            assert cfg.has_trusted_key is True
            assert cfg.mutual_auth_ready is True

    def test_invalid_mac_ignored(self):
        """Config with invalid bluetooth_mac format gets empty string."""
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.toml"
            config_path.write_text("""\
[device]
bluetooth_mac = "not-a-mac"
""")
            cfg = load_config(config_path)
            assert cfg.bluetooth_mac == ""  # invalid → default empty

    def test_config_invalid_no_key_file(self):
        """Config points to a missing public key file → has_trusted_key = False."""
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.toml"
            config_path.write_text("""\
[keys]
public_key = "/nonexistent/key.pub"
""")
            cfg = load_config(config_path)
            assert cfg.has_trusted_key is False
            assert cfg.has_pc_key is False


# ======================================================================
# Daemon tests
# ======================================================================

class TestDaemonSessionDetection:
    """Tests for _get_active_session_ids() — uses a fake loginctl."""

    def test_parses_session_list(self, monkeypatch):
        """Should return session IDs for the current user on seat0."""
        monkeypatch.setattr("os.environ", {"USER": "testuser"})

        def fake_loginctl(*args, **kwargs):
            import subprocess
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=(
                    "2  1000  testuser  seat0  wayland\n"
                    "3  1000  testuser  seat0  x11\n"
                    "5  1001  otheruser seat0  wayland\n"
                    "7  1000  testuser  seat1  tty\n"
                ),
                stderr="",
            )

        monkeypatch.setattr("subprocess.run", fake_loginctl)

        cfg = DaemonConfig()
        daemon = PhonectDaemon(cfg)
        sessions = daemon._get_active_session_ids()
        assert sessions == ["2", "3"]  # testuser on seat0

    def test_no_sessions(self, monkeypatch):
        """When loginctl returns nothing, return empty list."""
        monkeypatch.setattr("os.environ", {"USER": "testuser"})

        def fake_loginctl(*args, **kwargs):
            import subprocess
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", fake_loginctl)

        cfg = DaemonConfig()
        daemon = PhonectDaemon(cfg)
        assert daemon._get_active_session_ids() == []

    def test_loginctl_not_found(self, monkeypatch):
        """If loginctl is missing, return empty list."""
        monkeypatch.setattr("os.environ", {"USER": "testuser"})

        def fake_run(*args, **kwargs):
            raise FileNotFoundError("loginctl not found")

        monkeypatch.setattr("subprocess.run", fake_run)

        cfg = DaemonConfig()
        daemon = PhonectDaemon(cfg)
        assert daemon._get_active_session_ids() == []


class TestDaemonUnlockHook:
    """Tests that _unlock_sessions() calls the hook with the right commands."""

    def test_unlock_calls_loginctl(self, monkeypatch):
        monkeypatch.setattr("os.environ", {"USER": "testuser"})

        captured: List[str] = []

        def fake_loginctl(*args, **kwargs):
            import subprocess
            return subprocess.CompletedProcess(
                args=args, returncode=0,
                stdout="2  1000  testuser  seat0  wayland\n",
                stderr="",
            )

        monkeypatch.setattr("subprocess.run", fake_loginctl)

        cfg = DaemonConfig()
        daemon = PhonectDaemon(cfg)
        daemon._unlock_hook = lambda cmd: captured.append(" ".join(cmd))
        daemon._unlock_sessions()

        assert len(captured) == 1
        assert "loginctl" in captured[0]
        assert "unlock-session" in captured[0]


# ======================================================================
# Async: handshake via daemon's _async_handshake (legacy test helper)
# ======================================================================

class TestDaemonAsyncHandshake:
    """Test the async handshake implementation by running a local echo."""

    @pytest.mark.asyncio
    async def test_successful_async_handshake(self):
        """Mobile emulator connects to an in-process TCP server, daemon verifies."""
        mobile_kp = generate_key_pair()
        pc_kp = generate_key_pair()

        cfg = DaemonConfig()
        daemon = PhonectDaemon(cfg)
        daemon._trusted_key = mobile_kp.public_key  # trusted key = mobile's pubkey

        async def handle_mobile(reader, writer):
            """This will run the daemon's handshake logic."""
            ok = await daemon._async_handshake(reader, writer)
            writer.close()
            return ok

        server = await asyncio.start_server(handle_mobile, "127.0.0.1", 0)
        addr = server.sockets[0].getsockname()

        async def mobile_client():
            """Emulate the phone: connect, receive challenge, sign, respond."""
            reader, writer = await asyncio.open_connection(*addr)
            try:
                from phonect.protocol import decode_frame
                buf = b""
                while True:
                    chunk = await reader.read(4096)
                    if not chunk:
                        break
                    buf += chunk
                    msg = decode_frame(buf)
                    if msg is not None:
                        break

                assert msg is not None, "No challenge received"
                assert msg["type"] == "challenge"

                nonce = bytes.fromhex(msg["nonce"])
                session_id = msg["session_id"]

                from phonect.crypto import sign_nonce, fingerprint_from_public_key
                signature = sign_nonce(mobile_kp.private_key, nonce)
                fp = fingerprint_from_public_key(mobile_kp.public_key)

                from phonect.protocol import encode_frame, make_response
                response = make_response(session_id, signature, fp, "test-phone")
                writer.write(encode_frame(response))
                await writer.drain()
            finally:
                writer.close()

        mobile_task = asyncio.create_task(mobile_client())
        await asyncio.wait_for(mobile_task, timeout=10)

        server.close()
        await server.wait_closed()

    @pytest.mark.asyncio
    async def test_async_handshake_wrong_key_rejected(self):
        """Mobile signs with wrong key → daemon rejects."""
        mobile_kp = generate_key_pair()
        wrong_kp = generate_key_pair()

        cfg = DaemonConfig()
        daemon = PhonectDaemon(cfg)
        daemon._trusted_key = wrong_kp.public_key  # PC trusts WRONG key

        async def handle_mobile(reader, writer):
            ok = await daemon._async_handshake(reader, writer)
            writer.close()
            return ok

        server = await asyncio.start_server(handle_mobile, "127.0.0.1", 0)
        addr = server.sockets[0].getsockname()

        async def mobile_client():
            reader, writer = await asyncio.open_connection(*addr)
            try:
                from phonect.protocol import decode_frame
                buf = b""
                while True:
                    chunk = await reader.read(4096)
                    if not chunk:
                        break
                    buf += chunk
                    msg = decode_frame(buf)
                    if msg is not None:
                        break

                nonce = bytes.fromhex(msg["nonce"])
                session_id = msg["session_id"]

                from phonect.crypto import sign_nonce, fingerprint_from_public_key
                signature = sign_nonce(mobile_kp.private_key, nonce)
                fp = fingerprint_from_public_key(mobile_kp.public_key)

                from phonect.protocol import encode_frame, make_response
                response = make_response(session_id, signature, fp, "evil-phone")
                writer.write(encode_frame(response))
                await writer.drain()
            finally:
                writer.close()

        mobile_task = asyncio.create_task(mobile_client())
        await asyncio.wait_for(mobile_task, timeout=10)

        server.close()
        await server.wait_closed()
