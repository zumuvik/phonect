"""
Tests for the phonect daemon module.

Focuses on the challenge-response loop, session detection, and config loading.
D-Bus integration is tested via mocks/stubs (no system bus required).
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
import tempfile
import socket
from pathlib import Path
from typing import List, Optional

import pytest

from phonect.config import DaemonConfig, load_config, write_default_config
from phonect.crypto import generate_key_pair, fingerprint_from_public_key, public_key_to_pem, sign_nonce
from phonect.daemon import PhonectDaemon
from phonect.handshake import HandshakeClient
from phonect.protocol import encode_frame, make_pair_hello, make_response, validate_pair_accept


# ======================================================================
# Config tests
# ======================================================================

class TestConfig:
    def test_default_config_returns_minimal(self):
        """load_config() with no file returns defaults (no keys)."""
        cfg = load_config(Path("/nonexistent/config.toml"))
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
            assert cfg.pc_name == "my-laptop"
            assert cfg.listen_host == "0.0.0.0"
            assert cfg.listen_port == 9876
            assert cfg.poll_interval == 0.3
            assert cfg.poll_timeout == 15.0
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
pc_name = "my-pc"
unlock_on_start = true

[daemon]
listen_host = "127.0.0.1"
listen_port = 12345
poll_interval = 1.5
poll_timeout = 0.5
""")
            cfg = load_config(config_path)
            assert cfg.pc_name == "my-pc"
            assert cfg.unlock_on_start is True
            assert cfg.listen_host == "127.0.0.1"
            assert cfg.listen_port == 12345
            assert cfg.poll_interval == 1.5
            assert cfg.poll_timeout == 0.5
            assert cfg.has_pc_key is True
            assert cfg.has_trusted_key is True
            assert cfg.mutual_auth_ready is True

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


class TestDaemonTcpPairing:
    async def _phone(self, host, port, kp, device_name="phone"):
        reader, writer = await asyncio.open_connection(host, port)
        fp = fingerprint_from_public_key(kp.public_key)
        hello = make_pair_hello(public_key_to_pem(kp.public_key).decode(), fp, device_name)
        writer.write(encode_frame(hello)); await writer.drain()
        accept = validate_pair_accept(await PhonectDaemon._read_frame(reader))
        challenge = await PhonectDaemon._read_frame(reader)
        signature = sign_nonce(kp.private_key, bytes.fromhex(challenge["nonce"]))
        writer.write(encode_frame(make_response(challenge["session_id"], signature, fp, device_name)))
        await writer.drain()
        writer.close(); await writer.wait_closed()
        return accept

    @pytest.mark.asyncio
    async def test_full_tcp_pairing_then_unlock_only_on_pinned_key(self, monkeypatch):
        mobile_kp = generate_key_pair(); pc_kp = generate_key_pair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = Path(tmp) / "trusted_device.pub"
            priv = Path(tmp) / "pc_private.pem"; priv.write_bytes(pc_kp.private_key_pem)
            cfg = DaemonConfig(private_key_path=priv, public_key_path=trusted, listen_host="127.0.0.1", listen_port=0)
            daemon = PhonectDaemon(cfg)
            daemon._auth_pending = True
            unlocks = []
            monkeypatch.setattr(daemon, "_get_active_session_ids", lambda: ["2"])
            daemon._unlock_hook = lambda cmd: unlocks.append(cmd)
            server = await asyncio.start_server(daemon._handle_client, "127.0.0.1", 0)
            host, port = server.sockets[0].getsockname()
            try:
                await self._phone(host, port, mobile_kp)
                await daemon._auth_completed.wait()
                assert trusted.read_bytes() == mobile_kp.public_key_pem
                assert unlocks == []
                daemon._auth_pending = True
                await self._phone(host, port, mobile_kp)
                await daemon._auth_completed.wait()
                assert len(unlocks) == 1
            finally:
                server.close(); await server.wait_closed()

    @pytest.mark.asyncio
    async def test_mismatched_pair_hello_rejected_without_overwrite(self):
        trusted_kp = generate_key_pair(); evil_kp = generate_key_pair(); pc_kp = generate_key_pair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = Path(tmp) / "trusted_device.pub"; trusted.write_bytes(trusted_kp.public_key_pem)
            original = trusted.read_bytes()
            priv = Path(tmp) / "pc_private.pem"; priv.write_bytes(pc_kp.private_key_pem)
            cfg = DaemonConfig(private_key_path=priv, public_key_path=trusted)
            daemon = PhonectDaemon(cfg)
            daemon._auth_pending = True
            async def handler(reader, writer):
                await daemon._handle_client(reader, writer)
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            host, port = server.sockets[0].getsockname()
            try:
                reader, writer = await asyncio.open_connection(host, port)
                fp = fingerprint_from_public_key(evil_kp.public_key)
                writer.write(encode_frame(make_pair_hello(public_key_to_pem(evil_kp.public_key).decode(), fp, "evil")))
                await writer.drain()
                with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError, TimeoutError)):
                    await PhonectDaemon._read_frame(reader, timeout=1)
                writer.close(); await writer.wait_closed()
                assert trusted.read_bytes() == original
            finally:
                server.close(); await server.wait_closed()

    @pytest.mark.asyncio
    async def test_tcp_connection_outside_auth_window_closed_without_unlock(self, monkeypatch):
        mobile_kp = generate_key_pair(); pc_kp = generate_key_pair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = Path(tmp) / "trusted_device.pub"; trusted.write_bytes(mobile_kp.public_key_pem)
            priv = Path(tmp) / "pc_private.pem"; priv.write_bytes(pc_kp.private_key_pem)
            cfg = DaemonConfig(private_key_path=priv, public_key_path=trusted)
            daemon = PhonectDaemon(cfg)
            unlocks = []
            daemon._unlock_hook = lambda cmd: unlocks.append(cmd)
            server = await asyncio.start_server(daemon._handle_client, "127.0.0.1", 0)
            host, port = server.sockets[0].getsockname()
            try:
                reader, writer = await asyncio.open_connection(host, port)
                fp = fingerprint_from_public_key(mobile_kp.public_key)
                writer.write(encode_frame(make_pair_hello(public_key_to_pem(mobile_kp.public_key).decode(), fp, "phone")))
                await writer.drain()
                with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError, TimeoutError)):
                    await PhonectDaemon._read_frame(reader, timeout=1)
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionResetError:
                    pass
                assert unlocks == []
            finally:
                server.close(); await server.wait_closed()

    @pytest.mark.asyncio
    async def test_first_tofu_fingerprint_mismatch_not_persisted(self):
        mobile_kp = generate_key_pair(); other_kp = generate_key_pair(); pc_kp = generate_key_pair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = Path(tmp) / "trusted_device.pub"
            priv = Path(tmp) / "pc_private.pem"; priv.write_bytes(pc_kp.private_key_pem)
            cfg = DaemonConfig(private_key_path=priv, public_key_path=trusted)
            daemon = PhonectDaemon(cfg)
            daemon._auth_pending = True
            server = await asyncio.start_server(daemon._handle_client, "127.0.0.1", 0)
            host, port = server.sockets[0].getsockname()
            try:
                reader, writer = await asyncio.open_connection(host, port)
                wrong_fp = fingerprint_from_public_key(other_kp.public_key)
                writer.write(encode_frame(make_pair_hello(public_key_to_pem(mobile_kp.public_key).decode(), wrong_fp, "phone")))
                await writer.drain()
                with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError, TimeoutError)):
                    await PhonectDaemon._read_frame(reader, timeout=1)
                writer.close(); await writer.wait_closed()
                assert not trusted.exists()
            finally:
                server.close(); await server.wait_closed()

    @pytest.mark.asyncio
    async def test_abandoned_first_tofu_not_persisted(self):
        mobile_kp = generate_key_pair(); pc_kp = generate_key_pair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = Path(tmp) / "trusted_device.pub"
            priv = Path(tmp) / "pc_private.pem"; priv.write_bytes(pc_kp.private_key_pem)
            cfg = DaemonConfig(private_key_path=priv, public_key_path=trusted)
            daemon = PhonectDaemon(cfg)
            daemon._auth_pending = True
            server = await asyncio.start_server(daemon._handle_client, "127.0.0.1", 0)
            host, port = server.sockets[0].getsockname()
            try:
                reader, writer = await asyncio.open_connection(host, port)
                fp = fingerprint_from_public_key(mobile_kp.public_key)
                writer.write(encode_frame(make_pair_hello(public_key_to_pem(mobile_kp.public_key).decode(), fp, "phone")))
                await writer.drain()
                await PhonectDaemon._read_frame(reader)
                await PhonectDaemon._read_frame(reader)
                writer.close(); await writer.wait_closed()
                await asyncio.wait_for(daemon._auth_completed.wait(), timeout=2)
                assert not trusted.exists()
            finally:
                server.close(); await server.wait_closed()

    @pytest.mark.asyncio
    async def test_listen_port_zero_records_actual_bound_port(self):
        pc_kp = generate_key_pair()
        with tempfile.TemporaryDirectory() as tmp:
            priv = Path(tmp) / "pc_private.pem"; priv.write_bytes(pc_kp.private_key_pem)
            cfg = DaemonConfig(private_key_path=priv, listen_host="127.0.0.1", listen_port=0, poll_timeout=0.05)
            daemon = PhonectDaemon(cfg)
            async def no_dbus():
                return None
            daemon._connect_dbus = no_dbus
            task = asyncio.create_task(daemon.run())
            try:
                for _ in range(50):
                    if daemon._actual_listen_port != 0:
                        break
                    await asyncio.sleep(0.01)
                assert daemon._actual_listen_port > 0
            finally:
                daemon.stop()
                await asyncio.wait_for(task, timeout=2)

    @pytest.mark.asyncio
    async def test_broadcast_discovery_window_survives_enetunreach(self, monkeypatch, caplog):
        cfg = DaemonConfig(poll_timeout=0.12, poll_interval=0.01)
        daemon = PhonectDaemon(cfg)
        daemon._auth_pending = True

        sends = []

        class FakeSocket:
            def setsockopt(self, *args, **kwargs):
                return None

            def sendto(self, payload, addr):
                sends.append((payload, addr))
                raise OSError(errno.ENETUNREACH, "Network is unreachable")

            def close(self):
                sends.append((b"closed", None))

        monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: FakeSocket())
        caplog.set_level(logging.WARNING, logger="phonect.daemon")

        await daemon._broadcast_discovery_window()

        assert "UDP discovery failed: Network is unreachable" in caplog.text
        assert any(item[0] == b"closed" for item in sends)
        assert len([item for item in sends if item[1] is not None]) >= 1

    @pytest.mark.asyncio
    async def test_auth_cycle_stays_alive_when_discovery_network_unreachable(self, monkeypatch):
        cfg = DaemonConfig(poll_timeout=0.12, poll_interval=0.01)
        daemon = PhonectDaemon(cfg)
        daemon._auth_completed.clear()

        class FakeSocket:
            def setsockopt(self, *args, **kwargs):
                return None

            def sendto(self, payload, addr):
                raise OSError(errno.ENETUNREACH, "Network is unreachable")

            def close(self):
                return None

        monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: FakeSocket())

        await daemon._run_auth_cycle()
        assert daemon._auth_pending is False
        assert daemon._auth_in_progress is False

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
