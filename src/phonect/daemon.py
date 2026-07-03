"""
phonect.daemon — Asyncio-based daemon for P2P biometric unlock via Bluetooth RFCOMM.

Architecture
============

The daemon connects to the Android phone via Bluetooth RFCOMM (PC = client).

On resume-from-sleep (``PrepareForSleep`` D-Bus signal), the daemon:

1. Opens a Bluetooth RFCOMM socket to the phone's MAC address.
2. Sends a ``pair_hello`` message with the PC's RSA public key.
3. Receives a ``pair_accept`` with the phone's public key (TOFU).
4. Sends a challenge (nonce) — with mutual-auth signature if PC key loaded.
5. Receives and verifies the phone's signed response.
6. On success: calls ``loginctl unlock-session``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import struct
import subprocess
from pathlib import Path
from typing import Callable, List, Optional

from phonect.config import DaemonConfig, load_config, BLUETOOTH_RFCOMM_CHANNEL
from phonect.crypto import (
    generate_nonce,
    load_public_key,
    load_private_key,
    verify_nonce,
    sign_nonce,
    fingerprint_from_public_key,
    public_key_to_pem,
    rsa,
)
from phonect.protocol import (
    MAX_FRAME_SIZE,
    encode_frame,
    make_challenge,
    make_pair_hello,
    make_pair_accept,
    validate_response,
    validate_pair_hello,
    validate_pair_accept,
    ProtocolError,
    ProtocolSecurityError,
    MSG_PAIR_HELLO,
    MSG_PAIR_ACCEPT,
)

LOG = logging.getLogger("phonect.daemon")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DBUS_LOGIN1_SERVICE = "org.freedesktop.login1"
DBUS_LOGIN1_OBJECT = "/org/freedesktop/login1"
DBUS_LOGIN1_MANAGER = "org.freedesktop.login1.Manager"
SIGNAL_PREPARE_FOR_SLEEP = "PrepareForSleep"

HANDSHAKE_TIMEOUT = 15.0  # seconds waiting for phone I/O
BT_CONNECT_TIMEOUT = 10.0  # seconds for BT socket connect


# ---------------------------------------------------------------------------
# Async Bluetooth transport
# ---------------------------------------------------------------------------


class BluetoothTransport:
    """
    Async wrapper around a Bluetooth RFCOMM socket.

    Provides frame-level read/write operations for the daemon's
    asyncio event loop.
    """

    def __init__(self, mac: str, channel: int = BLUETOOTH_RFCOMM_CHANNEL):
        self.mac = mac
        self.channel = channel
        self._sock: Optional[socket.socket] = None

    async def connect(self) -> BluetoothTransport:
        """
        Create and connect the RFCOMM socket (non-blocking).
        Raises ``OSError`` on failure (device off, unreachable, etc.).
        """
        self._sock = socket.socket(
            socket.AF_BLUETOOTH,
            socket.SOCK_STREAM,
            socket.BTPROTO_RFCOMM,
        )
        self._sock.setblocking(False)
        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(
                loop.sock_connect(self._sock, (self.mac, self.channel)),
                timeout=BT_CONNECT_TIMEOUT,
            )
        except (OSError, asyncio.TimeoutError):
            self._sock.close()
            self._sock = None
            raise
        LOG.info("Bluetooth RFCOMM connected to %s (ch %d)", self.mac, self.channel)
        return self

    async def _readexactly(self, n: int) -> bytes:
        """Read exactly *n* bytes from the socket."""
        if self._sock is None:
            raise ConnectionError("Bluetooth socket not connected")
        loop = asyncio.get_running_loop()
        buf = bytearray()
        while len(buf) < n:
            chunk = await loop.sock_recv(self._sock, n - len(buf))
            if not chunk:
                raise ConnectionError("Bluetooth connection closed by peer")
            buf.extend(chunk)
        return bytes(buf)

    async def read_frame(self, timeout: float = HANDSHAKE_TIMEOUT) -> Optional[dict]:
        """
        Read one length-prefixed JSON frame from the Bluetooth socket.

        Returns ``None`` on timeout or connection close.
        Raises ``ProtocolSecurityError`` on invalid frame size.
        """
        try:
            header = await asyncio.wait_for(
                self._readexactly(4), timeout=timeout,
            )
        except asyncio.TimeoutError:
            LOG.warning("Bluetooth read timed out (%.1fs)", timeout)
            return None
        except ConnectionError:
            return None

        payload_len = struct.unpack("!I", header)[0]

        if payload_len <= 0 or payload_len > MAX_FRAME_SIZE:
            raise ProtocolSecurityError(
                f"Declared payload length {payload_len} exceeds maximum {MAX_FRAME_SIZE}"
            )

        try:
            payload = await asyncio.wait_for(
                self._readexactly(payload_len), timeout=timeout,
            )
        except asyncio.TimeoutError:
            LOG.warning("Bluetooth payload read timed out")
            return None
        except ConnectionError:
            return None

        try:
            return json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ProtocolSecurityError(f"Invalid JSON payload: {exc}") from exc

    async def write_frame(self, msg: dict) -> None:
        """Encode and send a JSON frame over Bluetooth."""
        if self._sock is None:
            raise ConnectionError("Bluetooth socket not connected")
        data = encode_frame(msg)
        loop = asyncio.get_running_loop()
        await loop.sock_sendall(self._sock, data)

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            LOG.debug("Bluetooth socket closed")


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------


class PhonectDaemon:
    """
    Async daemon for P2P biometric unlock (Bluetooth RFCOMM).

    Usage::

        config = load_config()
        daemon = PhonectDaemon(config)
        asyncio.run(daemon.run())
    """

    def __init__(self, config: DaemonConfig) -> None:
        self.config = config
        self._running = False
        self._wakeup_event = asyncio.Event()

        # Auth-flow coordination
        self._auth_completed = asyncio.Event()
        self._last_auth_ok = False
        self._auth_in_progress = False

        # D-Bus proxy – set during _connect_dbus()
        self._bus = None
        self._login1_proxy = None
        self._login1_manager = None

        # Override hook for tests (capture unlock commands)
        self._unlock_hook: Optional[Callable[[List[str]], None]] = None

        # ── Load PC key pair ─────────────────────────────────────────
        self._pc_private_key: Optional[rsa.RSAPrivateKey] = None
        pk_path = config.private_key_path
        if pk_path and pk_path.is_file():
            try:
                self._pc_private_key = load_private_key(config.pc_private_key_pem)
                LOG.info("PC private key loaded from %s", pk_path)
            except Exception as exc:
                LOG.error("Failed to load PC private key: %s", exc)
        else:
            LOG.warning(
                "No PC private key at %s — handshake will fail. "
                "Run 'phonect gen-keys' first.", pk_path,
            )

        # ── Load trusted (phone) public key (optional — populated by TOFU) ──
        self._trusted_key: Optional[rsa.RSAPublicKey] = None
        if config.has_trusted_key:
            try:
                self._trusted_key = load_public_key(config.trusted_key_pem)
                LOG.info("Trusted phone key loaded from %s", config.public_key_path)
            except Exception as exc:
                LOG.error("Failed to load trusted phone key: %s", exc)

        # ── Bluetooth config status ──────────────────────────────────
        bt_ok = bool(config.bluetooth_mac)
        if bt_ok:
            LOG.info(
                "PhonectDaemon initialised (BT %s, %s)",
                config.bluetooth_mac,
                "mutual auth ready" if config.mutual_auth_ready
                else "awaiting phone pairing" if config.has_pc_key
                else "no PC key",
            )
        else:
            LOG.warning(
                "No bluetooth_mac configured — set [device]bluetooth_mac in config"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Main entry point.  Connect D-Bus, enter event loop."""
        LOG.info("Starting phonect daemon ...")
        self._running = True

        # 1. Connect D-Bus (system bus)
        try:
            await self._connect_dbus()
        except Exception as exc:
            LOG.warning("D-Bus connection failed: %s (polling-only mode)", exc)

        # 2. Optional initial unlock cycle
        if (
            self.config.unlock_on_start
            and self.config.has_pc_key
            and self.config.bluetooth_mac
        ):
            LOG.info("Performing initial unlock-on-start ...")
            asyncio.create_task(self._on_wakeup())

        LOG.info("Daemon ready.  Waiting for resume-from-sleep events ...")

        try:
            while self._running:
                await self._wakeup_event.wait()
                self._wakeup_event.clear()

                if not self._running:
                    break

                if not self.config.has_pc_key:
                    LOG.warning("Cannot run auth — no PC private key")
                    continue

                if not self.config.bluetooth_mac:
                    LOG.warning("Cannot run auth — no bluetooth_mac configured")
                    continue

                if not self._auth_in_progress:
                    asyncio.create_task(self._on_wakeup())

        except asyncio.CancelledError:
            pass
        finally:
            await self._cleanup()

    def stop(self) -> None:
        """Gracefully stop the daemon (called from signal handler)."""
        LOG.info("Shutdown requested")
        self._running = False
        self._wakeup_event.set()

    def trigger_wakeup(self) -> None:
        """Manually trigger a wakeup/auth cycle (for testing / SIGUSR1)."""
        LOG.info("Manual wakeup trigger")
        self._wakeup_event.set()

    # ------------------------------------------------------------------
    # D-Bus integration
    # ------------------------------------------------------------------

    async def _connect_dbus(self) -> None:
        """Connect to the system D-Bus, subscribe to ``PrepareForSleep``."""
        from dbus_next.aio import MessageBus
        from dbus_next import BusType
        from dbus_next.introspection import Node

        self._bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        LOG.debug("Connected to system D-Bus")

        introspection: Node = await self._bus.introspect(
            DBUS_LOGIN1_SERVICE, DBUS_LOGIN1_OBJECT,
        )
        self._login1_proxy = self._bus.get_proxy_object(
            DBUS_LOGIN1_SERVICE, DBUS_LOGIN1_OBJECT, introspection,
        )
        self._login1_manager = self._login1_proxy.get_interface(
            DBUS_LOGIN1_MANAGER,
        )

        self._login1_manager.on_prepare_for_sleep(self._on_prepare_for_sleep)
        LOG.info("Subscribed to %s.%s", DBUS_LOGIN1_MANAGER, SIGNAL_PREPARE_FOR_SLEEP)

    async def _cleanup(self) -> None:
        """Clean up D-Bus connection."""
        if self._bus is not None:
            self._bus.disconnect()
            self._bus = None
            LOG.debug("D-Bus disconnected")

    # ------------------------------------------------------------------
    # Signal handlers
    # ------------------------------------------------------------------

    def _on_prepare_for_sleep(self, sleeping: bool) -> None:
        """
        D-Bus signal callback for ``PrepareForSleep``.

        * ``sleeping=True``  → system is about to suspend
        * ``sleeping=False`` → system has resumed
        """
        if sleeping:
            LOG.info("System going to sleep (PrepareForSleep=true)")
        else:
            LOG.info("System resumed from sleep (PrepareForSleep=false)")
            self._wakeup_event.set()

    # ------------------------------------------------------------------
    # Wakeup / auth flow
    # ------------------------------------------------------------------

    async def _on_wakeup(self) -> None:
        """Handle wakeup: connect via BT, run handshake, unlock if OK."""
        if self._auth_in_progress:
            LOG.debug("Auth already in progress, skipping")
            return
        self._auth_in_progress = True
        self._auth_completed.clear()
        self._last_auth_ok = False

        try:
            ok = await self._bt_handshake()

            if ok:
                LOG.info("✓ Authentication successful — unlocking session(s)")
                self._unlock_sessions()
            else:
                LOG.warning("✗ Authentication failed or no phone connected")
        finally:
            self._last_auth_ok = ok
            self._auth_completed.set()
            self._auth_in_progress = False

    # ------------------------------------------------------------------
    # Bluetooth handshake (PC → Phone)
    # ------------------------------------------------------------------

    async def _bt_handshake(self) -> bool:
        """
        Full Bluetooth handshake as PC initiator.

        Steps:
        1. Connect to phone via RFCOMM.
        2. Send ``pair_hello`` with PC's public key.
        3. Receive ``pair_accept`` with phone's public key (TOFU).
        4. Send challenge with mutual-auth signature.
        5. Receive and verify signed response.
        """
        transport: Optional[BluetoothTransport] = None
        try:
            # 1. Connect
            transport = BluetoothTransport(self.config.bluetooth_mac)
            try:
                await transport.connect()
            except (OSError, asyncio.TimeoutError) as exc:
                LOG.warning("Bluetooth connect failed: %s", exc)
                return False

            # 2. Send pair_hello
            if self._pc_private_key is None:
                LOG.error("No PC private key — cannot authenticate")
                return False

            pc_pem = public_key_to_pem(
                self._pc_private_key.public_key()
            ).decode()
            pc_fp = fingerprint_from_public_key(self._pc_private_key.public_key())
            hello = make_pair_hello(
                public_key_pem=pc_pem,
                public_key_fingerprint=pc_fp,
                device_name=self.config.pc_name or socket.gethostname(),
            )
            await transport.write_frame(hello)
            LOG.debug("PairHello sent (fp=%s)", pc_fp[:16])

            # 3. Receive pair_accept
            msg = await transport.read_frame(timeout=HANDSHAKE_TIMEOUT)
            if msg is None:
                LOG.warning("No response from phone — connection closed or timeout")
                return False

            try:
                accept = validate_pair_accept(msg)
            except ProtocolError as exc:
                LOG.warning("Invalid pair_accept: %s", exc)
                return False

            phone_pem = accept["public_key_pem"]
            phone_fp = accept["public_key_fingerprint"]
            device_name = accept.get("device_name", "phone")

            # TOFU: save phone key if new
            is_new = False
            if not self._is_known_key(phone_fp):
                self._save_phone_key(phone_pem)
                try:
                    self._trusted_key = load_public_key(
                        self.config.trusted_key_pem
                    )
                    LOG.info(
                        "TOFU: paired with %s (%s …)",
                        device_name, phone_fp[:16],
                    )
                    is_new = True
                except Exception as exc:
                    LOG.error("TOFU: failed to reload phone key: %s", exc)
                    return False
            else:
                LOG.debug("Phone already known: %s …", phone_fp[:16])

            if self._trusted_key is None:
                LOG.error("No trusted phone key — cannot verify response")
                return False

            # 4. Send challenge
            nonce = generate_nonce()
            pc_fp_mutual: Optional[str] = None
            pc_sig: Optional[bytes] = None
            if self._pc_private_key is not None:
                pc_fp_mutual = fingerprint_from_public_key(
                    self._pc_private_key.public_key()
                )
                pc_sig = sign_nonce(self._pc_private_key, nonce)
                LOG.debug("Mutual-auth: challenge signed by PC key %s", pc_fp_mutual[:16])

            challenge = make_challenge(
                nonce,
                pc_key_fingerprint=pc_fp_mutual,
                pc_signature=pc_sig,
            )
            await transport.write_frame(challenge)
            LOG.debug("Sent challenge (session=%s)", challenge["session_id"])

            # 5. Receive response
            try:
                msg = await transport.read_frame(timeout=HANDSHAKE_TIMEOUT)
            except ProtocolSecurityError as exc:
                LOG.error("Security violation in response frame: %s", exc)
                return False

            if msg is None:
                LOG.warning("Empty response / connection closed")
                return False

            try:
                validated = validate_response(msg)
            except ProtocolError as exc:
                LOG.error("Invalid response schema: %s", exc)
                return False

            # 6. Verify signature (CPU-bound — run in executor)
            signature = bytes.fromhex(validated["signature"])
            loop = asyncio.get_running_loop()
            valid = await loop.run_in_executor(
                None, verify_nonce, self._trusted_key, nonce, signature,
            )

            if valid:
                LOG.info(
                    "✓ Handshake SUCCESS — device=%s fp=%s%s",
                    validated.get("device_name", "?"),
                    validated.get("public_key_fingerprint", "")[:16],
                    " (newly paired)" if is_new else "",
                )
            else:
                LOG.warning(
                    "✗ Handshake FAILED — device=%s fp=%s",
                    validated.get("device_name", "?"),
                    validated.get("public_key_fingerprint", "")[:16],
                )

            return valid

        except (ConnectionError, OSError) as exc:
            LOG.warning("Bluetooth connection error: %s", exc)
            return False
        except ProtocolSecurityError as exc:
            LOG.error("Security violation: %s", exc)
            return False
        except Exception as exc:
            LOG.exception("Unexpected error during BT handshake: %s", exc)
            return False
        finally:
            if transport is not None:
                transport.close()

    # ------------------------------------------------------------------
    # TOFU helpers
    # ------------------------------------------------------------------

    def _save_phone_key(self, pem: str) -> None:
        """Persist the phone's public key PEM to ``config.public_key_path``."""
        path = self.config.public_key_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(pem)
        LOG.info("Phone public key saved to %s", path)

    def _is_known_key(self, fingerprint: str) -> bool:
        """Check whether *fingerprint* matches the currently trusted key."""
        if self._trusted_key is None:
            return False
        our_fp = fingerprint_from_public_key(self._trusted_key)
        return our_fp == fingerprint

    # ------------------------------------------------------------------
    # Legacy async handshake (used by tests via reader/writer)
    # ------------------------------------------------------------------

    async def _async_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> bool:
        """
        Perform the challenge-response handshake over an established TCP
        connection.  Used by **tests only** — the BT handshake uses
        ``_bt_handshake()`` instead.

        Returns ``True`` if the phone's response signature is valid.
        """
        if self._trusted_key is None:
            LOG.error("No trusted phone key loaded — cannot verify")
            return False

        nonce = generate_nonce()

        pc_fp: Optional[str] = None
        pc_sig: Optional[bytes] = None
        if self._pc_private_key is not None:
            pc_fp = fingerprint_from_public_key(
                self._pc_private_key.public_key()
            )
            pc_sig = sign_nonce(self._pc_private_key, nonce)
            LOG.debug("Mutual-auth: challenge signed by PC key %s", pc_fp[:16])

        challenge = make_challenge(
            nonce,
            pc_key_fingerprint=pc_fp,
            pc_signature=pc_sig,
        )
        writer.write(encode_frame(challenge))
        await writer.drain()
        LOG.debug("Sent challenge (session=%s)", challenge["session_id"])

        try:
            msg = await self._read_frame(reader, timeout=HANDSHAKE_TIMEOUT)
        except (asyncio.TimeoutError, ConnectionError) as exc:
            LOG.warning("Failed to read response: %s", exc)
            return False
        except ProtocolSecurityError as exc:
            LOG.error("Security violation in response frame: %s", exc)
            return False

        if msg is None:
            LOG.warning("Empty response / connection closed")
            return False

        try:
            validated = validate_response(msg)
        except ProtocolError as exc:
            LOG.error("Invalid response schema: %s", exc)
            return False

        signature = bytes.fromhex(validated["signature"])
        loop = asyncio.get_running_loop()
        valid = await loop.run_in_executor(
            None, verify_nonce, self._trusted_key, nonce, signature,
        )

        if valid:
            LOG.info(
                "✓ Signature valid — device=%s fp=%s",
                validated.get("device_name", "?"),
                validated.get("public_key_fingerprint", "")[:16],
            )
        else:
            LOG.warning(
                "✗ Signature mismatch — device=%s",
                validated.get("device_name", "?"),
            )

        return valid

    @staticmethod
    async def _read_frame(
        reader: asyncio.StreamReader,
        timeout: float = 10.0,
    ) -> Optional[dict]:
        """
        Read one length-prefixed JSON frame from a stream (test helper).

        Security
        --------
        * Rejects frames whose declared payload exceeds ``MAX_FRAME_SIZE`` (64 KB).
        """
        header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        payload_len = struct.unpack("!I", header)[0]

        if payload_len <= 0 or payload_len > MAX_FRAME_SIZE:
            raise ProtocolSecurityError(
                f"Declared payload length {payload_len} exceeds maximum {MAX_FRAME_SIZE}"
            )

        payload = await asyncio.wait_for(
            reader.readexactly(payload_len), timeout=timeout,
        )
        return json.loads(payload.decode("utf-8"))

    # ------------------------------------------------------------------
    # Session unlock
    # ------------------------------------------------------------------

    def _unlock_sessions(self) -> None:
        """Unlock all active sessions for the current user."""
        session_ids = self._get_active_session_ids()
        if not session_ids:
            LOG.warning("No active session found for user %s", os.environ.get("USER", "?"))
            return

        for sid in session_ids:
            cmd = ["loginctl", "unlock-session", sid]
            LOG.info("Running: %s", " ".join(cmd))

            if self._unlock_hook:
                self._unlock_hook(cmd)
                continue

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    LOG.info("Session %s unlocked", sid)
                else:
                    LOG.warning(
                        "loginctl unlock-session %s failed: %s",
                        sid, result.stderr.strip(),
                    )
            except subprocess.TimeoutExpired:
                LOG.error("loginctl timed out for session %s", sid)
            except FileNotFoundError:
                LOG.error("loginctl not found — is systemd installed?")

    def _get_active_session_ids(self) -> List[str]:
        """Get active session IDs for the current user on seat0."""
        try:
            result = subprocess.run(
                ["loginctl", "--no-legend", "list-sessions"],
                capture_output=True, text=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        current_user = os.environ.get("USER", "")
        sessions: List[str] = []

        for line in result.stdout.strip().splitlines():
            parts = line.strip().split()
            if len(parts) >= 5:
                sid, _, user, seat = parts[0], parts[1], parts[2], parts[3]
                if user == current_user and seat == "seat0":
                    sessions.append(sid)

        return sessions


# ---------------------------------------------------------------------------
# CLI entry-point helper
# ---------------------------------------------------------------------------


async def run_daemon(
    config_path: Optional[Path] = None,
    foreground: bool = False,
) -> None:
    """
    Load config and start the daemon.

    If *foreground* is ``True``, log to stderr instead of syslog.
    """
    config = load_config(config_path)
    _configure_logging(config.log_level)

    if not config.has_pc_key:
        LOG.warning(
            "No PC private key configured. "
            "Run 'phonect gen-keys' then update config [keys]private_key."
        )
    if not config.bluetooth_mac:
        LOG.warning(
            "No bluetooth_mac configured. "
            "Set [device]bluetooth_mac in config (e.g., \"AA:BB:CC:DD:EE:FF\")."
        )

    daemon = PhonectDaemon(config)

    # Handle SIGTERM/SIGINT for graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in ("SIGTERM", "SIGINT"):
        try:
            loop.add_signal_handler(
                getattr(__import__("signal"), sig),
                daemon.stop,
            )
        except (ValueError, AttributeError, NotImplementedError):
            pass

    # Handle SIGUSR1 for manual wakeup trigger
    try:
        loop.add_signal_handler(
            getattr(__import__("signal"), "SIGUSR1"),
            daemon.trigger_wakeup,
        )
    except (ValueError, AttributeError, NotImplementedError):
        pass

    await daemon.run()


def _configure_logging(level: str) -> None:
    """Configure the logging handler."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
