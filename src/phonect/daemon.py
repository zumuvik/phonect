"""
phonect.daemon — Asyncio-based daemon for P2P biometric unlock via UDP discovery + TOFU.

Architecture
============

Instead of connecting to a static phone IP, the daemon:

1. Listens on a TCP port (default 9876) for incoming phone connections.
2. On resume-from-sleep (``PrepareForSleep`` D-Bus signal), sends UDP
   discovery broadcasts on port 9875.
3. A phone that hears the broadcast connects to the daemon over TCP.
4. **Trust On First Use (TOFU)**: if the phone is unknown, both sides
   exchange RSA public keys automatically — no manual config needed.
5. After TOFU (or immediately for a known phone) the standard
   challenge-response handshake runs; on success the daemon calls
   ``loginctl unlock-session``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Callable, List, Optional

from phonect.config import DaemonConfig, load_config, UDP_DISCOVERY_PORT
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
    make_pair_accept,
    validate_response,
    validate_pair_hello,
    ProtocolError,
    ProtocolSecurityError,
    MSG_PAIR_HELLO,
)

LOG = logging.getLogger("phonect.daemon")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DBUS_LOGIN1_SERVICE = "org.freedesktop.login1"
DBUS_LOGIN1_OBJECT = "/org/freedesktop/login1"
DBUS_LOGIN1_MANAGER = "org.freedesktop.login1.Manager"
SIGNAL_PREPARE_FOR_SLEEP = "PrepareForSleep"

HANDSHAKE_TIMEOUT = 10.0  # seconds waiting for phone I/O
DISCOVERY_MSG_PREFIX = "PHONECT_DISCOVERY:"


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------


class PhonectDaemon:
    """
    Async daemon for P2P biometric laptop unlock (UDP discovery + TOFU).

    Usage::

        config = load_config()
        daemon = PhonectDaemon(config)
        asyncio.run(daemon.run())
    """

    def __init__(self, config: DaemonConfig) -> None:
        self.config = config
        self._running = False
        self._wakeup_event = asyncio.Event()

        # TCP server reference (set during run())
        self._tcp_server: Optional[asyncio.AbstractServer] = None

        # Auth-flow coordination: _handle_connection signals this
        # event so that _on_wakeup knows when to proceed.
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

        LOG.info(
            "PhonectDaemon initialised (listen=%s:%d, %s)",
            config.listen_host, config.listen_port,
            "mutual auth ready" if config.mutual_auth_ready
            else "awaiting phone pairing" if config.has_pc_key
            else "no PC key",
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Main entry point.  Start TCP server, connect D-Bus, enter loop."""
        LOG.info("Starting phonect daemon ...")
        self._running = True

        # 1. Start TCP listener for phone connections
        try:
            self._tcp_server = await asyncio.start_server(
                self._handle_connection,
                host=self.config.listen_host,
                port=self.config.listen_port,
            )
            addr = self._tcp_server.sockets[0].getsockname()
            LOG.info("TCP listener on %s:%d", addr[0], addr[1])
        except OSError as exc:
            LOG.critical("Cannot start TCP listener: %s", exc)
            return

        # 2. Connect D-Bus (system bus)
        try:
            await self._connect_dbus()
        except Exception as exc:
            LOG.warning("D-Bus connection failed: %s (polling-only mode)", exc)

        # 3. Optional initial unlock cycle
        if self.config.unlock_on_start and self.config.has_pc_key:
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
        """Stop TCP server and disconnect D-Bus."""
        if self._tcp_server is not None:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            LOG.debug("TCP server stopped")
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
        """Handle wakeup: broadcast discovery, wait for phone auth."""
        if self._auth_in_progress:
            LOG.debug("Auth already in progress, skipping")
            return
        self._auth_in_progress = True
        self._auth_completed.clear()
        self._last_auth_ok = False

        try:
            # Start UDP discovery broadcasts in the background
            broadcast_task = asyncio.create_task(self._send_discovery_broadcasts())

            # Wait for a phone to connect and complete auth
            try:
                await asyncio.wait_for(
                    self._auth_completed.wait(),
                    timeout=self.config.poll_timeout + 5.0,
                )
            except asyncio.TimeoutError:
                LOG.warning("No phone responded during discovery window")
            finally:
                broadcast_task.cancel()
                try:
                    await broadcast_task
                except asyncio.CancelledError:
                    pass

            if self._last_auth_ok:
                LOG.info("✓ Authentication successful — unlocking session(s)")
                self._unlock_sessions()
            else:
                LOG.warning("✗ Authentication failed or no phone connected")
        finally:
            self._auth_in_progress = False

    async def _send_discovery_broadcasts(self) -> None:
        """
        Send UDP broadcast packets on port 9875 during the polling window.

        Packet format: ``PHONECT_DISCOVERY:<pc_name>:<pc_fingerprint_prefix>``

        The phone extracts the PC's IP from the UDP source address and
        connects to our TCP listener.
        """
        if self._pc_private_key is None:
            return

        pc_name = self.config.pc_name or socket.gethostname()
        fp = fingerprint_from_public_key(self._pc_private_key.public_key())
        payload = f"{DISCOVERY_MSG_PREFIX}{pc_name}:{fp[:16]}"
        data = payload.encode()

        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setblocking(False)

        deadline = time.monotonic() + self.config.poll_timeout
        count = 0
        try:
            while time.monotonic() < deadline and self._running:
                try:
                    await loop.sock_sendto(
                        sock, data, ("255.255.255.255", UDP_DISCOVERY_PORT),
                    )
                    count += 1
                except OSError:
                    pass  # network not ready yet
                await asyncio.sleep(self.config.poll_interval)
        finally:
            sock.close()
            LOG.debug("Discovery: sent %d broadcasts in %.1fs", count, self.config.poll_timeout)

    # ------------------------------------------------------------------
    # TCP connection handler
    # ------------------------------------------------------------------

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Handle an incoming phone TCP connection.

        1. Read the first frame — expects ``pair_hello`` with phone's PEM key.
        2. TOFU: save phone key if unknown, send ``pair_accept`` with PC key.
        3. Challenge-response handshake.
        4. Signal the wakeup handler with the result.
        """
        peer = writer.get_extra_info("peername", ("?", 0))
        LOG.info("Phone connected from %s:%d", peer[0], peer[1])

        try:
            # 1. Read first frame
            msg = await self._read_frame(reader, timeout=HANDSHAKE_TIMEOUT)
            if msg is None:
                LOG.warning("Empty frame from phone — closing")
                return

            msg_type = msg.get("type")
            LOG.debug("Received message type: %s", msg_type)

            # Only pair_hello is expected as the first message
            if msg_type != MSG_PAIR_HELLO:
                LOG.warning("Unexpected first message type: %s", msg_type)
                return

            # 2. Validate pair_hello
            try:
                hello = validate_pair_hello(msg)
            except ProtocolError as exc:
                LOG.warning("Invalid pair_hello: %s", exc)
                return

            phone_pem = hello["public_key_pem"]
            phone_fp = hello["public_key_fingerprint"]
            device_name = hello.get("device_name", "phone")

            # 3. TOFU: save phone key if new
            is_new = False
            if not self._is_known_key(phone_fp):
                self._save_phone_key(phone_pem)
                # Reload trusted key so _async_handshake can use it
                try:
                    self._trusted_key = load_public_key(self.config.trusted_key_pem)
                    LOG.info(
                        "TOFU: paired with %s (%s …)",
                        device_name, phone_fp[:16],
                    )
                    is_new = True
                except Exception as exc:
                    LOG.error("TOFU: failed to reload phone key: %s", exc)
                    return
            else:
                LOG.debug("Phone already known: %s …", phone_fp[:16])

            # 4. Send pair_accept with PC's public key
            if self._pc_private_key is not None:
                pc_pem = public_key_to_pem(self._pc_private_key.public_key()).decode()
                pc_fp = fingerprint_from_public_key(self._pc_private_key.public_key())
                accept = make_pair_accept(hello["session_id"], pc_pem, pc_fp)
                writer.write(encode_frame(accept))
                await writer.drain()
            else:
                LOG.warning("No PC private key — cannot send pair_accept")
                return

            # 5. Challenge-response
            ok = await self._async_handshake(reader, writer)
            self._last_auth_ok = ok

            if ok:
                LOG.info(
                    "✓ Handshake SUCCESS — device=%s fp=%s%s",
                    device_name, phone_fp[:16],
                    " (newly paired)" if is_new else "",
                )
            else:
                LOG.warning(
                    "✗ Handshake FAILED — device=%s fp=%s",
                    device_name, phone_fp[:16],
                )

        except (asyncio.TimeoutError, ConnectionError) as exc:
            LOG.warning("Connection error with %s: %s", peer[0], exc)
            self._last_auth_ok = False
        except ProtocolSecurityError as exc:
            LOG.error("Security violation from %s: %s", peer[0], exc)
            self._last_auth_ok = False
        except Exception as exc:
            LOG.exception("Unexpected error handling %s: %s", peer[0], exc)
            self._last_auth_ok = False
        finally:
            self._auth_completed.set()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

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
    # Challenge-response handshake
    # ------------------------------------------------------------------

    async def _async_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> bool:
        """
        Perform the challenge-response handshake over an established TCP
        connection (async version of ``HandshakeServer.accept_and_verify``).

        Returns ``True`` if the phone's response signature is valid.
        """
        if self._trusted_key is None:
            LOG.error("No trusted phone key loaded — cannot verify")
            return False

        # 1. Send challenge (with mutual-auth fields if PC private key loaded)
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

        # 2. Read response (length-prefixed frame)
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

        # 3. Validate message structure
        try:
            validated = validate_response(msg)
        except ProtocolError as exc:
            LOG.error("Invalid response schema: %s", exc)
            return False

        # 4. Verify signature (CPU-bound — run in executor)
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
        Read one length-prefixed JSON frame from the stream.

        Security
        --------
        * Rejects frames whose declared payload exceeds ``MAX_FRAME_SIZE`` (64 KB)
          to prevent memory exhaustion (DoS/OOM).  The caller must close the
          connection after catching ``ProtocolSecurityError``.
        """
        import struct
        import json

        # Read 4-byte header
        header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        payload_len = struct.unpack("!I", header)[0]

        # ── Security: enforce max frame size before allocating ──────────
        if payload_len <= 0 or payload_len > MAX_FRAME_SIZE:
            raise ProtocolSecurityError(
                f"Declared payload length {payload_len} exceeds maximum {MAX_FRAME_SIZE}"
            )

        # Read payload
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
