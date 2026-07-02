"""
phonect.daemon — Asyncio-based system daemon for P2P biometric unlock.

Integrates with ``systemd-logind`` via D-Bus (``PrepareForSleep`` signal).
On resume-from-sleep the daemon aggressively polls the mobile device over TCP,
runs the challenge-response handshake, and calls ``loginctl unlock-session``
on success.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Callable, List, Optional, Set

from phonect.config import DaemonConfig, load_config
from phonect.crypto import (
    generate_nonce,
    load_public_key,
    load_private_key,
    verify_nonce,
    sign_nonce,
    fingerprint_from_public_key,
    rsa,
)
from phonect.protocol import (
    MAX_FRAME_SIZE,
    encode_frame,
    decode_frame,
    make_challenge,
    make_response,
    validate_response,
    ProtocolError,
    ProtocolSecurityError,
)

LOG = logging.getLogger("phonect.daemon")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DBUS_LOGIN1_SERVICE = "org.freedesktop.login1"
DBUS_LOGIN1_OBJECT = "/org/freedesktop/login1"
DBUS_LOGIN1_MANAGER = "org.freedesktop.login1.Manager"
SIGNAL_PREPARE_FOR_SLEEP = "PrepareForSleep"

HANDSHAKE_TIMEOUT = 10.0  # seconds waiting for mobile response
UNLOCK_SESSION_MAX_ATTEMPTS = 3


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------

class PhonectDaemon:
    """
    Async daemon for P2P biometric laptop unlock.

    Usage::

        config = load_config()
        daemon = PhonectDaemon(config)
        asyncio.run(daemon.run())
    """

    def __init__(self, config: DaemonConfig) -> None:
        self.config = config
        self._running = False
        self._wakeup_event = asyncio.Event()
        self._auth_in_progress = False

        # D-Bus proxy – set during _connect_dbus()
        self._bus = None
        self._login1_proxy = None
        self._login1_manager = None

        # Override hook for tests (capture unlock commands)
        self._unlock_hook: Optional[Callable[[List[str]], None]] = None

        # Load the trusted (mobile) public key
        self._trusted_key: Optional[rsa.RSAPublicKey] = None
        if config.valid:
            try:
                self._trusted_key = load_public_key(config.trusted_key_pem)
            except Exception as exc:
                LOG.error("Failed to load trusted public key: %s", exc)
        else:
            LOG.warning("Daemon config is incomplete — auth will not be possible")

        # Load the PC private key for mutual authentication
        self._pc_private_key: Optional[rsa.RSAPrivateKey] = None
        pk_path = config.private_key_path
        if pk_path and pk_path.is_file():
            try:
                self._pc_private_key = load_private_key(config.pc_private_key_pem)
                LOG.info("PC private key loaded for mutual auth")
            except Exception as exc:
                LOG.error("Failed to load PC private key: %s", exc)
        else:
            LOG.info("No PC private key — mutual auth disabled (pair via TUI first)")

        LOG.info(
            "PhonectDaemon initialised (mobile=%s:%d, poll=%.1fs/%.1fs, mutual=%s)",
            config.mobile_ip, config.mobile_port,
            config.poll_interval, config.poll_timeout,
            self._pc_private_key is not None,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Main entry point.  Connect D-Bus and enter the event loop."""
        LOG.info("Starting phonect daemon ...")
        self._running = True

        # Connect D-Bus (system bus)
        try:
            await self._connect_dbus()
        except Exception as exc:
            LOG.critical("D-Bus connection failed: %s", exc)
            LOG.critical("Falling back to polling-only mode (no sleep detection)")
            # We can still operate in polling-only mode with a wakeup trigger

        # Optional initial unlock cycle
        if self.config.unlock_on_start and self.config.valid:
            LOG.info("Performing initial unlock-on-start ...")
            asyncio.create_task(self._on_wakeup())

        LOG.info("Daemon ready.  Waiting for resume-from-sleep events ...")

        try:
            # Main loop: wait for wakeup events
            while self._running:
                await self._wakeup_event.wait()
                self._wakeup_event.clear()

                if not self._running:
                    break

                if not self.config.valid:
                    LOG.warning("Cannot run auth — config incomplete")
                    continue

                # Start auth flow in background (don't block the signal handler)
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
        self._wakeup_event.set()  # unblock the main loop

    def trigger_wakeup(self) -> None:
        """Manually trigger a wakeup/auth cycle (for testing / SIGUSR1)."""
        LOG.info("Manual wakeup trigger")
        self._wakeup_event.set()

    # ------------------------------------------------------------------
    # D-Bus integration
    # ------------------------------------------------------------------

    async def _connect_dbus(self) -> None:
        """Connect to the system D-Bus, introspect logind, subscribe to
        ``PrepareForSleep``."""
        from dbus_next.aio import MessageBus
        from dbus_next import BusType
        from dbus_next.introspection import Node

        self._bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        LOG.debug("Connected to system D-Bus")

        # Introspect logind to get the full interface definition
        introspection: Node = await self._bus.introspect(
            DBUS_LOGIN1_SERVICE, DBUS_LOGIN1_OBJECT,
        )
        self._login1_proxy = self._bus.get_proxy_object(
            DBUS_LOGIN1_SERVICE, DBUS_LOGIN1_OBJECT, introspection,
        )
        self._login1_manager = self._login1_proxy.get_interface(
            DBUS_LOGIN1_MANAGER,
        )

        # Subscribe to PrepareForSleep signal
        self._login1_manager.on_prepare_for_sleep(self._on_prepare_for_sleep)
        LOG.info("Subscribed to %s.%s", DBUS_LOGIN1_MANAGER, SIGNAL_PREPARE_FOR_SLEEP)

    async def _cleanup(self) -> None:
        """Disconnect D-Bus."""
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
    # Auth flow
    # ------------------------------------------------------------------

    async def _on_wakeup(self) -> None:
        """Handle a wakeup event: poll mobile device and authenticate."""
        if self._auth_in_progress:
            LOG.debug("Auth already in progress, skipping")
            return
        self._auth_in_progress = True

        try:
            success = await self._poll_and_authenticate()

            if success:
                LOG.info("✓ Authentication successful — unlocking session(s)")
                self._unlock_sessions()
            else:
                LOG.warning("✗ Authentication failed or timed out")
        finally:
            self._auth_in_progress = False

    async def _poll_and_authenticate(self) -> bool:
        """
        Aggressively poll the mobile device's TCP port.

        Attempts a connection every ``poll_interval`` seconds for up to
        ``poll_timeout`` seconds.  Once connected, runs the challenge-response
        handshake.

        Returns ``True`` if the mobile's signature was verified.
        """
        host = self.config.mobile_ip
        port = self.config.mobile_port
        interval = self.config.poll_interval
        deadline = time.monotonic() + self.config.poll_timeout

        LOG.info(
            "Polling %s:%d (interval=%.1fs, timeout=%.1fs) ...",
            host, port, interval, self.config.poll_timeout,
        )

        attempt = 0
        while time.monotonic() < deadline and self._running:
            attempt += 1
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=max(interval, 1.0),
                )
                LOG.info("TCP connection established (attempt #%d)", attempt)
            except (ConnectionRefusedError, ConnectionError, OSError):
                await asyncio.sleep(interval)
                continue
            except asyncio.TimeoutError:
                await asyncio.sleep(interval)
                continue

            # Connection succeeded — run the handshake
            try:
                ok = await self._async_handshake(reader, writer)
                return ok
            except Exception as exc:
                LOG.error("Handshake error: %s", exc)
                # Connection may have failed mid-handshake — retry
                await asyncio.sleep(interval)
                continue
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        LOG.warning("Polling timed out after %d attempts", attempt)
        return False

    async def _async_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> bool:
        """
        Perform the challenge-response handshake over an established TCP
        connection (async version of ``HandshakeServer.accept_and_verify``).

        Returns ``True`` if the response signature is valid.
        """
        if self._trusted_key is None:
            LOG.error("No trusted public key loaded — cannot verify")
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
            writer.close()
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
                "✓ Handshake SUCCESS — device=%s fp=%s",
                validated.get("device_name", "?"),
                validated.get("public_key_fingerprint", "")[:16],
            )
        else:
            LOG.warning(
                "✗ Handshake FAILED — signature mismatch (device=%s)",
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
                # Test hook
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
        """
        Get the active session ID(s) for the current user via loginctl.

        Returns a list of session IDs belonging to the current user
        that have ``seat = seat0`` (local graphical sessions).
        """
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
            # Format: <session_id> <uid> <user> <seat> <type>
            # Example: "2  1000  zumuvik  seat0  wayland"
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

    if not config.valid:
        pk_status = (
            str(config.public_key_path)
            if config.public_key_path.exists() and config.public_key_path.is_file()
            else "MISSING"
        )
        LOG.warning(
            "Config incomplete (mobile_ip=%r, public_key=%s). "
            "Run 'phonect init-config' to create a template.",
            config.mobile_ip,
            pk_status,
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
            pass  # Windows or unsupported

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
    """Configure the logging handler (no syslog for now)."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
