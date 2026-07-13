"""
phonect.daemon — Asyncio-based daemon for P2P biometric unlock via Wi-Fi/TCP.

Architecture
============

The daemon advertises itself via UDP and accepts TCP connections from Android.

On resume-from-sleep (``PrepareForSleep`` D-Bus signal), the daemon:

1. Receives ``pair_hello`` with the phone's RSA public key.
2. Sends ``pair_accept`` with the PC public key.
3. Sends a challenge (nonce) — with mutual-auth signature if PC key loaded.
4. Receives and verifies the phone's signed response.
6. On success: calls ``loginctl unlock-session``.
"""

from __future__ import annotations

import asyncio
import errno
import json
import logging
import os
import socket
import struct
import subprocess
from pathlib import Path
from typing import Callable, List, Optional

from phonect.config import DaemonConfig, load_config, validate_unlock_config, UDP_DISCOVERY_PORT
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


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------


class PhonectDaemon:
    """
    Async daemon for P2P biometric unlock (Wi-Fi/TCP).

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
        self._auth_pending = False
        self._actual_listen_port = config.listen_port

        # D-Bus proxy – set during _connect_dbus()
        self._bus = None
        self._login1_proxy = None
        self._login1_manager = None
        self._server: Optional[asyncio.AbstractServer] = None
        self._discovery_task: Optional[asyncio.Task] = None

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
            "PhonectDaemon initialised (TCP %s:%s, %s)",
            config.listen_host, config.listen_port,
            "mutual auth ready" if config.mutual_auth_ready
            else "awaiting phone pairing" if config.has_pc_key
            else "no PC key",
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

        self._server = await asyncio.start_server(
            self._handle_client, self.config.listen_host, self.config.listen_port,
        )
        if self._server.sockets:
            self._actual_listen_port = self._server.sockets[0].getsockname()[1]
        if self.config.unlock_on_start:
            self._wakeup_event.set()
        LOG.info("Daemon ready. Waiting for TCP phone connections ...")

        try:
            while self._running:
                await self._wakeup_event.wait()
                self._wakeup_event.clear()

                if not self._running:
                    break

                LOG.debug("Wakeup event received; opening bounded auth window")
                await self._run_auth_cycle()

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
        if self._discovery_task is not None:
            self._discovery_task.cancel()
            self._discovery_task = None
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
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
    # TCP / auth flow
    # ------------------------------------------------------------------

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle one incoming TCP connection from the phone."""
        ok = False
        if not self._auth_pending:
            LOG.debug("TCP connection outside auth window; closing")
            writer.close()
            await writer.wait_closed()
            return
        if self._auth_in_progress:
            LOG.debug("Auth already in progress, skipping")
            writer.close()
            await writer.wait_closed()
            return
        self._auth_in_progress = True
        self._auth_completed.clear()
        self._last_auth_ok = False

        try:
            ok, may_unlock = await self._tcp_handshake(reader, writer)

            if ok and may_unlock:
                LOG.info("✓ Authentication successful — unlocking session(s)")
                self._unlock_sessions()
            elif ok:
                LOG.info("✓ Pairing completed — not unlocking on first TOFU connection")
            else:
                LOG.warning("✗ Authentication failed")
        finally:
            self._last_auth_ok = ok
            self._auth_completed.set()
            self._auth_in_progress = False
            writer.close()
            await writer.wait_closed()

    async def _run_auth_cycle(self) -> None:
        """Open a bounded auth window and broadcast discovery until auth or timeout."""
        self._auth_pending = True
        self._auth_completed.clear()
        self._last_auth_ok = False
        discovery_task = asyncio.create_task(self._broadcast_discovery_window())
        try:
            try:
                await asyncio.wait_for(self._auth_completed.wait(), timeout=self.config.poll_timeout)
            except asyncio.TimeoutError:
                LOG.debug("Auth window expired without successful connection")
        finally:
            self._auth_pending = False
            discovery_task.cancel()
            try:
                await discovery_task
            except asyncio.CancelledError:
                pass

    async def _broadcast_discovery_window(self) -> None:
        """Broadcast UDP discovery packets during the current auth window."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            deadline = asyncio.get_running_loop().time() + self.config.poll_timeout
            warned_network_unreachable = False
            while self._auth_pending and asyncio.get_running_loop().time() <= deadline:
                fp16 = "unknown"
                if self._pc_private_key is not None:
                    fp16 = fingerprint_from_public_key(self._pc_private_key.public_key())[:16]
                payload = (
                    f"PHONECT_DISCOVERY:{self.config.pc_name or socket.gethostname()}:"
                    f"{fp16}:{self._actual_listen_port}"
                ).encode("utf-8")
                try:
                    sock.sendto(payload, ("255.255.255.255", UDP_DISCOVERY_PORT))
                except OSError as exc:
                    if exc.errno == errno.ENETUNREACH:
                        if not warned_network_unreachable:
                            LOG.warning("UDP discovery failed: %s", exc.strerror or exc)
                            warned_network_unreachable = True
                        else:
                            LOG.debug("UDP discovery still unavailable: %s", exc.strerror or exc)
                        await asyncio.sleep(min(0.25, max(0.05, self.config.poll_interval / 2)))
                        continue
                    raise
                await asyncio.sleep(self.config.poll_interval)
        finally:
            sock.close()

    # ------------------------------------------------------------------
    # TCP handshake (Phone → PC)
    # ------------------------------------------------------------------

    async def _tcp_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> tuple[bool, bool]:
        """
        Full TCP handshake as PC listener. Returns (valid, may_unlock).
        """
        try:
            if self._pc_private_key is None:
                LOG.error("No PC private key — cannot authenticate")
                return False, False

            msg = await self._read_frame(reader, timeout=HANDSHAKE_TIMEOUT)
            if isinstance(msg, dict):
                LOG.debug(
                    "Received pair_hello frame: type=%s repr=%r keys=%s message_type=%r",
                    type(msg).__name__, msg, list(msg.keys()), msg.get("type"),
                )
            else:
                LOG.debug(
                    "Received pair_hello frame: type=%s repr=%r",
                    type(msg).__name__, msg,
                )
                raise ProtocolError(
                    f"pair_hello frame decoded as {type(msg).__name__}, expected dict"
                )
            hello = validate_pair_hello(msg)
            phone_pem = hello["public_key_pem"]
            phone_fp = hello["public_key_fingerprint"]
            device_name = hello.get("device_name", "phone")

            candidate_key = load_public_key(phone_pem.encode("utf-8"))
            candidate_fp = fingerprint_from_public_key(candidate_key)
            if candidate_fp != phone_fp:
                LOG.warning("Rejecting phone key: pair_hello fingerprint does not match PEM")
                return False, False

            is_new = False
            verification_key = self._trusted_key
            if self._trusted_key is None:
                is_new = True
                verification_key = candidate_key
                LOG.info("TOFU: verifying candidate %s (%s …)", device_name, phone_fp[:16])
            elif not self._is_known_key(phone_fp):
                LOG.warning("Rejecting untrusted phone key %s …; trusted key not overwritten", phone_fp[:16])
                return False, False

            pc_pem = public_key_to_pem(
                self._pc_private_key.public_key()
            ).decode()
            pc_fp = fingerprint_from_public_key(self._pc_private_key.public_key())
            accept = make_pair_accept(
                session_id=hello["session_id"],
                public_key_pem=pc_pem,
                public_key_fingerprint=pc_fp,
            )
            writer.write(encode_frame(accept))
            await writer.drain()

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
            writer.write(encode_frame(challenge))
            await writer.drain()
            LOG.debug("Sent challenge (session=%s)", challenge["session_id"])

            # 5. Receive response
            try:
                msg = await self._read_frame(reader, timeout=HANDSHAKE_TIMEOUT)
            except ProtocolSecurityError as exc:
                LOG.error("Security violation in response frame: %s", exc)
                return False, False

            if msg is None:
                LOG.warning("Empty response / connection closed")
                return False, False

            try:
                validated = validate_response(msg)
            except ProtocolError as exc:
                LOG.error("Invalid response schema: %s", exc)
                return False, False

            # 6. Verify signature (CPU-bound — run in executor)
            signature = bytes.fromhex(validated["signature"])
            loop = asyncio.get_running_loop()
            valid = await loop.run_in_executor(
                None, verify_nonce, verification_key, nonce, signature,
            )

            if valid:
                if is_new:
                    self._save_phone_key(phone_pem)
                    self._trusted_key = candidate_key
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

            return valid, (valid and not is_new)

        except (ConnectionError, OSError) as exc:
            LOG.warning("TCP connection error: %s", exc)
            return False, False
        except ProtocolSecurityError as exc:
            LOG.error("Security violation: %s", exc)
            return False, False
        except ProtocolError as exc:
            LOG.warning("Invalid handshake message: %s", exc)
            return False, False
        except Exception as exc:
            LOG.exception("Unexpected error during TCP handshake: %s", exc)
            return False, False

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
        connection.  Used by legacy tests/dev helpers.

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
        """Dispatch the configured unlock backend after successful authentication."""
        try:
            validate_unlock_config(self.config)
        except ValueError as exc:
            LOG.error("Invalid unlock backend configuration: %s", exc)
            return
        if self.config.unlock_backend == "command":
            self._unlock_command()
        else:
            self._unlock_loginctl_sessions()

    def _unlock_loginctl_sessions(self) -> None:
        """Unlock all active sessions for the current user via loginctl."""
        session_ids = self._get_active_session_ids()
        if not session_ids:
            LOG.warning("No active session found for user %s", os.environ.get("USER", "?"))
            return

        for sid in session_ids:
            cmd = ["loginctl", "unlock-session", sid]
            LOG.info("Running loginctl unlock-session for session %s", sid)

            if self._unlock_hook:
                self._unlock_hook(list(cmd))
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

    def _unlock_command(self) -> None:
        """Run the configured static command once without a shell."""
        argv = list(self.config.unlock_command)
        executable = argv[0]
        if self._unlock_hook:
            self._unlock_hook(list(argv))
            return
        try:
            LOG.info("Running unlock command executable: %s", executable)
            result = subprocess.run(
                list(argv), shell=False, capture_output=True, text=True, timeout=5,
                errors="replace",
            )
            if result.returncode == 0:
                LOG.info("Unlock command completed successfully")
            else:
                LOG.warning("Unlock command failed with status %s", result.returncode)
        except subprocess.TimeoutExpired:
            LOG.error("Unlock command timed out after 5 seconds")
        except FileNotFoundError:
            LOG.error("Unlock command executable not found")
        except OSError:
            LOG.error("Unlock command failed with OSError")

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
