"""
phonect.handshake — High-level handshake orchestration.

Contains the PC-side challenge issuer and the mobile-side responder
abstractions that use the crypto primitives and protocol messages.

Mutual authentication (future)
==============================
The challenge message already carries optional fields ``pc_key_fingerprint``
and ``pc_signature``.  When both are present, the mobile can verify the PC's
identity before responding — enabling full mutual (bidirectional) RSA
authentication.  The existing flow works without these fields (backward
compatible).
"""

from __future__ import annotations

import logging
import socket
from typing import Callable, Optional

from phonect.crypto import (
    generate_nonce,
    sign_nonce,
    verify_nonce,
    fingerprint_from_public_key,
    rsa,
)
from phonect.protocol import (
    FRAME_HEADER_SIZE,
    MAX_FRAME_SIZE,
    encode_frame,
    decode_frame,
    make_challenge,
    make_response,
    make_error,
    validate_challenge,
    validate_response,
    ProtocolError,
    ProtocolSecurityError,
)

LOG = logging.getLogger(__name__)

# Max bytes to read when accumulating a frame
READ_CHUNK_SIZE = 4096


# ---------------------------------------------------------------------------
# PC side  —  Challenge issuer
# ---------------------------------------------------------------------------

class HandshakeServer:
    """
    Runs on the PC.

    Listens on a TCP port for a mobile connection, sends a challenge,
    receives the signed response, and verifies it against the stored
    public key.

    Parameters
    ----------
    trusted_public_key
        The mobile device's RSA public key (used for verification).
    pc_private_key
        Optional.  If set, the PC also signs the challenge, enabling
        mutual authentication with the phone.  (Future use.)
    """

    def __init__(
        self,
        trusted_public_key: rsa.RSAPublicKey,
        pc_private_key: Optional[rsa.RSAPrivateKey] = None,
        listen_host: str = "0.0.0.0",
        listen_port: int = 0,       # 0 = OS-assign
        timeout: float = 30.0,
    ) -> None:
        self.trusted_key = trusted_public_key
        self._pc_private_key = pc_private_key
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None

    @property
    def port(self) -> Optional[int]:
        return self._sock.getsockname()[1] if self._sock else None

    def start(self) -> None:
        """Bind and listen."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.listen_host, self.listen_port))
        self._sock.listen(1)
        self._sock.settimeout(self.timeout)
        LOG.info(
            "HandshakeServer listening on %s:%d (timeout=%.1fs)",
            self.listen_host, self.port, self.timeout,
        )

    def accept_and_verify(self) -> bool:
        """
        Accept one connection, run the full challenge-response flow.

        Returns ``True`` if the response was verified successfully.
        """
        if self._sock is None:
            raise RuntimeError("Server not started. Call .start() first.")

        conn, addr = self._sock.accept()
        LOG.info("Connection from %s:%d", *addr)

        try:
            conn.settimeout(self.timeout)

            # 1. Generate & send challenge (with optional mutual-auth fields)
            nonce = generate_nonce()

            pc_fp: Optional[str] = None
            pc_sig: Optional[bytes] = None
            if self._pc_private_key is not None:
                pc_fp = fingerprint_from_public_key(
                    self._pc_private_key.public_key()
                )
                pc_sig = sign_nonce(self._pc_private_key, nonce)
                LOG.debug("Mutual-auth challenge signed by PC key %s", pc_fp[:16])

            challenge = make_challenge(
                nonce,
                pc_key_fingerprint=pc_fp,
                pc_signature=pc_sig,
            )
            conn.sendall(encode_frame(challenge))
            LOG.debug("Sent challenge (session=%s)", challenge["session_id"])

            # 2. Read response (with size limit)
            buf = b""
            while len(buf) <= FRAME_HEADER_SIZE + MAX_FRAME_SIZE:
                chunk = conn.recv(READ_CHUNK_SIZE)
                if not chunk:
                    LOG.warning("Connection closed by peer (no response)")
                    return False
                buf += chunk
                try:
                    msg = decode_frame(buf)
                except ProtocolSecurityError as exc:
                    LOG.error("Security violation: %s", exc)
                    return False
                if msg is not None:
                    break
            else:
                LOG.warning("Response exceeded maximum frame size")
                return False

            # 3. Validate message structure
            try:
                validated = validate_response(msg)
            except ProtocolError as exc:
                LOG.error("Invalid response: %s", exc)
                try:
                    conn.sendall(
                        encode_frame(make_error(msg.get("session_id", ""), str(exc)))
                    )
                except OSError:
                    pass
                return False

            # 4. Verify signature (RSA-4096 PSS/SHA-512)
            try:
                signature = bytes.fromhex(validated["signature"])
            except ValueError:
                LOG.error("Response contains invalid hex signature")
                return False

            valid = verify_nonce(self.trusted_key, nonce, signature)

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

        except socket.timeout:
            LOG.warning("Handshake timed out waiting for response")
            return False
        except OSError as exc:
            LOG.error("Socket error during handshake: %s", exc)
            return False
        except Exception:
            LOG.exception("Unexpected error during handshake")
            return False
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


# ---------------------------------------------------------------------------
# Mobile side  —  Response signer
# ---------------------------------------------------------------------------

class HandshakeClient:
    """
    Runs on the mobile device (or mobile emulator).

    Connects to the PC, receives a challenge, signs the nonce with
    the local private key, and sends the signed response back.
    """

    def __init__(
        self,
        signing_key: rsa.RSAPrivateKey,
        public_key_fingerprint: str,
        device_name: str = "android-phone",
        connect_timeout: float = 10.0,
    ) -> None:
        self.signing_key = signing_key
        self.fingerprint = public_key_fingerprint
        self.device_name = device_name
        self.connect_timeout = connect_timeout

    def do_handshake(
        self,
        pc_host: str,
        pc_port: int,
        before_sign_callback: Optional[Callable[[bytes, dict], bool]] = None,
    ) -> bool:
        """
        Connect to PC, receive challenge, sign, respond.

        *before_sign_callback* is invoked with the raw nonce bytes and the
        full challenge dict (which may contain mutual-auth fields).
        Return ``True`` to proceed or ``False`` to abort.

        Returns ``True`` on successful completion (signature sent).
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.connect_timeout)

        try:
            sock.connect((pc_host, pc_port))
            LOG.info("Connected to PC %s:%d", pc_host, pc_port)

            # 1. Read challenge (with size limit)
            buf = b""
            while len(buf) <= FRAME_HEADER_SIZE + MAX_FRAME_SIZE:
                chunk = sock.recv(READ_CHUNK_SIZE)
                if not chunk:
                    LOG.warning("PC closed connection unexpectedly")
                    return False
                buf += chunk
                try:
                    msg = decode_frame(buf)
                except ProtocolSecurityError as exc:
                    LOG.error("Security violation: %s", exc)
                    return False
                if msg is not None:
                    break
            else:
                LOG.warning("Challenge exceeded maximum frame size")
                return False

            # 2. Validate challenge
            try:
                validated = validate_challenge(msg)
            except ProtocolError as exc:
                LOG.error("Invalid challenge: %s", exc)
                return False

            nonce = bytes.fromhex(validated["nonce"])
            session_id = validated["session_id"]
            LOG.debug(
                "Received challenge (session=%s, nonce_len=%d)",
                session_id, len(nonce),
            )

            # 2a. (Future) Verify PC mutual-auth signature if present
            pc_fp = validated.get("pc_key_fingerprint")
            pc_sig_hex = validated.get("pc_signature")
            if pc_fp is not None and pc_sig_hex is not None:
                # The phone would verify the PC's signature here
                LOG.info(
                    "Mutual-auth challenge from PC fp=%s (verification TBD)",
                    pc_fp[:16],
                )
                # TODO: verify pc_sig against known PC public key

            # 3. Biometric gate (callback)
            if before_sign_callback is not None:
                LOG.info("Awaiting biometric confirmation …")
                if not before_sign_callback(nonce, validated):
                    LOG.warning("Biometric declined — aborting handshake")
                    return False

            # 4. Sign
            signature = sign_nonce(self.signing_key, nonce)
            LOG.debug("Nonce signed (%d bytes signature)", len(signature))

            # 5. Send response
            response = make_response(
                session_id=session_id,
                signature=signature,
                public_key_fingerprint=self.fingerprint,
                device_name=self.device_name,
            )
            sock.sendall(encode_frame(response))
            LOG.info("✓ Response sent to PC")
            return True

        except socket.timeout:
            LOG.warning("Connection to PC timed out")
            return False
        except ConnectionRefusedError:
            LOG.warning("Connection refused — PC not listening?")
            return False
        except OSError as exc:
            LOG.error("Socket error during handshake: %s", exc)
            return False
        except Exception:
            LOG.exception("Unexpected error during handshake")
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass
