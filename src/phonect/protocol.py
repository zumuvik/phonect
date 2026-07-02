"""
phonect.protocol — Wire-format messages for the challenge-response handshake.

Messages are JSON-encoded, length-prefixed frames over TCP.

Frame format
============
::

   ┌──────────────────────────────┐
   │  uint32 payload_length (BE)  │  ← header (4 bytes)
   ├──────────────────────────────┤
   │  UTF-8 JSON payload          │  ← max 65536 bytes
   └──────────────────────────────┘

Security constraints
====================
* Maximum frame (payload) size: **64 KB** — prevents memory exhaustion.
* Nonce must be exactly 32 bytes (64 hex chars).
* JSON parsing is wrapped in try/except — malformed input never crashes.
* Future mutual-auth fields are accepted but not required for backward compat.
"""

from __future__ import annotations

import json
import struct
import uuid
from typing import Optional

# ---------------------------------------------------------------------------
# Protocol version
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = 1

# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------

MSG_CHALLENGE = "challenge"           # PC → Mobile
MSG_RESPONSE = "response"             # Mobile → PC
MSG_ERROR = "error"                   # either direction
MSG_PAIR_HELLO = "pair_hello"        # Mobile → PC (TOFU first contact)
MSG_PAIR_ACCEPT = "pair_accept"      # PC → Mobile (TOFU response)

# ---------------------------------------------------------------------------
# Security limits
# ---------------------------------------------------------------------------

MAX_FRAME_SIZE = 65_536            # 64 KB — hard limit on JSON payload
NONCE_HEX_LENGTH = 64              # 32 bytes → 64 hex chars

# ---------------------------------------------------------------------------
# Frame encoding (length-prefixed JSON)
# ---------------------------------------------------------------------------

FRAME_HEADER_FORMAT = "!I"          # network-byte-order uint32
FRAME_HEADER_SIZE = struct.calcsize(FRAME_HEADER_FORMAT)


class ProtocolSecurityError(Exception):
    """Raised when a frame violates security constraints (size, etc.)."""


def encode_frame(payload: dict) -> bytes:
    """Encode *payload* dict as a length-prefixed JSON frame."""
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    if len(data) > MAX_FRAME_SIZE:
        raise ProtocolSecurityError(
            f"Payload {len(data)} bytes exceeds maximum {MAX_FRAME_SIZE}"
        )

    header = struct.pack(FRAME_HEADER_FORMAT, len(data))
    return header + data


def decode_frame(buffer: bytes) -> Optional[dict]:
    """
    Try to decode a single frame from *buffer*.

    Returns the decoded dict, or ``None`` if the buffer doesn't contain a
    complete frame.

    Raises
    ------
    ProtocolSecurityError
        If the declared payload length exceeds ``MAX_FRAME_SIZE``.
    """
    if len(buffer) < FRAME_HEADER_SIZE:
        return None

    payload_len = struct.unpack(FRAME_HEADER_FORMAT, buffer[:FRAME_HEADER_SIZE])[0]

    # ── Security: enforce max frame size ──────────────────────────────────
    if payload_len <= 0 or payload_len > MAX_FRAME_SIZE:
        raise ProtocolSecurityError(
            f"Declared payload length {payload_len} is invalid or exceeds "
            f"maximum {MAX_FRAME_SIZE}"
        )

    frame_end = FRAME_HEADER_SIZE + payload_len
    if len(buffer) < frame_end:
        return None

    # ── Security: wrap JSON parsing ──────────────────────────────────────
    try:
        payload = json.loads(buffer[FRAME_HEADER_SIZE:frame_end])
    except json.JSONDecodeError as exc:
        raise ProtocolSecurityError(f"Invalid JSON payload: {exc}") from exc

    if not isinstance(payload, dict):
        raise ProtocolSecurityError("JSON payload is not an object")

    return payload


# ---------------------------------------------------------------------------
# Message builders
# ---------------------------------------------------------------------------

def make_challenge(
    nonce: bytes,
    session_id: Optional[str] = None,
    pc_key_fingerprint: Optional[str] = None,
    pc_signature: Optional[bytes] = None,
) -> dict:
    """
    Build a challenge message (PC → Mobile).

    If *pc_key_fingerprint* and *pc_signature* are provided, they enable
    **mutual authentication**: the phone can verify the PC's identity.
    For backward compatibility these fields are optional.
    """
    msg: dict = {
        "version": PROTOCOL_VERSION,
        "type": MSG_CHALLENGE,
        "session_id": session_id or uuid.uuid4().hex,
        "nonce": nonce.hex(),
    }

    # Mutual auth fields (optional, future use)
    if pc_key_fingerprint is not None:
        msg["pc_key_fingerprint"] = pc_key_fingerprint
    if pc_signature is not None:
        msg["pc_signature"] = pc_signature.hex()

    return msg


def make_response(
    session_id: str,
    signature: bytes,
    public_key_fingerprint: str,
    device_name: str = "android-phone",
) -> dict:
    """Build a signed response message (Mobile → PC)."""
    return {
        "version": PROTOCOL_VERSION,
        "type": MSG_RESPONSE,
        "session_id": session_id,
        "signature": signature.hex(),
        "public_key_fingerprint": public_key_fingerprint,
        "device_name": device_name,
    }


def make_error(session_id: str, reason: str) -> dict:
    """Build an error message."""
    return {
        "version": PROTOCOL_VERSION,
        "type": MSG_ERROR,
        "session_id": session_id,
        "reason": reason,
    }


def make_pair_hello(
    public_key_pem: str,
    public_key_fingerprint: str,
    device_name: str = "android-phone",
    session_id: Optional[str] = None,
) -> dict:
    """
    Build a pair_hello message (Mobile → PC).

    Sent by the phone on first TCP connection to an unknown PC.
    Carries the phone's RSA public key so the PC can store it
    (Trust On First Use).
    """
    return {
        "version": PROTOCOL_VERSION,
        "type": MSG_PAIR_HELLO,
        "session_id": session_id or uuid.uuid4().hex,
        "public_key_pem": public_key_pem,
        "public_key_fingerprint": public_key_fingerprint,
        "device_name": device_name,
    }


def make_pair_accept(
    session_id: str,
    public_key_pem: str,
    public_key_fingerprint: str,
) -> dict:
    """
    Build a pair_accept message (PC → Mobile).

    Response to ``pair_hello``.  Carries the PC's RSA public key
    so the phone can store it.
    """
    return {
        "version": PROTOCOL_VERSION,
        "type": MSG_PAIR_ACCEPT,
        "session_id": session_id,
        "public_key_pem": public_key_pem,
        "public_key_fingerprint": public_key_fingerprint,
    }


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

class ProtocolError(Exception):
    """Raised when a received message fails schema validation."""


def validate_challenge(msg: dict) -> dict:
    """Validate and return a challenge message."""
    if msg.get("type") != MSG_CHALLENGE:
        raise ProtocolError(f"Expected '{MSG_CHALLENGE}', got '{msg.get('type')}'")
    if "nonce" not in msg:
        raise ProtocolError("Missing 'nonce' in challenge")
    if "session_id" not in msg:
        raise ProtocolError("Missing 'session_id' in challenge")

    # Validate nonce length
    nonce = msg["nonce"]
    if not isinstance(nonce, str) or len(nonce) != NONCE_HEX_LENGTH:
        raise ProtocolError(
            f"Nonce must be {NONCE_HEX_LENGTH} hex chars, got {len(nonce)}"
        )

    # Validate nonce is valid hex
    try:
        bytes.fromhex(nonce)
    except ValueError as exc:
        raise ProtocolError(f"Nonce is not valid hex: {exc}") from exc

    return msg


def validate_response(msg: dict) -> dict:
    """Validate and return a response message."""
    if msg.get("type") != MSG_RESPONSE:
        raise ProtocolError(f"Expected '{MSG_RESPONSE}', got '{msg.get('type')}'")
    if "signature" not in msg:
        raise ProtocolError("Missing 'signature' in response")
    if "session_id" not in msg:
        raise ProtocolError("Missing 'session_id' in response")
    if "public_key_fingerprint" not in msg:
        raise ProtocolError("Missing 'public_key_fingerprint' in response")

    # Validate signature hex length
    sig = msg["signature"]
    if not isinstance(sig, str):
        raise ProtocolError("'signature' must be a hex string")
    try:
        sig_bytes = bytes.fromhex(sig)
    except ValueError as exc:
        raise ProtocolError(f"Signature is not valid hex: {exc}") from exc

    # RSA-4096 PSS signature = 512 bytes = 1024 hex chars
    if len(sig_bytes) != 512:
        raise ProtocolError(
            f"Signature length {len(sig_bytes)} bytes != expected 512 "
            f"(RSA-4096 PSS/SHA-512)"
        )

    return msg


def validate_pair_hello(msg: dict) -> dict:
    """Validate a pair_hello message."""
    if msg.get("type") != MSG_PAIR_HELLO:
        raise ProtocolError(f"Expected '{MSG_PAIR_HELLO}', got '{msg.get('type')}'")
    if "public_key_pem" not in msg:
        raise ProtocolError("Missing 'public_key_pem' in pair_hello")
    if "public_key_fingerprint" not in msg:
        raise ProtocolError("Missing 'public_key_fingerprint' in pair_hello")
    if "session_id" not in msg:
        raise ProtocolError("Missing 'session_id' in pair_hello")
    return msg


def validate_pair_accept(msg: dict) -> dict:
    """Validate a pair_accept message."""
    if msg.get("type") != MSG_PAIR_ACCEPT:
        raise ProtocolError(f"Expected '{MSG_PAIR_ACCEPT}', got '{msg.get('type')}'")
    if "public_key_pem" not in msg:
        raise ProtocolError("Missing 'public_key_pem' in pair_accept")
    if "public_key_fingerprint" not in msg:
        raise ProtocolError("Missing 'public_key_fingerprint' in pair_accept")
    if "session_id" not in msg:
        raise ProtocolError("Missing 'session_id' in pair_accept")
    return msg
