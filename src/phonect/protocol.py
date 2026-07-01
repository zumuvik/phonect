"""
phonect.protocol — Wire-format messages for the challenge-response handshake.

Messages are JSON-encoded, length-prefixed frames over TCP.
"""

from __future__ import annotations

import json
import struct
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional

# ---------------------------------------------------------------------------
# Protocol version
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = 1

# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------

MSG_CHALLENGE = "challenge"         # PC → Mobile
MSG_RESPONSE = "response"           # Mobile → PC
MSG_ERROR = "error"                 # either direction


# ---------------------------------------------------------------------------
# Frame encoding (length-prefixed JSON)
# ---------------------------------------------------------------------------

FRAME_HEADER_FORMAT = "!I"           # network-byte-order uint32
FRAME_HEADER_SIZE = struct.calcsize(FRAME_HEADER_FORMAT)


def encode_frame(payload: dict) -> bytes:
    """Encode *payload* dict as a length-prefixed JSON frame."""
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    header = struct.pack(FRAME_HEADER_FORMAT, len(data))
    return header + data


def decode_frame(buffer: bytes) -> Optional[dict]:
    """
    Try to decode a single frame from *buffer*.

    Returns the decoded dict and the remainder of the buffer, or ``None``
    if the buffer doesn't contain a complete frame.
    """
    if len(buffer) < FRAME_HEADER_SIZE:
        return None
    payload_len = struct.unpack(FRAME_HEADER_FORMAT, buffer[:FRAME_HEADER_SIZE])[0]
    frame_end = FRAME_HEADER_SIZE + payload_len
    if len(buffer) < frame_end:
        return None
    payload = json.loads(buffer[FRAME_HEADER_SIZE:frame_end])
    return payload


# ---------------------------------------------------------------------------
# Message builders
# ---------------------------------------------------------------------------

def make_challenge(
    nonce: bytes,
    session_id: Optional[str] = None,
) -> dict:
    """Build a challenge message (PC → Mobile)."""
    return {
        "version": PROTOCOL_VERSION,
        "type": MSG_CHALLENGE,
        "session_id": session_id or uuid.uuid4().hex,
        "nonce": nonce.hex(),
    }


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
    return msg
