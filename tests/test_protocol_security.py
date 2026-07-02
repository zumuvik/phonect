"""
Security tests for the phonect protocol layer.

Verifies:
- MAX_FRAME_SIZE enforcement (DoS prevention)
- Malformed JSON rejection
- Nonce length / format validation
- Invalid signature rejection
"""

from __future__ import annotations

import json
import struct

import pytest

from phonect.protocol import (
    MAX_FRAME_SIZE,
    FRAME_HEADER_SIZE,
    FRAME_HEADER_FORMAT,
    encode_frame,
    decode_frame,
    make_challenge,
    make_response,
    validate_challenge,
    validate_response,
    ProtocolError,
    ProtocolSecurityError,
)
from phonect.crypto import generate_key_pair, generate_nonce, sign_nonce


# ======================================================================
# Frame encoding / decoding security
# ======================================================================


class TestFrameSecurity:
    """Tests for encode_frame / decode_frame with security constraints."""

    def test_encode_frame_respects_max_size(self):
        """encode_frame should raise when payload exceeds MAX_FRAME_SIZE."""
        large_payload = {"data": "x" * (MAX_FRAME_SIZE + 1)}
        with pytest.raises(ProtocolSecurityError, match="exceeds maximum"):
            encode_frame(large_payload)

    def test_decode_frame_rejects_too_large_declared_length(self):
        """A frame header declaring > MAX_FRAME_SIZE must be rejected."""
        # Build a header with payload_len = MAX_FRAME_SIZE + 1
        evil_len = MAX_FRAME_SIZE + 1
        header = struct.pack(FRAME_HEADER_FORMAT, evil_len)
        # Attach a tiny payload (won't matter — header check fires first)
        evil_frame = header + b"{}"
        with pytest.raises(ProtocolSecurityError, match="exceeds maximum"):
            decode_frame(evil_frame)

    def test_decode_frame_rejects_negative_length(self):
        """A frame header with negative/zero length must be rejected."""
        header = struct.pack(FRAME_HEADER_FORMAT, 0)
        with pytest.raises(ProtocolSecurityError, match="invalid"):
            decode_frame(header + b"{}")

    def test_decode_frame_rejects_malformed_json(self):
        """Malformed JSON payload must raise ProtocolSecurityError."""
        payload = b"this is not json"
        header = struct.pack(FRAME_HEADER_FORMAT, len(payload))
        frame = header + payload
        with pytest.raises(ProtocolSecurityError, match="Invalid JSON"):
            decode_frame(frame)

    def test_decode_frame_rejects_non_dict_json(self):
        """JSON payload must be a dict (object), not array/string/number."""
        for bad in (b'"string"', b'[1,2,3]', b'42', b'null'):
            header = struct.pack(FRAME_HEADER_FORMAT, len(bad))
            frame = header + bad
            with pytest.raises(ProtocolSecurityError, match="not an object"):
                decode_frame(frame)

    def test_decode_frame_incomplete_returns_none(self):
        """Incomplete frame (no payload yet) returns None without error."""
        header = struct.pack(FRAME_HEADER_FORMAT, 100)
        assert decode_frame(header) is None  # not enough data

    def test_decode_frame_short_buffer_returns_none(self):
        """Very short buffer (< 4 bytes) returns None."""
        assert decode_frame(b"abc") is None


# ======================================================================
# Challenge message validation
# ======================================================================


class TestChallengeValidation:

    def test_valid_challenge_passes(self):
        nonce = generate_nonce()
        msg = make_challenge(nonce)
        validated = validate_challenge(msg)
        assert validated["session_id"] == msg["session_id"]
        assert len(validated["nonce"]) == 64  # 32 bytes → 64 hex chars

    def test_challenge_wrong_type_rejected(self):
        msg = make_challenge(generate_nonce())
        msg["type"] = "response"
        with pytest.raises(ProtocolError, match="Expected 'challenge'"):
            validate_challenge(msg)

    def test_challenge_missing_nonce_rejected(self):
        msg = make_challenge(generate_nonce())
        del msg["nonce"]
        with pytest.raises(ProtocolError, match="Missing 'nonce'"):
            validate_challenge(msg)

    def test_challenge_short_nonce_rejected(self):
        msg = make_challenge(generate_nonce())
        msg["nonce"] = "abcd"  # only 4 hex chars, not 64
        with pytest.raises(ProtocolError, match="64 hex chars"):
            validate_challenge(msg)

    def test_challenge_invalid_hex_nonce_rejected(self):
        msg = make_challenge(generate_nonce())
        msg["nonce"] = "zz" * 32  # 64 chars, but not valid hex
        with pytest.raises(ProtocolError, match="not valid hex"):
            validate_challenge(msg)

    def test_challenge_accepts_optional_mutual_auth_fields(self):
        """Challenge with mutual-auth fields must still validate."""
        kp = generate_key_pair()
        nonce = generate_nonce()
        sig = sign_nonce(kp.private_key, nonce)
        fp = kp.public_key_fingerprint

        msg = make_challenge(nonce, pc_key_fingerprint=fp, pc_signature=sig)
        validated = validate_challenge(msg)
        assert validated["pc_key_fingerprint"] == fp
        assert validated["pc_signature"] == sig.hex()


# ======================================================================
# Response message validation
# ======================================================================


class TestResponseValidation:

    def test_valid_response_passes(self):
        kp = generate_key_pair()
        nonce = generate_nonce()
        sig = sign_nonce(kp.private_key, nonce)
        msg = make_response("sess-1", sig, kp.public_key_fingerprint, "test-phone")
        validated = validate_response(msg)
        assert validated["session_id"] == "sess-1"
        assert validated["device_name"] == "test-phone"

    def test_response_wrong_type_rejected(self):
        kp = generate_key_pair()
        sig = sign_nonce(kp.private_key, generate_nonce())
        msg = make_response("s-1", sig, kp.public_key_fingerprint)
        msg["type"] = "challenge"
        with pytest.raises(ProtocolError, match="Expected 'response'"):
            validate_response(msg)

    def test_response_missing_signature_rejected(self):
        kp = generate_key_pair()
        sig = sign_nonce(kp.private_key, generate_nonce())
        msg = make_response("s-1", sig, kp.public_key_fingerprint)
        del msg["signature"]
        with pytest.raises(ProtocolError, match="Missing 'signature'"):
            validate_response(msg)

    def test_response_short_signature_rejected(self):
        """RSA-4096 signature = 512 bytes → 1024 hex chars."""
        kp = generate_key_pair()
        sig = sign_nonce(kp.private_key, generate_nonce())
        msg = make_response("s-1", sig[:100], kp.public_key_fingerprint)
        with pytest.raises(ProtocolError, match="512"):
            validate_response(msg)

    def test_response_invalid_hex_signature_rejected(self):
        kp = generate_key_pair()
        msg = {
            "version": 1,
            "type": "response",
            "session_id": "s-1",
            "signature": "zzzz",  # not valid hex
            "public_key_fingerprint": kp.public_key_fingerprint,
            "device_name": "test",
        }
        with pytest.raises(ProtocolError, match="not valid hex"):
            validate_response(msg)


# ======================================================================
# MAX_FRAME_SIZE constant integrity
# ======================================================================


class TestMaxFrameSize:

    def test_constant_is_65536(self):
        assert MAX_FRAME_SIZE == 65_536

    def test_roundtrip_at_limit(self):
        """A payload exactly at MAX_FRAME_SIZE must encode/decode correctly,
        provided it's valid JSON."""
        # Build a dict that serialises to ~ MAX_FRAME_SIZE bytes
        key = "x" * 100
        val = "y" * (MAX_FRAME_SIZE - len(key) - 20)  # approx
        payload = {key: val}
        frame = encode_frame(payload)
        decoded = decode_frame(frame)
        assert decoded is not None
        assert key in decoded
