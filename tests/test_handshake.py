"""
Integration test: full challenge-response handshake over localhost TCP.
"""

from __future__ import annotations

import threading
import time

from phonect.crypto import generate_key_pair
from phonect.handshake import HandshakeServer, HandshakeClient


def test_full_handshake() -> None:
    """Generate keys, run PC server in a thread, connect with mobile emulator, verify success."""
    pc_kp = generate_key_pair()
    mobile_kp = generate_key_pair()

    server = HandshakeServer(
        trusted_public_key=mobile_kp.public_key,
        listen_host="127.0.0.1",
        listen_port=0,          # OS-assign
        timeout=10.0,
    )
    server.start()
    port = server.port
    assert port is not None and port > 0

    results: list[bool] = []

    def run_server() -> None:
        try:
            ok = server.accept_and_verify()
            results.append(ok)
        finally:
            server.close()

    t = threading.Thread(target=run_server, daemon=True)
    t.start()

    time.sleep(0.2)  # let server bind

    client = HandshakeClient(
        signing_key=mobile_kp.private_key,
        public_key_fingerprint=mobile_kp.public_key_fingerprint,
        device_name="test-phone",
        connect_timeout=5.0,
    )

    def biometric_ok(_nonce: bytes) -> bool:
        return True

    client_ok = client.do_handshake(
        pc_host="127.0.0.1",
        pc_port=port,
        before_sign_callback=biometric_ok,
    )

    t.join(timeout=5.0)

    assert client_ok, "Client reported failure"
    assert len(results) == 1 and results[0] is True, "Server reported failure"
    print("✓ Full handshake integration test PASSED")


def test_handshake_wrong_key() -> None:
    """Server has a different public key than mobile's private key → must fail."""
    pc_kp = generate_key_pair()
    mobile_kp = generate_key_pair()
    wrong_kp = generate_key_pair()  # not the mobile's key

    server = HandshakeServer(
        trusted_public_key=wrong_kp.public_key,  # Trusts WRONG key
        listen_host="127.0.0.1",
        listen_port=0,
        timeout=10.0,
    )
    server.start()
    port = server.port

    results: list[bool] = []

    def run_server() -> None:
        try:
            ok = server.accept_and_verify()
            results.append(ok)
        finally:
            server.close()

    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    time.sleep(0.2)

    client = HandshakeClient(
        signing_key=mobile_kp.private_key,
        public_key_fingerprint=mobile_kp.public_key_fingerprint,
        device_name="evil-phone",
        connect_timeout=5.0,
    )

    def biometric_ok(_nonce: bytes) -> bool:
        return True

    client_ok = client.do_handshake("127.0.0.1", port, biometric_ok)
    t.join(timeout=5.0)

    # Client still sends its response fine, but server should reject it
    assert client_ok, "Client should not fail (it signed correctly)"
    assert len(results) == 1 and results[0] is False, "Server should have rejected wrong key"
    print("✓ Wrong-key rejection test PASSED")


def test_biometric_decline() -> None:
    """Biometric declined → client should abort, server should time out."""
    pc_kp = generate_key_pair()
    mobile_kp = generate_key_pair()

    server = HandshakeServer(
        trusted_public_key=mobile_kp.public_key,
        listen_host="127.0.0.1",
        listen_port=0,
        timeout=5.0,
    )
    server.start()
    port = server.port

    results: list[bool] = []

    def run_server() -> None:
        try:
            ok = server.accept_and_verify()
            results.append(ok)
        finally:
            server.close()

    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    time.sleep(0.2)

    client = HandshakeClient(
        signing_key=mobile_kp.private_key,
        public_key_fingerprint=mobile_kp.public_key_fingerprint,
        device_name="test-phone",
        connect_timeout=5.0,
    )

    def biometric_decline(_nonce: bytes) -> bool:
        return False  # User declined

    client_ok = client.do_handshake("127.0.0.1", port, biometric_decline)
    t.join(timeout=5.0)

    assert client_ok is False, "Client should have aborted"
    # Server should timeout or get nothing
    print("✓ Biometric decline test PASSED")


if __name__ == "__main__":
    test_full_handshake()
    test_handshake_wrong_key()
    test_biometric_decline()
    print("\n=== All integration tests passed ===")
