"""
phonect.cli — Command-line tool for development & testing.

Usage::

    # Generate a keypair and save to files
    phonect gen-keys

    # Run as PC server (waits for mobile to connect)
    phonect server <public_key.pem>

    # Run as mobile emulator (connects to PC)
    phonect client <private_key.pem> <pc_ip> <pc_port>

    # Run the system daemon
    phonect daemon [--config <path>] [--foreground]

    # Initialise a config template
    phonect init-config [--path <path>]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from phonect.crypto import generate_key_pair, load_public_key, load_private_key
from phonect.handshake import HandshakeServer, HandshakeClient


def cmd_gen_keys(args: argparse.Namespace) -> None:
    """Generate RSA-4096 key pair and save to files."""
    kp = generate_key_pair()

    priv_path = Path(args.private_key)
    pub_path = Path(args.public_key)

    priv_path.write_bytes(kp.private_key_pem)
    pub_path.write_bytes(kp.public_key_pem)

    print(f"✓ Key pair generated:")
    print(f"  Private key: {priv_path}  ({len(kp.private_key_pem)} bytes)")
    print(f"  Public key:  {pub_path}  ({len(kp.public_key_pem)} bytes)")
    print(f"  Fingerprint: {kp.public_key_fingerprint}")


def cmd_server(args: argparse.Namespace) -> None:
    """Run as PC challenge server."""
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="%(message)s")
    pub_key = load_public_key(Path(args.public_key).read_bytes())
    server = HandshakeServer(
        trusted_public_key=pub_key,
        listen_port=args.port,
        timeout=args.timeout,
    )
    server.start()
    print(f"Listening on port {server.port} ...")
    result = server.accept_and_verify()
    server.close()

    if result:
        print("\n✓ SUCCESS: Handshake verified — session unlocked!")
        sys.exit(0)
    else:
        print("\n✗ FAILED: Handshake rejected.")
        sys.exit(1)


def cmd_client(args: argparse.Namespace) -> None:
    """Run as mobile emulator client."""

    def biometric_prompt(_nonce: bytes, _challenge: dict) -> bool:
        """Simulate Android biometric dialogue."""
        print("\n  [Simulating BiometricPrompt — fingerprint scan OK]\n")
        return True

    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="%(message)s")
    priv_key = load_private_key(Path(args.private_key).read_bytes())
    pub_key = priv_key.public_key()

    from phonect.crypto import fingerprint_from_public_key
    fp = fingerprint_from_public_key(pub_key)

    client = HandshakeClient(
        signing_key=priv_key,
        public_key_fingerprint=fp,
        device_name=args.device_name,
        connect_timeout=args.timeout,
    )

    result = client.do_handshake(
        pc_host=args.pc_ip,
        pc_port=args.pc_port,
        before_sign_callback=biometric_prompt,
    )

    if result:
        print("\n✓ Handshake completed successfully.")
        sys.exit(0)
    else:
        print("\n✗ Handshake failed.")
        sys.exit(1)


def cmd_daemon(args: argparse.Namespace) -> None:
    """Run the system daemon (D-Bus / poll / unlock)."""
    from phonect.daemon import run_daemon

    asyncio.run(run_daemon(
        config_path=Path(args.config) if args.config else None,
        foreground=args.foreground,
    ))


def cmd_init_config(args: argparse.Namespace) -> None:
    """Write a default config.toml template."""
    from phonect.config import write_default_config

    target = Path(args.path) if args.path else None
    written = write_default_config(target)
    print(f"✓ Config template written to: {written}")
    print(f"  Edit it to set your mobile IP and public key path, then run:")
    print(f"    phonect daemon")


def cmd_tui(_args: argparse.Namespace) -> None:
    """Launch the Textual TUI."""
    from phonect.tui import run_tui
    run_tui()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="phonect",
        description="P2P Biometric Laptop Unlock — development CLI",
    )
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sub = parser.add_subparsers(dest="command", required=True)

    # gen-keys
    gk = sub.add_parser("gen-keys", help="Generate RSA-4096 key pair")
    gk.add_argument("--private-key", default="phonect_private.pem")
    gk.add_argument("--public-key", default="phonect_public.pem")
    gk.set_defaults(func=cmd_gen_keys)

    # server (PC side)
    sv = sub.add_parser("server", help="Run as PC challenge server")
    sv.add_argument("public_key", help="Path to trusted public key PEM file")
    sv.add_argument("--port", type=int, default=0, help="Listen port (0 = random)")
    sv.add_argument("--timeout", type=float, default=30.0, help="Handshake timeout (s)")
    sv.set_defaults(func=cmd_server)

    # client (mobile emulator)
    cl = sub.add_parser("client", help="Run as mobile handshake emulator")
    cl.add_argument("private_key", help="Path to private key PEM file")
    cl.add_argument("pc_ip", help="PC IP address to connect to")
    cl.add_argument("pc_port", type=int, help="PC port number")
    cl.add_argument("--device-name", default="android-emulator")
    cl.add_argument("--timeout", type=float, default=10.0)
    cl.set_defaults(func=cmd_client)

    # daemon (system service)
    dm = sub.add_parser("daemon", help="Run the background unlock daemon")
    dm.add_argument("--config", help="Path to config.toml (default: ~/.config/phonect/config.toml)")
    dm.add_argument("--foreground", action="store_true", help="Log to stderr instead of syslog")
    dm.set_defaults(func=cmd_daemon)

    # init-config
    ic = sub.add_parser("init-config", help="Write a default config.toml template")
    ic.add_argument("--path", help="Output path (default: ~/.config/phonect/config.toml)")
    ic.set_defaults(func=cmd_init_config)

    # tui
    tui_p = sub.add_parser("tui", help="Launch the Textual TUI (pairing, status, logs)")
    tui_p.set_defaults(func=cmd_tui)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
