"""
phonect.config — Configuration file management for the daemon.

Config location:  ``$XDG_CONFIG_HOME/phonect/config.toml``
Defaults:         ``~/.config/phonect/config.toml``

Zero-config discovery: the daemon no longer needs a static ``mobile_ip``.
Instead it listens for incoming TCP connections from the phone and sends
UDP broadcasts for device discovery.

Example config::

    [keys]
    private_key = "/home/user/.config/phonect/pc_private.pem"
    public_key = "/home/user/.config/phonect/trusted_device.pub"

    [daemon]
    listen_port = 9876
    pc_name = "my-laptop"

    [logging]
    level = "INFO"
"""

from __future__ import annotations

import tomllib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

CONFIG_DIR_NAME = "phonect"
CONFIG_FILE_NAME = "config.toml"
DEFAULT_LISTEN_PORT = 9876
UDP_DISCOVERY_PORT = 9875
DEFAULT_POLL_INTERVAL_SEC = 0.3   # 300ms between UDP broadcasts
DEFAULT_POLL_TIMEOUT_SEC = 15.0   # broadcast window
DEFAULT_PC_KEY_BASENAME = "pc_private"


# ---------------------------------------------------------------------------
# Config data class
# ---------------------------------------------------------------------------

@dataclass
class DaemonConfig:
    """Runtime configuration for the daemon."""

    # PC identity
    pc_name: str = ""
    private_key_path: Path = field(default_factory=lambda: Path("/nonexistent"))

    # Trusted phone key (populated by TOFU on first connection)
    public_key_path: Path = field(default_factory=lambda: Path("/nonexistent"))

    # TCP listener (phone connects here)
    listen_host: str = "0.0.0.0"
    listen_port: int = DEFAULT_LISTEN_PORT

    # Behaviour
    poll_interval: float = DEFAULT_POLL_INTERVAL_SEC
    poll_timeout: float = DEFAULT_POLL_TIMEOUT_SEC
    unlock_on_start: bool = False

    # Logging
    log_level: str = "INFO"

    # Derived
    config_dir: Path = field(default_factory=lambda: _default_config_dir())

    @property
    def trusted_key_pem(self) -> bytes:
        """Read the trusted (mobile) public key PEM file."""
        return self.public_key_path.read_bytes()

    @property
    def pc_private_key_pem(self) -> bytes:
        """Read the PC private key PEM file."""
        return self.private_key_path.read_bytes()

    @property
    def has_pc_key(self) -> bool:
        """PC has its own private key (needed for signing challenges)."""
        return self.private_key_path.exists()

    @property
    def has_trusted_key(self) -> bool:
        """A phone public key has been paired (TOFU completed)."""
        return self.public_key_path.exists()

    @property
    def mutual_auth_ready(self) -> bool:
        """Both sides can authenticate each other."""
        return self.has_pc_key and self.has_trusted_key


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _default_config_dir() -> Path:
    """Return ``$XDG_CONFIG_HOME/phonect`` or ``~/.config/phonect``."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / CONFIG_DIR_NAME
    return Path.home() / ".config" / CONFIG_DIR_NAME


def default_config_path() -> Path:
    """Return the default config file path."""
    return _default_config_dir() / CONFIG_FILE_NAME


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config(path: Optional[Path] = None) -> DaemonConfig:
    """
    Load and parse a ``phonect`` TOML config file.

    If *path* is ``None``, the default location is used
    (``~/.config/phonect/config.toml``).  Missing files return defaults.
    """

    cfg_path = path or default_config_path()

    if not cfg_path.exists():
        return DaemonConfig()

    raw = cfg_path.read_bytes()
    data = tomllib.loads(raw.decode("utf-8"))

    base = DaemonConfig(config_dir=cfg_path.parent)

    # ── [keys] ────────────────────────────────────────────────────────
    keys = data.get("keys", {})

    pk = keys.get("public_key", "")
    if pk:
        base.public_key_path = Path(pk).expanduser()
    else:
        fallback = cfg_path.parent / "trusted_device.pub"
        if fallback.exists():
            base.public_key_path = fallback

    privk = keys.get("private_key", "")
    if privk:
        base.private_key_path = Path(privk).expanduser()
    else:
        fallback_priv = cfg_path.parent / f"{DEFAULT_PC_KEY_BASENAME}.pem"
        if fallback_priv.exists():
            base.private_key_path = fallback_priv

    # ── [daemon] ──────────────────────────────────────────────────────
    daemon = data.get("daemon", {})
    base.listen_host = daemon.get("listen_host", base.listen_host)
    base.listen_port = daemon.get("listen_port", base.listen_port)
    if "poll_interval_ms" in daemon:
        base.poll_interval = daemon["poll_interval_ms"] / 1000.0
    if "poll_timeout_seconds" in daemon:
        base.poll_timeout = daemon["poll_timeout_seconds"]
    base.unlock_on_start = daemon.get("unlock_on_start", base.unlock_on_start)
    base.pc_name = daemon.get("pc_name", base.pc_name)

    # ── [logging] ─────────────────────────────────────────────────────
    logging_ = data.get("logging", {})
    base.log_level = logging_.get("level", base.log_level)

    return base


# ---------------------------------------------------------------------------
# Config file initialiser
# ---------------------------------------------------------------------------

def write_default_config(path: Optional[Path] = None) -> Path:
    """Write a template config file to *path* (or the default location)."""
    cfg_path = path or default_config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)

    template = """\
# ── phonect daemon configuration ──────────────────────────────────────────
# See https://github.com/zumuvik/phonect
#
# Zero-config: no IP needed.  The daemon listens for phone connections
# and broadcasts its presence via UDP discovery on port 9875.

[keys]
# Path to the PC's own private key (PEM) — generate with: phonect gen-keys
private_key = "%s/pc_private.pem"
# Path to the trusted mobile device public key (PEM) — auto-populated by
# Trust-On-First-Use on the first successful connection
public_key = "%s/trusted_device.pub"

[daemon]
# TCP port the daemon listens on (phone connects here)
listen_port = 9876
# Human-friendly PC name shown during pairing
pc_name = "my-laptop"
# Run one auth cycle when the daemon starts
unlock_on_start = false
# How often (ms) to send UDP discovery broadcasts after wake
poll_interval_ms = 300
# Max polling window (seconds) — phone must respond within this window
poll_timeout_seconds = 15

[logging]
level = "INFO"
""" % (cfg_path.parent, cfg_path.parent)

    cfg_path.write_text(template)
    return cfg_path
