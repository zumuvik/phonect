"""
phonect.config — Configuration file management for the daemon.

Config location:  ``$XDG_CONFIG_HOME/phonect/config.toml``
Defaults:         ``~/.config/phonect/config.toml``

Example config::

    [device]
    mobile_ip = "192.168.1.100"
    mobile_port = 9876

    [keys]
    public_key = "/home/user/.config/phonect/trusted_device.pub"
    private_key = "/home/user/.config/phonect/pc_private.pem"

    [daemon]
    poll_interval_ms = 200
    poll_timeout_seconds = 10
    unlock_on_start = false

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
DEFAULT_POLL_INTERVAL_MS = 200
DEFAULT_POLL_TIMEOUT_SEC = 10
DEFAULT_MOBILE_PORT = 9876
DEFAULT_PC_KEY_NAME = "pc_private"
DEFAULT_PC_KEY_BASENAME = "pc_private"


# ---------------------------------------------------------------------------
# Config data class
# ---------------------------------------------------------------------------

@dataclass
class DaemonConfig:
    """Runtime configuration for the daemon."""

    # Device
    mobile_ip: str = ""
    mobile_port: int = DEFAULT_MOBILE_PORT

    # PC identity
    pc_name: str = ""
    private_key_path: Path = field(default_factory=lambda: Path())

    # Keys
    public_key_path: Path = field(default_factory=lambda: Path())

    # Behaviour
    poll_interval: float = DEFAULT_POLL_INTERVAL_MS / 1000.0
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
    def valid(self) -> bool:
        """Check if the config has the minimum required fields for daemon mode."""
        return bool(self.mobile_ip) and self.public_key_path.exists()

    @property
    def mutual_auth_ready(self) -> bool:
        """Check if both mobile public key AND PC private key are available."""
        return self.valid and self.private_key_path.exists()


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

    # ── [device] ──────────────────────────────────────────────────────
    dev = data.get("device", {})
    base.mobile_ip = dev.get("mobile_ip", base.mobile_ip)
    base.mobile_port = dev.get("mobile_port", base.mobile_port)

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

[device]
# Static IP of the Android phone on your LAN
mobile_ip = "192.168.1.100"
# Port the phone's listener is bound to
mobile_port = 9876

[keys]
# Path to the trusted mobile device public key (PEM)
public_key = "%s/trusted_device.pub"
# Path to the PC's own private key (PEM) — for mutual authentication
private_key = "%s/pc_private.pem"

[daemon]
# How often (ms) to retry TCP connect during wakeup polling
poll_interval_ms = 200
# Max polling window (seconds) before giving up
poll_timeout_seconds = 10
# Run one auth cycle when the daemon starts
unlock_on_start = false
# Human-friendly PC name shown during pairing
pc_name = "my-laptop"

[logging]
level = "INFO"
""" % (cfg_path.parent, cfg_path.parent)

    cfg_path.write_text(template)
    return cfg_path
